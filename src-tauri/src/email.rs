//! "Send by mail": open the system's default mail client with a new draft that
//! already has the (encrypted) file attached.
//!
//! `mailto:` cannot carry attachments, so each OS gets its own mechanism:
//! macOS drives the default client (Mail, Outlook, Thunderbird) natively,
//! Windows uses Simple MAPI and Linux uses `xdg-email`. All user-supplied
//! values are passed as process arguments or environment variables, never
//! spliced into script source.

use std::path::{Path, PathBuf};
use std::process::Command;

struct Draft {
    to: Vec<String>,
    subject: String,
    body: String,
    attachment: PathBuf,
}

#[tauri::command]
pub async fn send_via_default_mail_client(
    to: Option<String>,
    subject: Option<String>,
    body: Option<String>,
    attachment_path: String,
) -> Result<(), String> {
    let attachment = Path::new(&attachment_path)
        .canonicalize()
        .map_err(|e| format!("Attachment not found: {e}"))?;
    // Windows canonicalization yields a `\\?\` path that MAPI clients reject.
    let attachment = PathBuf::from(attachment.to_string_lossy().trim_start_matches(r"\\?\"));
    if !attachment.is_file() {
        return Err("Attachment is not a file".into());
    }
    let draft = Draft {
        to: to
            .unwrap_or_default()
            .split([',', ';'])
            .map(str::trim)
            .filter(|a| a.contains('@') && !a.contains(['\r', '\n']))
            .map(String::from)
            .collect(),
        subject: subject.unwrap_or_default().replace(['\r', '\n'], " "),
        body: body.unwrap_or_default(),
        attachment,
    };
    tauri::async_runtime::spawn_blocking(move || platform::send(&draft))
        .await
        .map_err(|e| e.to_string())?
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("Could not start mail client: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("Mail client failed: {}", err.trim()))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const MAIL: &str = r#"on run argv
  set theSubject to item 1 of argv
  set theBody to item 2 of argv
  set theFile to item 3 of argv
  tell application "Mail"
    set m to make new outgoing message with properties {subject:theSubject, content:theBody & return & return, visible:true}
    tell m
      repeat with i from 4 to count of argv
        make new to recipient at end of to recipients with properties {address:item i of argv}
      end repeat
      tell content to make new attachment with properties {file name:(POSIX file theFile as alias)} at after the last paragraph
    end tell
    activate
  end tell
end run"#;

    const OUTLOOK: &str = r#"on run argv
  set theSubject to item 1 of argv
  set theBody to item 2 of argv
  set theFile to item 3 of argv
  tell application "Microsoft Outlook"
    set m to make new outgoing message with properties {subject:theSubject, plain text content:theBody}
    repeat with i from 4 to count of argv
      make new recipient at m with properties {email address:{address:item i of argv}}
    end repeat
    make new attachment at m with properties {file:(POSIX file theFile as alias)}
    open m
    activate
  end tell
end run"#;

    /// Bundle id registered for `mailto:`; Apple Mail unless the user chose another.
    fn default_handler() -> String {
        let plist = Command::new("defaults")
            .args(["export", "com.apple.LaunchServices/com.apple.launchservices.secure", "-"])
            .output()
            .ok()
            .and_then(|o| {
                let mut conv = Command::new("plutil")
                    .args(["-convert", "json", "-o", "-", "-"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .ok()?;
                std::io::Write::write_all(conv.stdin.as_mut()?, &o.stdout).ok()?;
                let out = conv.wait_with_output().ok()?;
                serde_json::from_slice::<serde_json::Value>(&out.stdout).ok()
            });
        plist
            .and_then(|v| {
                v.get("LSHandlers")?
                    .as_array()?
                    .iter()
                    .find(|h| h.get("LSHandlerURLScheme").and_then(|s| s.as_str()) == Some("mailto"))
                    .and_then(|h| h.get("LSHandlerRoleAll")?.as_str().map(str::to_lowercase))
            })
            .unwrap_or_else(|| "com.apple.mail".into())
    }

    fn osascript(script: &str, d: &Draft) -> Result<(), String> {
        let mut cmd = Command::new("osascript");
        cmd.arg("-e").arg(script).arg("--").arg(&d.subject).arg(&d.body).arg(&d.attachment);
        cmd.args(&d.to);
        run(&mut cmd)
    }

    pub fn send(d: &Draft) -> Result<(), String> {
        match default_handler().as_str() {
            "com.apple.mail" => osascript(MAIL, d),
            "com.microsoft.outlook" => osascript(OUTLOOK, d),
            "org.mozilla.thunderbird" | "org.mozilla.thunderbird-beta" => thunderbird(d),
            // Unknown client: open a draft without the attachment and show
            // the file in Finder so it can be dragged in.
            _ => {
                let mut url = format!("mailto:{}?subject={}&body={}", d.to.join(","), enc(&d.subject), enc(&d.body));
                url.truncate(url.len().min(8000));
                run(Command::new("open").arg(url))?;
                run(Command::new("open").arg("-R").arg(&d.attachment))
            }
        }
    }

    fn thunderbird(d: &Draft) -> Result<(), String> {
        let q = |s: &str| s.replace('\'', "\u{2019}");
        let compose = format!(
            "to='{}',subject='{}',body='{}',attachment='file://{}'",
            q(&d.to.join(",")),
            q(&d.subject),
            q(&d.body),
            enc_path(&d.attachment),
        );
        run(Command::new("open").args(["-b", "org.mozilla.thunderbird", "--args", "-compose"]).arg(compose))
    }

    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    fn enc_path(p: &Path) -> String {
        p.to_string_lossy().split('/').map(enc).collect::<Vec<_>>().join("/")
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::os::windows::process::CommandExt;

    /// Simple MAPI: handled by Outlook, Thunderbird and other registered clients.
    const SCRIPT: &str = r#"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Mapi {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public class Msg {
    public int r; public string subject; public string text; public string type; public string date; public string convId;
    public int flags; public IntPtr originator; public int recipCount; public IntPtr recips; public int fileCount; public IntPtr files; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct Recip {
    public int r; public int cls; public string name; public string addr; public int eidSize; public IntPtr eid; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct File {
    public int r; public int flags; public int pos; public string path; public string name; public IntPtr type; }
  [DllImport("mapi32.dll", CharSet=CharSet.Unicode)] static extern int MAPISendMailW(IntPtr s, IntPtr w, Msg m, int f, int r);
  public static int Send(string subject, string body, string[] to, string file) {
    var m = new Msg { subject = subject, text = body };
    int rs = Marshal.SizeOf(typeof(Recip));
    if (to.Length > 0) {
      m.recipCount = to.Length; m.recips = Marshal.AllocHGlobal(rs * to.Length);
      for (int i = 0; i < to.Length; i++)
        Marshal.StructureToPtr(new Recip { cls = 1, name = to[i], addr = "SMTP:" + to[i] }, (IntPtr)((long)m.recips + i * rs), false);
    }
    m.fileCount = 1; m.files = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(File)));
    Marshal.StructureToPtr(new File { pos = -1, path = file, name = System.IO.Path.GetFileName(file) }, m.files, false);
    return MAPISendMailW(IntPtr.Zero, IntPtr.Zero, m, 0x9 /* LOGON_UI | DIALOG */, 0);
  }
}
'@
$to = @(); if ($env:AEGIS_TO) { $to = $env:AEGIS_TO -split "`n" }
$rc = [Mapi]::Send($env:AEGIS_SUBJECT, $env:AEGIS_BODY, [string[]]$to, $env:AEGIS_FILE)
if ($rc -ne 0 -and $rc -ne 1) { [Console]::Error.WriteLine("MAPI error $rc (no default mail client?)"); exit 1 }
"#;

    pub fn send(d: &Draft) -> Result<(), String> {
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SCRIPT])
            .env("AEGIS_TO", d.to.join("\n"))
            .env("AEGIS_SUBJECT", &d.subject)
            .env("AEGIS_BODY", &d.body)
            .env("AEGIS_FILE", &d.attachment)
            .creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        run(&mut cmd)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    use super::*;

    pub fn send(d: &Draft) -> Result<(), String> {
        let mut cmd = Command::new("xdg-email");
        cmd.arg("--utf8").arg("--subject").arg(&d.subject).arg("--body").arg(&d.body).arg("--attach").arg(&d.attachment);
        cmd.args(&d.to);
        run(&mut cmd).map_err(|e| format!("{e} (is xdg-utils installed?)"))
    }
}

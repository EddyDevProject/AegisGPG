//! Copying secrets (decrypted text, secret keys) to the clipboard with an
//! automatic wipe.
//!
//! The wipe only happens if the clipboard still holds exactly what we put
//! there, so anything the user copied in the meantime is left alone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arboard::Clipboard;
use zeroize::Zeroizing;

/// Bumped on every copy so an older timer never wipes a newer copy early.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Empties the clipboard whatever it holds (used by the panic wipe).
pub fn clear_now() {
    if let Ok(mut clipboard) = Clipboard::new() {
        let _ = clipboard.clear();
    }
}

/// Puts `text` on the clipboard and clears it again after `seconds`.
/// With `seconds == 0` the text is copied and left there.
#[tauri::command]
pub fn copy_sensitive(text: String, seconds: u64) -> Result<(), String> {
    let text = Zeroizing::new(text);
    // Keep this instance alive: on Linux/X11 the owner serves the content.
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.set_text(text.as_str()).map_err(|e| e.to_string())?;
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

    if seconds > 0 {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds));
            if GENERATION.load(Ordering::SeqCst) != generation {
                return;
            }
            let current = clipboard.get_text().map(Zeroizing::new).ok();
            if current.as_deref().map(|c| c.as_str()) == Some(text.as_str()) {
                let _ = clipboard.clear();
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real clipboard, so it only runs on request:
    /// `cargo test --lib clipboard -- --ignored`
    #[test]
    #[ignore]
    fn wipes_only_what_it_copied() {
        copy_sensitive("aegis-secret".into(), 1).unwrap();
        std::thread::sleep(Duration::from_millis(1600));
        let after = Clipboard::new().unwrap().get_text().unwrap_or_default();
        assert_ne!(after, "aegis-secret");

        copy_sensitive("aegis-secret".into(), 1).unwrap();
        Clipboard::new().unwrap().set_text("something else").unwrap();
        std::thread::sleep(Duration::from_millis(1600));
        assert_eq!(Clipboard::new().unwrap().get_text().unwrap(), "something else");
    }
}

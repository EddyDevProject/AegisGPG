<div align="center">

<img src="assets/icon.svg" alt="AegisGPG" width="120" height="120" />

# AegisGPG

**OpenPGP, without the pain.**
A modern, minimal desktop app to manage keys, encrypt, sign and build your web of trust.
No `gpg` binary required.

**[aegisgpg.app](https://aegisgpg.app)** · [Download](https://github.com/EddyDevProject/AegisGPG/releases/latest)

![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB?logo=tauri&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-sequoia--openpgp-DEA584?logo=rust&logoColor=white)
![Svelte](https://img.shields.io/badge/Svelte-5-FF3E00?logo=svelte&logoColor=white)
![Tailwind](https://img.shields.io/badge/Tailwind-v4-06B6D4?logo=tailwindcss&logoColor=white)
![Platforms](https://img.shields.io/badge/macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)

</div>

---

## Why AegisGPG

GnuPG is powerful but hostile. AegisGPG puts the things people actually do with OpenPGP behind a clean, keyboard-friendly interface with dark mode, drag & drop and clear error messages ("Passphrase incorrect", "Missing public key for recipient…") instead of cryptic exit codes.

The cryptography runs in Rust on [Sequoia-PGP](https://sequoia-pgp.org) with a pure-Rust backend, so there is **nothing to install** besides the app itself and it speaks standard OpenPGP: your keys and files stay compatible with GnuPG, Thunderbird, Proton and friends.

## Features

### Keys
- Generate **Ed25519/Cv25519** (default) or **RSA 4096** keys, with optional passphrase and expiry
- Import from `.asc` / `.pub` / `.key` files, drag & drop, or pasted ASCII armor
- **Keys exported by GnuPG 2.4** work too: its protected secret keys use an encoding Sequoia rejects, so AegisGPG re-reads them in canonical form, and GnuPG's default ZLIB-compressed messages decrypt as well
- Export public keys, or secret keys behind a passphrase prompt, to the clipboard or a file
- Delete with confirmation
- **Backup & restore**: the whole keyring (secret keys included) in one file encrypted with a passphrase you choose, and a restore that merges it back
- **Revocation certificates**: save one for each of your keys while you still can, or revoke a key right away
- **Unlock with [KleyKnox](https://github.com/Nidhil-stack/kleyknox)**: plug in a USB stick holding a KleyKnox vault and one master passphrase unlocks every key on it, for 15 minutes up to 8 hours. Keys your keyring lacks are imported from the vault, and a passphrase that does not open your copy of a key is reported. Use the sidebar button, or let the passphrase prompt offer it first whenever the stick is plugged in (switchable in Keys). Nothing is written to disk

### Encrypt, sign, decrypt
- Drag & drop any file; encrypt to one or many recipients and/or sign with your key
- Binary (`.gpg`) or ASCII-armored (`.asc`) output
- **Send by mail**: one click opens your default mail client (Apple Mail, Outlook, Thunderbird) with a new draft and the encrypted file attached (macOS; Windows via Simple MAPI; Linux via `xdg-email`)
- **Streaming I/O** in a background thread: multi-gigabyte files don't load into RAM or freeze the UI, and you get a live progress bar
- Decrypt with a result card showing where the file went and a signature verdict: **valid**, **invalid** or **unknown signer**
- Quick text tool to encrypt/decrypt clipboard text without touching the disk, plus **cleartext signing and verification** (readable message with a signature below it)

### Contacts & Web of Trust
- Contact book with avatars (generated initials; optional Libravatar → Gravatar lookup, off by default because it sends a hash of each email to third parties)
- Contact details: fingerprint in groups of four, key IDs, ownertrust selector, user IDs, subkeys with purposes and expiry
- **Trust graph**: an interactive, zoomable map of who certified whom, coloured by validity (green: full, yellow: marginal, grey: unknown). Signatures are cryptographically verified, not just read
- **Certify a key** with a guided dialog: verification level, user IDs, passphrase, and export of the countersigned key
- Lookup by email via **WKD** (advanced and direct methods) and **keys.openpgp.org** / **keyserver.ubuntu.com**; publish your key; check all keys for updates and **revocations**

### QR code sharing
- Share a key as a QR code: fingerprint (`openpgp4fpr:`), the full public key, or a keyserver link
- Keys too large to scan reliably are refused with a clear hint instead of producing an unreadable code
- Save as PNG/SVG, copy the image, copy the fingerprint
- Import a key from a scanned `openpgp4fpr:` URI. The download is accepted only if its fingerprint matches exactly

## Security model

- **Secrets in memory** (passphrases, decrypted key material) are held in zeroizing buffers and wiped on drop
- **Least privilege**: the webview gets *no* filesystem access. The Rust side opens only files you picked in a dialog or dropped on the window. The Tauri capability list contains just the dialog permissions, and a strict CSP is set
- **Untrusted downloads**: anything fetched from a keyserver/WKD is stripped of secret material, size-capped (5 MB), HTTPS-only, bound to timeouts, and checked against what you asked for
- **KleyKnox vault**: read-only (age, scrypt passphrase), decrypted off the UI thread, with the scrypt cost capped. The passphrases it releases live only in memory, for the time you chose, and the wipe below clears them
- **Wipe & quit**: the sidebar button (or Ctrl/Cmd+Shift+X) forgets remembered passphrases, empties the clipboard and exits. Copied decrypted text and secret keys are also cleared from the clipboard after 30 seconds
- **Supply chain**: `cargo-deny` and `npm audit` run on dependency changes and weekly in CI (see [`audit.yml`](.github/workflows/audit.yml) and [`deny.toml`](src-tauri/deny.toml)). Security reports: see [SECURITY.md](SECURITY.md)
- **Typed errors** end to end: Rust enum → `{ code, message }` → friendly UI message
- **OS credential store**: secret keys without a passphrase are kept in the macOS Keychain, Windows Credential Manager or Linux Secret Service, and only the public part stays on disk. Existing keys are migrated on first launch. If the store is unavailable (or the key is too large for it, e.g. RSA 4096 on Windows) the key stays in its file, so **set a passphrase** (the app warns you)

> **Heads-up:** AegisGPG has not been independently audited, and the pure-Rust crypto backend is flagged *experimental* by Sequoia. For high-stakes use, review the code and prefer a hardware token.

## Install

Installers for all platforms are built by GitHub Actions and attached to each [Release](../../releases). Locally they are produced with `npm run tauri build` (see below).

| Platform | Artifact |
|---|---|
| macOS (Apple Silicon + Intel) | `.dmg` / `.app` |
| Windows (x64) | NSIS `-setup.exe` |
| Linux | `.deb`, `.rpm`, `.AppImage` (from Releases) |

Builds are currently **unsigned**: macOS Gatekeeper will say "unidentified developer" (right-click → Open) and Windows SmartScreen will warn (More info → Run anyway).

Your keyring lives in the app data folder:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/app.aegisgpg.desktop/keyring` |
| Windows | `%APPDATA%\app.aegisgpg.desktop\keyring` |
| Linux | `~/.local/share/app.aegisgpg.desktop/keyring` |

## Build from source

**Requirements:** Node.js 20+, Rust 1.77+ (stable recommended). On Linux also the Tauri system packages (WebKitGTK 4.1 and friends, see the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)).

```bash
npm install
npm run tauri dev      # run with hot reload
npm run tauri build    # produce installers for your OS
```

```bash
npm run check          # svelte-check / TypeScript
cd src-tauri && cargo test   # crypto, web of trust, WKD and QR tests
```

<details>
<summary>Cross-compiling the Windows installer from macOS</summary>

```bash
brew install nsis llvm lld
cargo install --locked cargo-xwin
rustup target add x86_64-pc-windows-msvc
export PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:$PATH"
npx tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc
```

Tauri flags cross-compilation as experimental; test the result on a real Windows machine.
</details>

## Project layout

```
src/                     Svelte 5 + TypeScript UI
  lib/views/             Keys · Discover & Sync · Trust Graph · Encrypt · Decrypt · Quick Text
  lib/components/        Modals, drawer, dropzone, avatar, QR, toasts…
  lib/api.ts             Typed wrappers around the Tauri commands
src-tauri/src/
  commands.rs            #[tauri::command] IPC surface
  gpg/
    keys.rs  store.rs    Key generation, parsing, on-disk keyring + ownertrust
    crypto.rs            Streaming encrypt / sign / decrypt / verify
    wot.rs  certify.rs   Web of trust, validity, key certification
    net.rs               WKD + keyserver (VKS/HKP) client
    qr.rs                QR payloads and SVG/PNG rendering
    error.rs             Typed errors → UI messages
```

## Roadmap

- [ ] Camera QR scanner
- [x] Signing from the Quick Text tool
- [ ] Code signing and notarization for macOS and Windows
- [x] Linux, Windows and macOS (arm64 + Intel) builds in CI
- [x] Key backup/restore wizard and revocation certificates
- [ ] Localization (Italian first)

## License

AegisGPG is free software, released under the [GNU General Public License v3.0 or later](LICENSE). It builds on Sequoia-PGP (LGPL-2.0-or-later), Tauri (MIT/Apache-2.0) and other open-source components under their own licenses.

## Credits

Made with ♥ by **Edoardo Bavaro**.

Built on [Tauri](https://tauri.app), [Sequoia-PGP](https://sequoia-pgp.org), [Svelte](https://svelte.dev), [Tailwind CSS](https://tailwindcss.com) and [D3](https://d3js.org).

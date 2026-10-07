# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML/CSS/JS in `site/`, deployed on Netlify with no build step (`netlify.toml`: publish = site). Strict CSP (`script-src 'self'`, `style-src 'self'`, `connect-src https://api.github.com`), so no inline scripts/styles and no third-party hosts. Fonts must be self-hosted.

## Users

Non-technical people who need to protect files and messages with OpenPGP but avoid GnuPG because it is hostile (terminal, cryptic exit codes). Secondary: privacy-minded developers who want to verify the code.

## Product Purpose

AegisGPG is a free, open-source desktop app (macOS, Windows, Linux) to manage OpenPGP keys, encrypt, sign and decrypt files, share keys and build a web of trust. The website's job: make a first-time visitor understand in seconds what it does and download it.

## Positioning

OpenPGP without the pain: no `gpg` binary needed (pure-Rust Sequoia-PGP backend), standard OpenPGP so keys and files stay compatible with GnuPG, Thunderbird and Proton, plain-language errors, drag and drop, streaming for huge files, "Send by mail" with the encrypted file attached, interactive trust graph.

## Operating Context

Visitors arrive from GitHub or search, on any OS. The download buttons read the latest GitHub release via the GitHub API (assets: mac arm/x64 `.dmg`, Windows `-setup.exe`, Linux AppImage/deb/rpm). Releases are currently unsigned/ad-hoc signed, so first launch needs a documented OS warning workaround.

## Capabilities and Constraints

Features: key generation (Ed25519/Cv25519, RSA 4096), import/export, streaming encrypt/sign/decrypt/verify with progress, Quick Text, Teams (encrypt to a group, own key added automatically), contacts with ownertrust, trust graph, certify keys, WKD + keys.openpgp.org + keyserver.ubuntu.com, QR sharing (`openpgp4fpr:`), Send by mail, in-app signed updater, dark mode. Not independently audited; Sequoia pure-Rust backend flagged experimental. Not yet code-signed/notarized. License GPL-3.0-or-later. Domain planned: aegisgpg.app (not yet live); live at aegisgpg.netlify.app. Repo: github.com/EddyDevProject/AegisGPG. UI, README and site are in English.

## Brand Commitments

Name AegisGPG. Existing mark: white shield with keyhole cut-out on an indigo gradient square (`assets/icon.svg`, `site/favicon.svg`). Indigo (#4338ca / #7c7ff5) is the app's accent; the site must feel like the same product, light and dark. Made by Edoardo Bavaro.

## Evidence on Hand

No real testimonials, user counts, audits or benchmarks exist; none may be invented. No app screenshots on disk. Real content: README feature list and security model, GitHub release assets.

## Product Principles

1. Plain language over jargon; every claim traceable to the README.
2. Honest about limits: unaudited, experimental backend, unsigned builds.
3. Show the product doing its job instead of describing it.
4. Download is always one click away and OS-aware.

## Accessibility & Inclusion

WCAG AA contrast, keyboard focus visible, prefers-reduced-motion and color-scheme respected.

# Security policy

AegisGPG handles private keys, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private reporting instead:
**[Report a vulnerability](https://github.com/EddyDevProject/AegisGPG/security/advisories/new)**
(Security tab → *Report a vulnerability*).

Please include what you found, how to reproduce it, the impact you see and, if you have one, a suggested fix.

## What to expect

- Acknowledgement within a few days. This is a one-person project, so there is no formal SLA.
- A fix and a coordinated disclosure; reporters are credited unless they prefer not to be.

## Scope

In scope:

- Private key or passphrase leakage (disk, memory, clipboard, logs)
- Weaknesses in how keys are generated, stored, imported or exported
- Signature or trust verification bypasses (the web of trust, certifications, `openpgp4fpr:` imports)
- Malicious keyserver / WKD responses that get past the download checks
- Access to files the user did not choose, or escaping the webview's restrictions
- Vulnerable dependencies with a practical impact

Out of scope:

- Anything needing an already-compromised account or machine (malware, keyloggers, memory forensics)
- Issues in GnuPG, Sequoia-PGP, Tauri or the OS themselves: please report those upstream
- Unsigned installers triggering Gatekeeper / SmartScreen warnings (known)

## Supported versions

Only the latest release receives security fixes.

## Known limits

AegisGPG has **not been independently audited**, and its pure-Rust crypto backend is flagged *experimental* by Sequoia. For high-stakes use, review the code and prefer a hardware token. See the *Security model* section of the [README](README.md) for what the app protects against.

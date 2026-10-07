# Design: AegisGPG website

Evidence-bag system in the app's indigo. Static HTML/CSS/JS in `site/`. Replaces the earlier airmail world.

- **Concept:** a tamper-evident evidence bag with a chain-of-custody label. The hero is a working label: hold the button to seal the message (ciphertext + seal number + stamp), then open it as the recipient or as anyone else (tape reads VOID). Simulated; nothing is encrypted in the browser.
- **Color:** cool translucent grey `oklch(0.955 0.008 255)` ground, ink `oklch(0.2 0.035 270)`, one accent indigo `#4338ca` (text variant `#a5a8ff` in dark). Dark mode is indigo-tinted near-black. Indigo security tape is the only saturated field; the download section is drenched. Amber appears only on the "Known limits" slip.
- **Type:** Big Shoulders Display (uppercase, 800) for headings and numerals, Archivo for text, Red Hat Mono for ids, fingerprints, labels. All self-hosted in `site/fonts/`.
- **Shape:** 4px radius, 1.5px ink rules, hard 8px offset shadow on the label, diagonal tape stripes (`-45deg`), dashed slips for notes, numbered manifest rows (K-01...) and custody log.
- **Motion:** `cubic-bezier(0.23, 1, 0.32, 1)`; 160ms `scale(0.97)` on press; hold-to-seal fills with transform over 900ms linear and releases in 200ms ease-out; stamp lands from scale 1.25; 520ms reveals via IntersectionObserver; keyboard Enter/Space seals instantly. Everything gated by `prefers-reduced-motion`, hover by `(hover: hover)`.
- **SEO/perf:** single H1, section landmarks, canonical, OG/Twitter, JSON-LD (SoftwareApplication, Person, WebSite, FAQPage), `sitemap.xml`, `robots.txt`, preloaded fonts, reserved heights for dynamic states (CLS 0 target), no raster except `og.png`.
- **Constraints:** CSP is `script-src 'self'; style-src 'self'`: no inline scripts or `style` attributes.

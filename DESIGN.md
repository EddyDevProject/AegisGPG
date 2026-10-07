# Design: AegisGPG website

Airmail system in the app's indigo. Static HTML/CSS/JS in `site/`.

- **Color:** cool paper `oklch(0.975 0.008 285)`, ink `oklch(0.2 0.06 280)`, accent indigo `#4338ca` with `#7c7ff5` as the second stripe. Dark mode swaps to indigo-tinted near-black. The download section is drenched indigo. One accent, no gradients on text.
- **Type:** Archivo variable (width axis 62-125%), headlines at 112% width, 850 over 300 weight for emphasis. Geist Mono for armored text and commands. Both self-hosted in `site/fonts/`.
- **Shape:** one 8px radius. Envelope border and footer band use a -45deg chevron stripe (indigo, paper, light indigo, paper). Stamps and the "how" panels are perforated with CSS masks. Declaration slips are 3px-radius paper with a dashed inner rule.
- **Motion:** ease-out `cubic-bezier(0.23, 1, 0.32, 1)`, 160ms on controls with `scale(0.97)` on press, 560ms reveals via IntersectionObserver, 520ms ciphertext scramble in the hero letter. All gated by `prefers-reduced-motion`; hover gated by `(hover: hover)`.
- **Icons:** Phosphor Regular and Simple Icons, bundled as `site/icons.svg`. QR in `site/qr.svg` is a real code for the repo.
- **Constraints:** CSP is `script-src 'self'; style-src 'self'`, so no inline scripts or `style` attributes.

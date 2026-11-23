# CyberLens v1.0 design decisions

Reference requested by the user:
https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/main/.claude/skills/ui-ux-pro-max/SKILL.md

Read SKILL.md and ran the skill's Python search (not just a visual imitation):

```
search.py "security dashboard dark mode professional monitoring tool" --design-system
search.py "live status feed auto-update pause control stale" --domain ux
```

The first query returned Operations / Real-Time, dark Glassmorphism,
slate #0F172A / #1B2336 and green #22C55E. Applied to a local security
workspace, not its suggested marketing landing page. Shallow gradients and
opaque readable cards replace heavy blur to keep this zero-dependency app fast.
Recommended Fira font pairing was not fetched from Google: system sans and
monospace fallbacks deliberately keep the app offline, without font downloads.

Implemented:
- Consistent inline outline SVGs for tabs and upload; no external icon CDN.
- Green primary capture action; neutral secondary actions; disabled states.
- Source selector with visible label and active-interface default.
- Live label backed by capture status, counts, transport and stale-packet state.
- Separate, explicitly labelled training simulation.
- Pause/resume display without stopping collection; explicit stop capture.
- Reduced-motion styling and initially paused live display for that preference.
- Hidden-document live rendering is skipped; server collection continues.
- Visible focus rings, skip link, Enter/Space upload, 44px control height.
- Meaningful status messages without moving keyboard focus.
- Tab deep links, source controls above investigation tabs, export feedback.
- Offline/permission/connection failure messages; report export only in app mode.

Browser verification (Chromium / Playwright):
- Demo investigation, all tabs, report download: passed.
- No horizontal overflow at 375×812 and 812×375: passed.
- Reduced-motion CSS: passed. No JavaScript page errors.
- Screenshots saved in release/screenshots/.

Limits: not a formal WCAG audit or assistive-technology certification. Native
Kali browser/hardware testing is still required. Generated reports use a separate
light, print-friendly theme and may preserve emoji in evidence/content.


---

# v1.1 — "Obsidian Glass" skin (added 2026-11-23)

The v1.0 design was legible but flat. v1.1 keeps every accessibility decision and
replaces the visual language with a layered glass system.

## Layers, back to front

| Layer | Recipe |
|---|---|
| Base | `#050810` → `#04060d` vertical gradient, fixed attachment |
| Aurora | three soft radial orbs — cyan (top-left), violet (top-right), emerald (bottom-centre) — 13–26 % opacity |
| Grain | 160 px SVG `feTurbulence` tile at 5 % opacity, `mix-blend-mode: overlay` (kills gradient banding) |
| Vignette | radial mask that darkens the outer 45 % so the centre reads as “the signal” |
| Surfaces | `rgba(13,20,36,.55)` + `backdrop-filter: blur(22px) saturate(150%)` + white top-edge inset highlight |
| Edge | 1 px `::before` gradient border (white 42 % → cyan 30 %) drawn with `mask-composite: exclude` |

## Tokens

```
--bg       #050810   page
--panel    rgba(17,25,42,.55)     glass fill
--panel2   rgba(32,44,68,.60)     raised glass
--line     rgba(148,163,184,.18)  hairline
--cyan     #22d3ee   signal / focus
--green    #34d399   safe / primary action
--shadow-deep  0 30px 70px -38px rgba(0,0,0,.98)
```

## Type

- Display (hero, brand): system sans, 800 weight, `letter-spacing:-1.1px`,
  gradient fill `#fff → #9be8ff → #7bf0c4` via `background-clip: text`.
- Numbers: `font-variant-numeric: tabular-nums` so live counters do not jitter.
- Micro-labels (`.stat .k`, `.eyebrow`): 11–12 px, uppercase, `letter-spacing: .3–2.4px`.

## Interaction

- Hover: `translateY(-1px)` + cyan border + cyan-tinted shadow. Never scale text.
- Primary action only: emerald gradient with an inset white highlight and a wide glow.
- Live state: 2.6 s pulse ring on the status dot, 1.8 s on capture.
- `prefers-reduced-motion: reduce` → all animation and transform hover removed.

## Performance / privacy

- `backdrop-filter` is applied to large surfaces only (header, cards, nav, event cards);
  pills, chips and tables use a cheaper flat-glass fill.
- No external fonts, icons or images: inline SVG icons, system font stacks,
  and a single self-contained `dashboard.html` file.

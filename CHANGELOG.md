# Changelog

## v1.1.0 — "Obsidian Glass" (2026-11-23)

The interface release: same deterministic engine, a console worth showing.

### Added
- **Premium glassmorphism skin** for the whole console: layered aurora background,
  frosted surfaces with hairline edge highlights, neon cyan/emerald accents,
  sticky glass header, glass tab bar, glass event cards and code blocks.
- Depth and motion system: entrance rise on cards, hover lift + glow on actionable
  surfaces, pulsing live indicator — all disabled under `prefers-reduced-motion`.
- Refined typography scale: gradient display headings, tabular figures in the stat
  strip, uppercase micro-labels for scanning.
- The classic console (`server.py` + `index.html`) now shares the same glass tokens, so both
  front-ends look like one product.
- `CHANGELOG.md`, `SECURITY.md`, MIT `LICENSE`, and `docs/screenshots/`.

### Changed
- Stat strip, verdict bar, timeline lanes, donut legend and attacker bars restyled to
  read at a glance on a projector or a phone.
- Mobile layout: static header, tighter cards, no horizontal overflow at 390 × 844.
- Version bumped to 1.1.0; `.gitignore` now excludes `release/`, `ai_config.json`
  and local captures so keys never reach the repository.

### Kept
- Zero pip dependencies, stdlib-only runtime, offline by default.
- 98 automated checks still pass (parser, plugins, correlator, report, real loopback capture).

## v1.0.0
- Live interface capture, pause/stop controls, standalone offline HTML report,
  accessible capture workspace, Debian packaging and desktop entry.

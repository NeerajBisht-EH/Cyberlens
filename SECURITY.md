# Security policy

CyberLens is defensive tooling that reads hostile input (packet captures and alert
logs). Two things matter here: never leak the operator's data, and never trust the file.

## Reporting a vulnerability

Open a **private** report through GitHub → *Security* → *Report a vulnerability*,
or contact the maintainer listed in `README.md`. Please do not open a public issue for
anything that could expose captures, keys or local files. Expect an acknowledgement
within a few days; this is a student-maintained project, not a vendor product.

## Design rules that protect the operator

- **Offline by default.** No telemetry, no CDN, no external fonts. The only outbound
  request possible is the optional AI narration call, which you must explicitly configure.
- **Loopback only.** The web console binds to `127.0.0.1` and has no authentication. It is
  a local tool — never expose the port, never run it as root.
- **Secrets stay local.** `ai_config.json` (which can hold an API key) is git-ignored and
  is never written into an exported report.
- **Hostile evidence is escaped.** Packet payloads are rendered through an HTML escaper in
  both the dashboard and the exported report, so a crafted capture cannot inject script.
- **Bounded parsing.** Captures are parsed with size and count limits; a truncated or
  malformed file fails closed instead of hanging the UI.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | ✅ |
| 1.0.x | security fixes only |

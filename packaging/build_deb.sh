#!/usr/bin/env bash
#
# Build the CyberLens .deb — an installable Kali/Debian app, like Wireshark.
#
#   ./packaging/build_deb.sh            -> release/cyberlens_<ver>-1_all.deb
#   ./packaging/build_deb.sh /tmp/out   -> build somewhere else
#
# Design goals:
#   - EVERY dependency declared (apt installs them with the package)
#   - zero pip, zero downloads — pure python3 stdlib app
#   - CLI tools + desktop entry (appears in the Kali menu, like Wireshark)
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(dirname "$HERE")"                       # project root
OUT="${1:-$SRC/release}"
VER="$(python3 -c "import re; print(re.search(r'VERSION = \"([^\"]+)\"', open('$SRC/webui.py').read()).group(1))")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

APP="$STAGE/cyberlens"
SHARE="$APP/usr/share/cyberlens"

echo ">> building cyberlens $VER (stage: $STAGE)"

# ---------------- application code ----------------
mkdir -p "$SHARE/plugins" "$SHARE/captures"
cp "$SRC"/*.py "$SHARE/"
cp "$SRC"/plugins/*.py "$SHARE/plugins/"
cp "$SRC"/dashboard.html "$SRC"/ai_config.example.json "$SHARE/"
cp "$SRC"/captures/demo.pcap "$SRC"/captures/eve-sample.json \
   "$SRC"/captures/tshark-sample.json "$SHARE/captures/"

# ---------------- command-line entry points ----------------
mkdir -p "$APP/usr/bin"
for pair in "cyberlens:replay.py" "cyberlens-web:webui.py" \
            "cyberlens-suricata:suricata_adapter.py" \
            "cyberlens-tshark:tshark_adapter.py"; do
  name="${pair%%:*}"; target="${pair##*:}"
  cat > "$APP/usr/bin/$name" <<EOF
#!/bin/sh
# CyberLens $VER — $name
exec python3 /usr/share/cyberlens/$target "\$@"
EOF
  chmod 755 "$APP/usr/bin/$name"
done

# ---------------- desktop entry (Kali menu, like Wireshark) ----------------
mkdir -p "$APP/usr/share/applications" "$APP/usr/share/icons/hicolor/scalable/apps"
cat > "$APP/usr/share/applications/cyberlens.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=CyberLens
GenericName=Network Traffic Narrator
Comment=Read a packet capture and tell its story in plain English
Comment[en_GB]=Read a packet capture and tell its story in plain English
Exec=cyberlens-web
Icon=cyberlens
Terminal=false
Categories=Network;Security;System;Utility;
Keywords=network;security;pcap;wireshark;analysis;ids;blue-team;
StartupNotify=true
EOF

cat > "$APP/usr/share/icons/hicolor/scalable/apps/cyberlens.svg" <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#101c33"/>
      <stop offset="1" stop-color="#060b16"/>
    </linearGradient>
  </defs>
  <rect x="4" y="4" width="120" height="120" rx="28" fill="url(#bg)" stroke="#22334f" stroke-width="2"/>
  <circle cx="54" cy="52" r="27" fill="rgba(34,211,238,0.05)" stroke="#22d3ee" stroke-width="8"/>
  <path d="M75 73 L107 105" stroke="#22d3ee" stroke-width="13" stroke-linecap="round"/>
  <path d="M36 58 L46 46 L54 58 L69 40" fill="none" stroke="#34d399" stroke-width="5.5" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="67" cy="38" r="4" fill="#f87171"/>
</svg>
EOF

# ---------------- documentation ----------------
mkdir -p "$APP/usr/share/doc/cyberlens"
cp "$SRC"/README.md "$SRC"/HOW_IT_WORKS.md "$SRC"/COMPARISON.md "$SRC"/DESIGN_SYSTEM.md \
   "$APP/usr/share/doc/cyberlens/" 2>/dev/null || true
cat > "$APP/usr/share/doc/cyberlens/copyright" <<'EOF'
CyberLens — plain-English network traffic narrator
Copyright (c) 2026 the CyberLens project

License: MIT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

CyberLens is a defensive security education tool. It explains and correlates
network evidence; it does not contain attack functionality.
EOF

# ---------------- Debian control ----------------
mkdir -p "$APP/DEBIAN"
SIZE="$(du -sk "$APP/usr" | cut -f1)"
cat > "$APP/DEBIAN/control" <<EOF
Package: cyberlens
Version: $VER-1
Section: net
Priority: optional
Architecture: all
Installed-Size: $SIZE
Depends: python3 (>= 3.8)
Recommends: tshark, xdg-utils
Suggests: suricata
Maintainer: CyberLens project <cyberlens@localhost>
Homepage: https://localhost/cyberlens
Description: Plain-English network traffic narrator
 CyberLens reads packet captures (.pcap, Suricata eve.json, tshark exports)
 and tells you what happened in simple English: every event shown with its
 raw evidence, single alerts connected into attack stories, and defensive
 response playbooks that say what to do next.
 .
 Ships a local web console (cyberlens-web, appears in the application menu
 like Wireshark) plus CLI narrators (cyberlens, cyberlens-tshark,
 cyberlens-suricata). Deterministic rules-based engine; the optional AI
 companion layer only adds clearly-labelled comments and never replaces the
 built-in analysis. Defensive security education tool.
EOF

cat > "$APP/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# refresh menus/icons when the helpers exist (never fail the install for it)
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -qtf /usr/share/icons/hicolor || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q || true
fi
exit 0
EOF
chmod 755 "$APP/DEBIAN/postinst"

# ---------------- build ----------------
mkdir -p "$OUT"
DEB="$OUT/cyberlens_${VER}-1_all.deb"
dpkg-deb --build --root-owner-group "$APP" "$DEB"
echo ">> built: $DEB ($(du -h "$DEB" | cut -f1))"
echo ">> install on Kali/Debian/Ubuntu:"
echo "      sudo apt install $DEB        # or: sudo dpkg -i $DEB"
echo ">> then run 'cyberlens' (CLI) or find CyberLens in your application menu"

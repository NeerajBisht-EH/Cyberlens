#!/usr/bin/env python3
"""
CyberLens report export (v1.0) — turn any analysis into ONE self-contained
HTML file you can hand to someone, print, or archive.

Works from three shapes of input (all shaped by the same pipeline):
  • file analysis   (webui.analyze / replay --json)
  • live snapshot   (live_capture.LiveEngine.analysis)
  • Suricata/eve    (the webui normalizes those to the same shape)

Design: light, print-friendly, zero external assets (inline CSS + SVG only)
— the report must open on an air-gapped machine, like the tool itself.
"""
import html
import time
from datetime import datetime

TOKENS = {
    "bg": "#f5f7fb", "card": "#ffffff", "ink": "#0f172a",
    "dim": "#475569", "line": "#dbe3ee", "accent": "#0e7490",
    "clean": "#047857", "susp": "#b45309", "comp": "#b91c1c",
    "normal": "#047857", "recon": "#a16207", "attack": "#c2410c",
    "breach": "#b91c1c", "campaign": "#7c3aed",
}
VCOL = {"CLEAN": TOKENS["clean"], "SUSPICIOUS": TOKENS["susp"],
        "COMPROMISED": TOKENS["comp"]}
CATC = {k: TOKENS[k] for k in ("normal", "recon", "attack", "breach",
                               "campaign")}

LOGO = """<svg width="40" height="40" viewBox="0 0 64 64" aria-hidden="true">
<rect x="1" y="1" width="62" height="62" rx="14" fill="#0f172a"/>
<circle cx="27" cy="27" r="13" fill="none" stroke="#22d3ee" stroke-width="4"/>
<path d="M37 37 L51 51" stroke="#22d3ee" stroke-width="6" stroke-linecap="round"/>
<path d="M18 30 L23 25 L27 30 L34 21" fill="none" stroke="#34d399"
 stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>"""

E = html.escape


def _clock(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "--:--:--"


def _stat(v, k):
    return (f'<div class="stat"><div class="v">{E(str(v))}</div>'
            f'<div class="k">{E(k)}</div></div>')


def _event_card(ev, idx):
    c = CATC.get(ev.get("category"), TOKENS["dim"])
    raw = (ev.get("raw") or "").strip()
    raw_html = (f'<pre>{E(raw[:1500])}'
                + ("…" if len(raw) > 1500 else "") + "</pre>") if raw else ""
    steps = ""
    if ev.get("steps"):
        steps = '<div class="steps">' + "".join(
            f'<div class="step"><span class="dot" style="background:'
            f'{CATC.get(s.get("cat"), TOKENS["dim"])}"></span>'
            f'<span class="cat" style="color:{CATC.get(s.get("cat"), TOKENS["dim"])}">'
            f'{E(s.get("cat", ""))}</span> {E(s.get("title", ""))}'
            f' <span class="t">{_clock(s.get("ts"))}</span></div>'
            for s in ev["steps"]) + "</div>"
    ai = ""
    if ev.get("_ai"):
        ai = (f'<div class="ai">🤖 AI layer (optional, clearly labelled): '
              f'{E(ev["_ai"])}</div>')
    return f"""
<div class="ev" style="border-left:4px solid {c}">
  <div class="evhead">
    <span class="idx">#{idx}</span>
    <span class="time">{_clock(ev.get("ts"))}</span>
    <span class="title">{E(ev.get("title", ""))}</span>
    <span class="badge" style="color:{c};border-color:{c}">
      {E(ev.get("category", ""))} · {E(ev.get("severity", ""))}</span>
  </div>
  <p class="english">{E(ev.get("english", ""))}</p>
  {raw_html}
  {steps}
  <p class="advice"><b>🛡 Defender:</b> {E(ev.get("blue", ""))}</p>
  <p class="advice red"><b>🎯 Attacker's logic (why it works):</b>
     {E(ev.get("red", ""))}</p>
  {ai}
</div>"""


def _playbook(pb, recommended):
    badge = ('<span class="rec">recommended for this capture</span>'
             if recommended else "")
    steps = "".join(f"<li>{E(s)}</li>" for s in pb.get("steps", []))
    return f"""
<div class="pb">
  <div class="pbhead"><span class="nm">{E(pb.get("icon", ""))}
    {E(pb.get("name", ""))}</span>{badge}</div>
  <p class="trig"><b>Applies when:</b> {E(pb.get("trigger", ""))}</p>
  <ol>{steps}</ol>
  <p class="watch"><b>⚠ Watch out:</b> {E(pb.get("watch", ""))}</p>
</div>"""


def render(a):
    """analysis dict -> standalone HTML string."""
    f = a.get("file", {})
    vcol = VCOL.get(a.get("verdict"), TOKENS["ink"])
    alerts = sum(1 for e in a.get("events", [])
                 if e.get("severity", "info") != "info")
    stories = a.get("stories") or [e for e in a.get("events", [])
                                   if e.get("category") == "campaign"]
    pbs = a.get("playbooks") or []
    pb_names = {p.get("name") for p in pbs}
    library = a.get("library") or []
    when = datetime.now().strftime("%d %b %Y, %H:%M")

    story_html = ("".join(_event_card(s, i + 1)
                          for i, s in enumerate(stories))
                  or "<p class='empty'>No attack stories in this capture — "
                     "the correlator found no connected chains.</p>")
    events = [e for e in a.get("events", [])
              if e.get("category") != "campaign"]
    events.sort(key=lambda e: e.get("ts", 0))
    ev_html = "".join(_event_card(e, i + 1) for i, e in enumerate(events)) or \
        "<p class='empty'>No events.</p>"
    pb_html = "".join(_playbook(p, True) for p in pbs)
    if library:
        rest = [p for p in library if p.get("name") not in pb_names]
        if rest:
            pb_html += "<h2>Full playbook library</h2>" + \
                "".join(_playbook(p, False) for p in rest)
    pb_html = pb_html or "<p class='empty'>Nothing suspicious — no " \
                         "playbooks needed.</p>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberLens report — {E(str(f.get("name", "capture")))}</title>
<style>
:root{{--ink:{TOKENS['ink']};--dim:{TOKENS['dim']};--line:{TOKENS['line']};
--accent:{TOKENS['accent']};--bg:{TOKENS['bg']};--card:{TOKENS['card']}}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font:15px/1.6 "Fira Sans",ui-sans-serif,system-ui,"Segoe UI",Roboto,
 Arial,sans-serif;color:var(--ink);background:var(--bg);padding:32px 16px}}
.wrap{{max-width:900px;margin:0 auto}}
header{{display:flex;gap:14px;align-items:center;margin-bottom:20px}}
header h1{{font-size:22px}} header .sub{{color:var(--dim);font-size:13px}}
.verdict{{display:flex;flex-wrap:wrap;align-items:center;gap:18px;
 background:var(--card);border:1px solid var(--line);border-radius:14px;
 padding:18px 20px;margin-bottom:14px}}
.verdict .word{{font-size:26px;font-weight:800;color:{vcol};
 letter-spacing:.5px}}
.verdict .score{{margin-left:auto;text-align:right;font-weight:700}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
 gap:10px;margin-bottom:22px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:12px 14px}}
.stat .v{{font-size:20px;font-weight:800}}
.stat .k{{font-size:11.5px;color:var(--dim)}}
h2{{font-size:17px;margin:26px 0 12px;color:var(--accent)}}
.ev{{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:14px 16px;margin-bottom:12px;page-break-inside:avoid}}
.evhead{{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline}}
.idx,.time{{font-family:"Fira Code",ui-monospace,Menlo,monospace;
 font-size:11.5px;color:var(--dim)}}
.title{{font-weight:700}}
.badge{{font-size:10.5px;font-weight:700;text-transform:uppercase;
 letter-spacing:.5px;border:1px solid;border-radius:99px;padding:2px 9px}}
.english{{margin:9px 0}}
pre{{font:11.8px/1.5 "Fira Code",ui-monospace,Menlo,monospace;color:var(--dim);
 background:#f8fafc;border:1px solid var(--line);border-radius:8px;
 padding:10px 12px;margin:9px 0;white-space:pre-wrap;word-break:break-word}}
.advice{{font-size:13.5px;margin-top:6px}} .advice.red{{color:var(--dim)}}
.ai{{margin-top:9px;font-size:13.5px;color:var(--accent);
 border:1px dashed var(--accent);border-radius:8px;padding:8px 12px}}
.steps{{margin:10px 0 4px 4px}}
.step{{font-size:13px;margin:5px 0;display:flex;gap:8px;align-items:center;
 flex-wrap:wrap}}
.dot{{width:9px;height:9px;border-radius:50%;display:inline-block}}
.step .cat{{font-size:10.5px;font-weight:700;text-transform:uppercase}}
.step .t{{color:var(--dim);font-size:11px}}
.pb{{background:var(--card);border:1px solid var(--line);border-radius:10px;
 padding:14px 16px;margin-bottom:12px;page-break-inside:avoid}}
.pbhead{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
.pbhead .nm{{font-weight:700}}
.rec{{font-size:10.5px;color:var(--accent);border:1px solid var(--accent);
 border-radius:99px;padding:2px 9px}}
.trig{{font-size:13px;color:var(--dim)}}
ol{{margin:8px 0 10px 22px}} li{{font-size:13.5px;margin:6px 0}}
.watch{{font-size:13.5px;background:#fef3c7;border:1px solid #fcd34d;
 border-radius:8px;padding:8px 12px}}
.empty{{color:var(--dim);font-size:14px}}
footer{{margin-top:34px;padding-top:14px;border-top:1px solid var(--line);
 color:var(--dim);font-size:11.5px;line-height:1.7}}
@media print{{body{{background:#fff;padding:0}} .ev,.pb,.verdict{{break-inside:avoid}}}}
</style></head><body><div class="wrap">
<header>{LOGO}
 <div><h1>CyberLens traffic report</h1>
 <div class="sub">{E(str(f.get("name", "capture")))} ·
 {E(str(f.get("kind", "")))} capture · generated {when} ·
 deterministic engine (AI sections, if any, are labelled 🤖)</div></div></header>

<div class="verdict">
  <div><div class="word">{E(a.get("verdict", "—"))}</div>
  <div class="sub" style="font-size:12px;color:var(--dim)">verdict</div></div>
  <div class="score"><span style="font-size:22px;color:{vcol}">
   {a.get("score", 0)}</span><span style="color:var(--dim)">/100 threat score
  </span></div>
</div>

<div class="stats">
 {_stat(a.get("packets", 0), "packets")}
 {_stat(f"{a.get('tcp', 0)} / {a.get('udp', 0)}", "TCP / UDP")}
 {_stat(alerts, "alerts")}
 {_stat(len(stories), "attack stories")}
 {_stat(len(pbs), "playbooks to run")}
 {_stat(f"{a.get('duration', 0)}s", "of traffic")}
</div>

<h2>Attack stories</h2>
{story_html}

<h2>Events, in order</h2>
{ev_html}

<h2>Response playbooks — what to do next</h2>
{pb_html}

<footer>
 Generated by <b>CyberLens</b> v1.0 — plain-English network traffic narrator.<br>
 Deterministic rules + correlation; the optional AI layer only adds clearly
 labelled comments. Every event shows its raw evidence above so you can
 always check the story against the facts.<br>
 CyberLens is a defensive security education tool — it explains and
 correlates; it does not attack.
</footer>
</div></body></html>"""

# ⚖️ CyberLens vs. the classic tools — an honest comparison

**The one-line answer:** CyberLens is NOT more powerful than the classic
tools — it is advanced in a *different dimension*. Classic tools spend their
power on **collecting and detecting**. CyberLens spends it on **explaining**.
The industry is only now moving in this direction (AI security copilots),
which validates the idea — but the big tools are still 20+ years ahead in raw
engineering. That gap is exactly what our roadmap is for.

---

## The comparison matrix

| Capability | Wireshark / tcpdump | Suricata / Snort (IDS) | Zeek | SIEM (Splunk, ELK, Wazuh) | MS Security Copilot | **CyberLens v1.0** |
|---|---|---|---|---|---|---|
| Reads raw packets | ✅ deepest in the world | ✅ | ✅ | ❌ (works on logs) | ❌ | ✅ 6 native **+ thousands via the tshark adapter (v0.5)** |
| Detection / alerting | ❌ | ✅ ~tens of thousands of signatures | ✅ rich logs | ✅ rules + correlation | ✅ | ✅ 8 own patterns **+ 10,000+ inherited via the Suricata adapter (v0.4)** |
| **Plain-English explanation of every event** | ❌ expert hex/panels | ❌ one-line technical alerts | ❌ log lines | ❌ "rule X fired" | ✅ | ✅ **every single event** |
| **Raw evidence shown next to the meaning** | ✅ (all raw, no meaning) | ❌ | ❌ | ❌ | partial | ✅ **always, side by side** |
| Correlates events into one incident | ❌ | limited | ❌ | ✅ but output is technical | ✅ | ✅ **narrated story + timeline** |
| **Tells you what to DO next (response playbooks)** | ❌ | ❌ | ❌ | partial (technical runbooks) | partial | ✅ **v0.7 — plain-English, defensive, step-by-step** |
| **Blue-team AND red-team view together** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **same event, both sides** |
| Point-and-click UI a beginner can start with | ✅ (expert-oriented panels) | ❌ | ❌ | ✅ (dashboards, config-heavy) | ✅ | ✅ **web console v0.9, drag & drop, one-click install (.deb)** |
| Built-in training mode | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **labeled live-fire simulation (real pipeline, fake traffic)** |
| One-word verdict (CLEAN/COMPROMISED) | ❌ | ❌ | ❌ | partial | ✅ | ✅ |
| A beginner can understand the output | ❌ | ❌ | ❌ | ❌ | partial | ✅ **that's the whole point** |
| Open source; readable implementation | partial | ✅ | ✅ | heavy | ❌ closed, expensive | ✅ (a few thousand — a full afternoon's read) |

## What each classic tool is brilliant at (respect!)

- **Wireshark/tcpdump** — the world's best *microscope* for packets. Nothing
  catches more detail. But it's a microscope: it shows, it never explains, and
  a beginner sees alphabet soup.
- **Suricata/Snort** — industrial *smoke detectors*. Thousands of signatures,
  blazing fast, real-time blocking. But alerts read like
  `"ET SCAN Potential SYN Scan"` — the machine talks to the expert, not to you.
- **Zeek** — turns traffic into beautifully structured logs. For analysts who
  already know what to look for.
- **SIEMs (Splunk, ELK, Wazuh)** — the *library + detective desk*: collect
  everything, correlate into incidents. They DO correlate — but output is
  tickets and dashboards, not stories, and they cost six figures and months
  to deploy. Alert fatigue is one of the most documented problems in the field.
- **Metasploit/Burp** — the red side: powerful offence frameworks. No defence
  view, no narration, no teaching.

## So what is actually ADVANCED about CyberLens?

### 1. Translation-first architecture
Every event carries three layers bound together: **evidence** (the raw
tcpdump-style line), **meaning** (plain English), and **advice** (what to do).
Classic tools give you one layer and expect you to supply the rest from your
head. This is the rarest feature in the industry — the big vendors are only
now building it with LLMs ("security copilots"), and it's closed/cloud/paid.

### 2. Correlation that NARRATES
A SIEM says: *"incident #4711: 6 rules matched."*
CyberLens says: *"Your server 10.0.0.5 was scouted, then attacked, then broken
into — here is the timeline — each event alone looked small, together they
are one intrusion."* Same math, human story. The story IS the security product.

### 3. Both perspectives on the same card (blue + red)
No mainstream tool does this. Blue: what to do. Red: why the technique works.
For a learner this is the fastest path to real understanding — you can't
defend what you don't understand from the attacker's side.

### 4. One universal event format = true "all-rounder" glue
Live simulator, dashboard, and real pcap files all emit the SAME event dict.
Correlator and narrator never know (or care) where data came from. This is
the architectural pattern that makes "one tool that does everything" actually
buildable — you wrap sources, you don't rewrite them.

### 5. A tool that trains its user
Every other tool *assumes* expertise. CyberLens *builds* it: plain English,
glossary, HOW_IT_WORKS, the attacker's reasoning on every card. The user
outgrows the tool exactly as fast as they learn — which is the goal.

### 6. Radical transparency
a few thousand lines, zero dependencies (python3 stdlib only — that's why the whole
app installs as a 60 KB `.deb`), every byte explainable, tests prove every
claim on every run. Wireshark is ~2 million+ lines — magnificent, but you
will never read it all. You can read ALL of CyberLens in one afternoon.

## Where the classic tools still beat us (the honest list)

| Gap | Them | Us | Closed by |
|---|---|---|---|
| Detection depth | 10,000+ signatures | ~8 patterns | ✅ **CLOSED in v0.4 — by wrapping Suricata's `eve.json`** (we inherit all 10,000+ signatures; it detects, we explain) |
| Protocol coverage | thousands | 6 basic ones | ✅ **CLOSED in v0.5 — tshark adapter: Wireshark's decoding engine wrapped; native parser and live tshark verified to give identical results** |
| Scale | millions of events/sec | hundreds | 🟡 **v0.8 measured honestly: 50,000 packets in 0.22 s (~225,000 pkt/s, single-threaded, pure stdlib) — thousands× faster than any human reads; millions/sec remains theirs** |
| Real-time from live interfaces | yes | Linux IPv4 TCP/UDP | v1.0: real interface capture, permission errors, pause/stop and HTML snapshots; 100,000-record cap; not full protocol parity |
| Installable desktop app | yes | scripts only | ✅ **CLOSED in v0.9 — one-command `.deb` build, `sudo apt install`, menu entry next to Wireshark, Python stdlib app; tshark recommended for live capture** |
| 20 years of battle-testing | yes | 9 iterations | the loop, forever |

**A tool is not "advanced" because it has more features. It is advanced when
it makes its user more capable.** By that measure the classic tools made
experts faster; CyberLens aims to make beginners into experts.

---

*Part of the CyberLens teaching project — see `HOW_IT_WORKS.md` for how it
works, `README.md` for status, `tests.py` for proof.*


**v1.0 export:** portable HTML reports include raw evidence, stories and response
playbooks. Capture transport availability does not mean full Wireshark protocol
coverage: live narration currently uses the native IPv4 TCP/UDP decoder.

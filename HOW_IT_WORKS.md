# 🧠 HOW IT WORKS — CyberLens explained with one example

**One sentence:** CyberLens watches network activity (live-simulated or from a
real capture file), turns every piece of raw technical evidence into one
**event** written in plain English, connects related events into **attack
stories**, and shows both the defender's move and the attacker's logic.

---

## The journey of one packet 🚚

Follow **one single packet** through the whole system. Our example: the
attacker `203.0.113.7` sends a SYN (a "knock on the door") to port `3389`
of server `10.0.0.5` — one knock of the 21-knock port scan.

### Step 1 — The packet exists as bytes on disk

`make_demo_pcap.py` wrote it into `captures/demo.pcap` as **54 raw bytes**:

```
[ Ethernet header: 14 bytes ]  who sent it on the local network
[ IP header:     20 bytes ]  src 203.0.113.7 → dst 10.0.0.5
[ TCP header:    20 bytes ]  dest port 3389, flag SYN set
```

This is a real pcap file — open it in **Wireshark** and you'll see every packet.

### Step 2 — `replay.py` reads and peels it

```python
read_pcap("captures/demo.pcap")   # 76 packets come out, each with a timestamp
decode(frame)                     # peels Ethernet → IP → TCP layers
```

`decode()` returns the useful facts, like a customs officer opening a parcel:
`("tcp", "203.0.113.7", "10.0.0.5", 40008, 3389, 0x02, b"")`
→ *who sent it, to whom, to which door, and what kind of knock (SYN).*

### Step 3 — A rule notices a PATTERN (this is "detection")

One knock means nothing. The rule watches the whole capture:

```python
if flags == 0x02:                       # a bare SYN = a knock
    syn_targets[src].add((dst, dport))  # remember EVERY door this source knocked on
...
if len(targets) >= 10:                  # 10+ different doors = not a person,
                                        # it's a map-maker → PORT SCAN
```

21 knocks on 21 different ports from the same machine → **port scan detected**.

### Step 4 — The pattern becomes an EVENT (the "universal plug")

Every sensor — live or replay — produces the **same shape** of event, so every
other part of the tool can understand every sensor:

```python
{
  "title":    "Port scan from 203.0.113.7 (21 ports)",
  "raw":      "IP 203.0.113.7 > 10.0.0.5:21: Flags [S]  …",   # the EVIDENCE
  "english":  "One machine (203.0.113.7) sent connection-start packets
               to 21 different ports…",                        # the MEANING
  "category": "recon",            # where it sits in the attack lifecycle
  "severity": "medium",           # how urgent
  "src": "203.0.113.7", "dst": "10.0.0.5",
  "blue":     "…block it and audit open ports…",               # defender's move
  "red":      "…each open port reveals a service…",            # attacker logic
  "ts": 1992941303.2,             # when it happened
}
```

### Step 5 — `correlator.py` connects events into a STORY

Each alert is recorded in a little history book, **per IP**:

```
203.0.113.7:  [recon  15:15:03]  ← port scan         }
10.0.0.5:     [recon  15:15:03]  ← it was the target } both get remembered
10.0.0.5:     [attack 15:15:03]  ← SSH brute force   ← now it has recon + attack
```

Rule inside the correlator: **same "who", new phase, over time = one story.**
When SSH brute-force lands on `10.0.0.5`, a story card is born:

> **Escalation: 10.0.0.5 is under attack** — *first it was quietly scouted
> (recon), now it is under active attack… stop this chain before step three.*
> Timeline: `recon · Port scan` → `attack · Repeated SSH logins`

When the DNS-theft event (category `breach`) later touches `10.0.0.5` too:

> **🚨 FULL ATTACK CHAIN: 10.0.0.5 is compromised** — *scouted → attacked →
> broken into. Each event alone looked small; together they are one
> intrusion.*

### Step 6 — A human reads the verdict

```
packets: 76 · alerts: 6 · stories: 2 · threat score: 100/100
verdict: COMPROMISED
```

### Step 7 — The playbook answers "okay… so what do I DO?" (v0.7)

The story tells you what happened; `playbooks.py` tells you what happens
next **on your side**. Each detected pattern maps to one defensive,
plain-English plan with the same shape every time:

```
🔎 Port scan response — applies when: one source probed many ports
  1. Ask first: is this source one of ours? …
  2. Check the firewall: which of the scanned ports actually ANSWERED? …
  3. …
  ⚠ watch out: A scan is a question, not an attack. Respond to the answer.
```

Deterministic (same event → same playbook), defensive-only by design, and
proven by a test that greps every step for attack-tool instructions and
must find none.

**Raw bytes in → a story a beginner can act on, out.** That is the whole tool.

---

## 🧠 Is this AI? (No — here is the actual brain)

CyberLens uses **zero AI, zero internet, zero dependencies**. The plain-English
storytelling that *looks* intelligent is three deterministic mechanisms working
together, all written in ordinary Python:

**1. Threshold rules (detection)** — plain `if` statements:

```python
if flags == 0x02:                        # a bare SYN = a knock on a door
    syn_targets[src].add((dst, dport))   # remember EVERY door this source knocks on
...
if len(targets) >= 10:                   # 10+ different doors = a map-maker → SCAN
```

**2. Translation templates (explanation)** — hand-written text with the
facts filled in (f-strings):

```python
english = (f"One machine ({src}) sent connection-start packets to "
           f"{len(targets)} different ports on {dst} — knocking on every "
           f"door to map what's open. Reconnaissance: step one of almost "
           f"every attack.")
```

**3. Phase tracking (stories)** — a tiny state machine, one history book per IP:

```
recon           → no story yet
recon + attack  → "Escalation" story
recon + attack + breach → "🚨 FULL ATTACK CHAIN" story
```

**Why not AI?** Speed (instant), cost (free), offline (works on an air-gapped
machine), and honesty: the explanation can never contradict the evidence —
it IS the evidence, restated. The proof: turn your internet off and run it;
the output is identical.

**Where AI comes in (v0.6 — shipped):** an *optional* layer ON TOP of the
rules, exactly as designed — opt-in with `--ai`, configured via
`ai_config.json` or `CYBERLENS_AI_*` env vars pointing at any
OpenAI-compatible endpoint (Groq, OpenRouter, OpenAI, or your own VPS
running Ollama). It only ADDS a clearly-labelled 🤖 commentary section below
the built-in explanation; it can never replace or override it, and if it is
unconfigured, offline, or slow, the output is byte-identical to v0.5. The
deterministic core stays so the tool never *depends* on an AI — the same
hybrid philosophy as commercial "security copilots", but with the evidence
always in charge.

## What every file does

| File | What it does | Analogy |
|---|---|---|
| `server.py` | The framework. Loads all sensors, stamps & stores every event, serves the live dashboard + API | The studio switchboard |
| `plugins/*.py` | Sensors. Each file = one scenario (~40 lines), auto-discovered, drop-in replaceable | Different kinds of security cameras |
| `correlator.py` | The brain. Connects events about the same IP into attack stories | The detective linking clues on a wall |
| `index.html` | The live dashboard: feed, threat score, blue/red views, story timelines | The control-room screen |
| `replay.py` | **The traffic narrator.** Reads any real `.pcap` and tells the story in plain English (CLI) | A translator watching CCTV footage |
| `suricata_adapter.py` | **The IDS wrapper.** Reads Suricata's `eve.json` alerts → plain-English events (10,000+ signatures inherited) | A translator for the smoke detector's beeps |
| `tshark_adapter.py` | **The protocol wrapper.** Runs Wireshark's engine (tshark) on any capture — thousands of protocols decoded, same story out | A translator fluent in every language |
| `playbooks.py` | **The "what now?" layer (v0.7).** Maps every detected pattern to a defensive, plain-English response plan | The evacuation map on the hotel door |
| `webui.py` + `dashboard.html` | **The web console (v0.9).** Local server + single-page app: drop captures, see timeline/stories/playbooks, per-event AI, training simulation | The control room anyone can walk into |
| `ai_narrator.py` | **The optional AI layer (v0.6).** Adds a clearly-labelled 🤖 commentary section on top of the rule engine — never replaces it; unconfigured = output identical | A guest commentator who can be sent home |
| `make_demo_pcap.py` | Builds the demo capture (a scripted mini-intrusion) | The film set |
| `make_big_pcap.py` | Builds the deterministic scale-test capture (thousands of packets + one attack chain) | A crowd scene for the stress test |
| `tests.py` | 99 automated checks — sensors, correlator, all pipelines, AI layer, playbooks, scale, web console, and the `.deb` package itself | The quality inspector at the factory gate |

**The architecture secret:** nothing is "one big tool". Every input — live
sensor or pcap file — becomes the same event dict (step 4), so the correlator,
dashboard, and narrator never care where data came from. Adding a new source
never touches the rest. That is what makes an "all-rounder" possible.

## Glossary (plain English)

- **sensor** — a small watcher that recognizes one scenario and describes it
- **event** — one thing that happened: evidence + meaning + advice
- **category** — where in the attack lifecycle it sits:
  `normal` (everyday) → `recon` (scouting) → `attack` (trying to break in) →
  `breach` (they're in) → `campaign` (a connected story)
- **severity** — urgency: `info → low → medium → high → critical`
- **correlation** — asking "same who, over time?" so split-up attacks can't hide
- **blue view / red view** — what the defender should do / why the technique works
- **verdict** — the bottom line for the whole capture: CLEAN / SUSPICIOUS / COMPROMISED

## Try it yourself

```bash
# the full app, installed like any Kali tool:
bash packaging/build_deb.sh && sudo apt install ./release/cyberlens_1.0.0-1_all.deb
cyberlens-web                          # web console → http://127.0.0.1:8787

# or straight from the project folder:
cd cyberlens
python3 webui.py                       # same web console, no install needed
python3 server.py                      # classic live dashboard → :8000
python3 make_demo_pcap.py              # build the demo capture
python3 replay.py captures/demo.pcap   # narrate it
python3 replay.py captures/demo.pcap --live     # watch it happen in real time
python3 replay.py captures/demo.pcap --view red # the attacker's perspective
python3 make_big_pcap.py --packets 50000 && python3 replay.py big.pcap  # scale!
python3 tests.py                       # 99 green checks
```

## Feed it YOUR OWN capture

```bash
# Linux/macOS: capture 60 seconds of your own network to a file
sudo tcpdump -i eth0 -w mine.pcap timeout 60
# then:
python3 replay.py mine.pcap

# Wireshark: File → Save As… → choose "pcap" format
# pcapng files? convert first:  tshark -F pcap -r in.pcapng -w mine.pcap
```

The narrator will tell you what your own network is doing — in plain English.


## v1.0 — live capture and report export

`live_capture.py` starts a capture helper, not a second detection engine.
Tshark streams **classic pcap** (`-F pcap`, not its default pcapNG) through
stdout. A non-blocking reader handles partial packet headers and payloads.
The decoder feeds the same `replay.build_events()` rules every 1.5 seconds.
Events are updated by stable source/destination/title identity, rather than
adding the same growing scan on each refresh. Each session has a private
correlator. The session stops at 100,000 decoded records.

Root-side raw AF_PACKET capture is also available on Linux. Prefer properly
configured dumpcap permissions instead of running the web server as root.
See README for current protocol and permission limits.

`report.py` escapes evidence and narration into a self-contained, print-friendly
HTML file. The web console downloads it through `/api/report`; CLI replay
supports `--export FILE.html`. No external scripts, fonts, or remote uploads.

`DESIGN_SYSTEM.md` records the UI/UX skill query and the applied design decisions.

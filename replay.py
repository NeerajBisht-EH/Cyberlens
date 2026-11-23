#!/usr/bin/env python3
"""
CyberLens replay — the traffic narrator (v0.3, shared core since v0.5).

Point it at a real packet capture (.pcap) and it tells you WHAT HAPPENED in
plain English — the same event pipeline the dashboard uses, but reading real
packets instead of the simulator:

    python3 replay.py captures/demo.pcap              # full report
    python3 replay.py captures/demo.pcap --live       # watch it unfold in real time
    python3 replay.py captures/demo.pcap --view red   # attacker's perspective
    python3 replay.py captures/demo.pcap --json       # machine-readable output

Accepts classic pcap files from tcpdump / Wireshark / tshark.
Pure Python stdlib — no dependencies.

ARCHITECTURE NOTE (v0.5): the detection core (build_events) now works on
"records" — decoded packet facts, not raw bytes. Any source that can produce
records can use this brain: this file (native pcap parsing) and
tshark_adapter.py (Wireshark's engine, thousands of protocols) share it.
Every narrated event is stamped with the time its pattern STARTED, so the
story always reads in true chronological order.
"""
import argparse
import json
import socket
import struct
import sys
import textwrap
import time
import urllib.parse
from collections import defaultdict

import correlator
import ai_narrator   # v0.6: OPTIONAL companion layer — never replaces the engine
import playbooks     # v0.7: what to DO next — deterministic, defensive plans

R, B, D = "\033[0m", "\033[1m", "\033[2m"
A = "\033[96m"      # AI layer colour (bright cyan — clearly a different voice)
COLOR = {"normal": "\033[92m", "recon": "\033[93m", "attack": "\033[38;5;208m",
         "breach": "\033[91m", "campaign": "\033[95m"}
if not sys.stdout.isatty():                    # plain output when piped
    R = B = D = ""
    A = ""
    COLOR = {k: "" for k in COLOR}
SEV_W = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 30}
BAD_SYNTAX = ("' or '", "union select", "../", "<script", "' and '")


def suspicious_line(line):
    """True if an HTTP request line hides attack syntax.
    URL-decodes first, because real attackers encode payloads (%27 = ' etc.)
    to slip past naive filters — and past naive detectors."""
    low = urllib.parse.unquote(line).lower()
    return any(b in low for b in BAD_SYNTAX)


# --------------------------------------------------------------- pcap I/O ----
def read_pcap(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise SystemExit(f"error: {path} is not a classic pcap file "
                         f"(pcapng? convert: tshark -F pcap -r in.pcapng -w out.pcap)")
    off, pkts = 24, []
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        frame = data[off:off + incl]
        off += incl
        pkts.append((sec + frac / (1e9 if nano else 1e6), frame))
    return pkts


def decode(frame):
    """Peel Ethernet -> IPv4 -> TCP/UDP. Returns a tuple, or None."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    total = struct.unpack("!H", ip[2:4])[0] or len(ip)
    l4 = ip[ihl:min(len(ip), total)]
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        flags = l4[13]
        payload = l4[(l4[12] >> 4) * 4:]
        return ("tcp", src, dst, sport, dport, flags, payload)
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return ("udp", src, dst, sport, dport, 0, l4[8:])
    return None


def dns_qname(payload):
    labels, i = [], 12
    while i < len(payload) and payload[i] != 0:
        n = payload[i]
        if n > 63 or i + 1 + n > len(payload):
            break
        labels.append(payload[i + 1:i + 1 + n].decode("latin1"))
        i += 1 + n
    return ".".join(labels) if labels else "(unreadable)"


# ------------------------------------------------------ record preparation ----
# A "record" is decoded packet facts, source-agnostic:
#   (ts, proto, src, dst, sport, dport, flags, payload, dns_q)
# payload: str or bytes (HTTP request line etc.); dns_q: parsed query name.
def read_records(path):
    """Native path: pcap file -> records (our own Ethernet/IP/TCP/UDP parser)."""
    pkts = read_pcap(path)
    records = []
    for ts, frame in pkts:
        d = decode(frame)
        if d is None:
            continue
        proto, src, dst, sport, dport, flags, payload = d
        dns_q = None
        if proto == "udp" and dport == 53 and len(payload) >= 16:
            dns_q = dns_qname(payload)
        records.append((ts, proto, src, dst, sport, dport, flags, payload, dns_q))
    return records, len(pkts)


# ------------------------------------------------------------- detection ----
def build_events(records, total_packets=None):
    """The shared detection brain: records -> plain-English events."""
    if total_packets is None:
        total_packets = len(records)
    syn_targets = defaultdict(set)     # src -> {(dst, port)}
    first_syn = {}                     # src -> ts of its first SYN
    ssh_times = defaultdict(list)      # (src, dst) -> [ts]
    gets = []                          # (ts, src, dst, request line)
    dns_small = defaultdict(list)      # src -> [(ts, qname)]
    dns_large = defaultdict(list)
    n_tcp = n_udp = n_other = 0
    t_first = t_last = None

    for ts, proto, src, dst, sport, dport, flags, payload, dns_q in records:
        t_first = ts if t_first is None else t_first
        t_last = ts
        if proto == "tcp":
            n_tcp += 1
            if isinstance(payload, bytes):
                payload = payload.decode("latin1", "replace")
            if flags == 0x02:                            # bare SYN
                syn_targets[src].add((dst, dport))
                first_syn.setdefault(src, ts)
                if dport == 22:
                    ssh_times[(src, dst)].append(ts)
            if dport == 80 and payload[:4] == "GET ":
                line = payload.split("\r\n")[0]
                gets.append((ts, src, dst, line))
        elif proto == "udp":
            n_udp += 1
            if dport == 53 and dns_q:
                # long query names = classic data-tunnelling smell
                (dns_large if len(dns_q) >= 45 else dns_small)[src].append((ts, dns_q))
        else:
            n_other += 1
    n_other += max(0, total_packets - len(records))

    evs = []

    def add(ts, **kw):
        kw["ts"] = ts
        evs.append(kw)

    # -- normal web browsing ----------------------------------------------
    web = defaultdict(list)
    for ts, src, dst, line in gets:
        if not suspicious_line(line):
            web[src].append((ts, dst, line))
    for src, items in web.items():
        raw = "\n".join(line for _, _, line in items[:3])
        if len(items) > 3:
            raw += f"\n… {len(items)} requests total …"
        add(items[0][0],
            title=f"Web browsing from {src}",
            raw=raw,
            english=(f"{src} requested {len(items)} web pages over plain HTTP — "
                     f"ordinary browsing, like someone reading websites."),
            category="normal", severity="info", src=src, dst=items[0][1],
            blue="No action needed — baseline traffic.",
            red="Baseline traffic is what attackers try to blend into.")

    # -- suspicious web requests -------------------------------------------
    bad = [(ts, src, dst, line) for ts, src, dst, line in gets
           if suspicious_line(line)]
    if bad:
        ts, src, dst, line = bad[-1]
        decoded = urllib.parse.unquote(line)
        add(ts,
            title=f"Attack syntax in web requests from {src}",
            raw="\n".join(l for _, _, _, l in bad[:3]),
            english=(f"A request to your web server carries attack syntax — "
                     f"URL-decoded it reads: '{decoded}'. Attackers encode "
                     f"their payloads (%27 = apostrophe) to slip past filters. "
                     f"The sender ({src}) is trying to make the application "
                     f"misbehave: classic injection probing, not normal "
                     f"browsing."),
            category="attack", severity="high", src=src, dst=dst,
            blue=("Check whether the app rejected it (error / WAF block) and "
                  "whether it uses parameterized queries. Review other requests "
                  "from this IP."),
            red=("Apps that paste user input into commands or queries are "
                 "trusting strangers to type innocent words — these probes test "
                 "exactly that."))

    # -- port scan -----------------------------------------------------------
    for src, targets in syn_targets.items():
        if len(targets) >= 10:
            dsts = sorted({d for d, _ in targets})
            raw = "\n".join(f"IP {src} > {d}:{p}: Flags [S]"
                            for d, p in sorted(targets)[:3])
            raw += f"\n… {len(targets)} ports probed on {', '.join(dsts)} …"
            add(first_syn[src],
                title=f"Port scan from {src} ({len(targets)} ports)",
                raw=raw,
                english=(f"One machine ({src}) sent connection-start packets to "
                         f"{len(targets)} different ports on {', '.join(dsts)} — "
                         f"knocking on every door to map what's open. "
                         f"Reconnaissance: step one of almost every attack."),
                category="recon", severity="medium", src=src, dst=dsts[0],
                blue=("If this source is unknown, block it and audit which of "
                      "those ports actually need to be open."),
                red=("Each open port reveals a service, often its version — "
                     "the ingredient list for the next step."))

    # -- SSH brute force ------------------------------------------------------
    for (src, dst), times in ssh_times.items():
        if len(times) >= 5:
            span = times[-1] - times[0]
            add(times[0],
                title=f"Repeated SSH logins: {src} -> {dst}",
                raw=(f"IP {src} > {dst}.22: Flags [S]  x{len(times)}\n"
                     f"{len(times)} connection attempts in {span:.0f}s"),
                english=(f"The same machine ({src}) opened {len(times)} SSH "
                         f"connections to {dst} within {span:.0f} seconds — like "
                         f"a thief trying every key on the ring. People don't "
                         f"reconnect that fast; password-guessing programs do."),
                category="attack", severity="high", src=src, dst=dst,
                blue=("Block the source, enforce key-based login, and enable "
                      "fail2ban-style auto-blocking after a few failures."),
                red=("Each new connection is a fresh guess — and nobody is "
                     "counting."))

    # -- DNS: normal lookups + tunnelling suspicion ---------------------------
    for src, items in dns_small.items():
        names = ", ".join(q for _, q in items[:4])
        add(items[0][0],
            title=f"Normal DNS lookups from {src}",
            raw="\n".join(f"A? {q}" for _, q in items[:3]),
            english=(f"{src} asked the network's phone book (DNS) for: {names}. "
                     f"Ordinary lookups made before connecting somewhere."),
            category="normal", severity="info", src=src, dst="(resolver)",
            blue="No action needed.",
            red=("DNS is trusted and almost never blocked on the way out — "
                 "which is what makes the breach pattern below so dangerous."))
    for src, items in dns_large.items():
        if len(items) >= 3:
            _, q = items[-1]
            add(items[0][0],
                title=f"Suspicious DNS volume from {src} (tunnelling?)",
                raw=("\n".join(f"TXT? {q}" for _, q in items[:3])
                     + f"\n… {len(items)} oversized queries …"),
                english=(f"{src} is sending unusually long DNS queries "
                         f"(example: '{q}'). Real lookups are short — packing "
                         f"data into query names is a classic way to smuggle "
                         f"stolen information out through a channel nobody "
                         f"watches."),
                category="breach", severity="critical", src=src, dst="(resolver)",
                blue=("Investigate this machine: which process makes these "
                      "queries, what data fits inside them, and who else it "
                      "talks to. Treat as likely data exfiltration."),
                red=("Hide the loot inside questions nobody reads."))

    # v0.7: stamp each event with its response-playbook id (deterministic map,
    # single source of truth lives in playbooks.TITLE_MAP)
    for ev in evs:
        ev["pb"] = next((pid for prefix, pid in playbooks.TITLE_MAP
                         if ev["title"].startswith(prefix)), None)

    evs.sort(key=lambda e: e["ts"])
    meta = {"packets": total_packets, "tcp": n_tcp, "udp": n_udp, "other": n_other,
            "duration": round(t_last - t_first, 1) if t_first else 0.0}
    return evs, meta


# ----------------------------------------------------------------- output ----
def show(ev, view):
    c = COLOR.get(ev["category"], "")
    clock = time.strftime("%H:%M:%S", time.localtime(ev.get("ts") or time.time()))
    pad = " " * 10
    print(f"  {D}{clock}{R}  {c}{B}{ev['title']}{R}")
    print(f"  {pad}  {c}[{ev['category']} · {ev['severity']}]{R}")
    print(textwrap.fill(ev["english"], 96,
                        initial_indent=f"  {pad}  ", subsequent_indent=f"  {pad}  "))
    for line in ev["raw"].splitlines()[:3]:
        print(f"  {pad}  {D}{line}{R}")
    if len(ev["raw"].splitlines()) > 3:
        print(f"  {pad}  {D}…{R}")
    act = ev["blue"] if view == "blue" else ev["red"]
    head = "🛡 " if view == "blue" else "🎯 "
    print(textwrap.fill(head + act, 96,
                        initial_indent=f"  {pad}  ", subsequent_indent=f"  {pad}  "))
    if ai_narrator.is_active():                    # v0.6: ADD, never replace
        note = ai_narrator.enrich(ev)
        if note:
            wrapped = textwrap.fill("🤖 " + note, 96,
                                    initial_indent=f"  {pad}  ",
                                    subsequent_indent=f"  {pad}  ")
            print(f"{A}{wrapped}{R}")
    print()


def main():
    ap = argparse.ArgumentParser(description="CyberLens — the traffic narrator")
    ap.add_argument("pcap", help="path to a .pcap capture file")
    ap.add_argument("--view", choices=["blue", "red"], default="blue",
                    help="defender (blue) or attacker (red) perspective")
    ap.add_argument("--live", action="store_true",
                    help="play the capture back in real time")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="live playback speed multiplier (default 1)")
    ap.add_argument("--json", action="store_true",
                    help="print machine-readable JSON instead of text")
    ap.add_argument("--ai", action="store_true",
                    help="enable the OPTIONAL AI companion layer (additive; "
                         "needs ai_config.json or CYBERLENS_AI_* env vars — "
                         "without it, the built-in engine runs alone)")
    ap.add_argument("--no-playbooks", action="store_true",
                    help="hide the v0.7 'what to do next' response playbooks")
    ap.add_argument("--export", metavar="FILE.html",
                    help="also write a standalone HTML report (v1.0)")
    args = ap.parse_args()

    if args.ai:
        if ai_narrator.activate():
            print(f"[ai] companion layer active ({ai_narrator.describe()})",
                  file=sys.stderr)
        else:
            print("[ai] not configured — running the built-in engine only. "
                  "Setup: see the header of ai_narrator.py.", file=sys.stderr)

    records, total = read_records(args.pcap)
    events, meta = build_events(records, total)
    end_ts = max((r[0] for r in records), default=time.time())

    all_events, stories = [], []
    for ev in events:
        all_events.append(ev)
        st = correlator.observe(ev, now=end_ts + 1)
        if st:
            st["ts"] = ev["ts"]
            all_events.append(st)
            stories.append(st)

    score = min(100, sum(SEV_W.get(e.get("severity"), 0) for e in all_events))
    verdict = ("CLEAN" if score < 10 else "SUSPICIOUS" if score < 40
               else "COMPROMISED")

    if args.json:
        print(json.dumps({"file": args.pcap, **meta, "score": score,
                          "verdict": verdict, "events": all_events,
                          "playbooks": playbooks.for_analysis(all_events)},
                         indent=1))
        return

    print(f"\n{B}  CyberLens replay — traffic narrator v0.3{R}")
    print(f"  {D}reading {args.pcap} — {meta['packets']} packets · "
          f"{meta['tcp']} TCP / {meta['udp']} UDP · "
          f"{meta['duration']}s of traffic{R}\n")
    if args.live:
        print(f"  {D}live mode: playing the capture as it happened "
              f"(speed x{args.speed}){R}\n")

    prev = None
    for ev in all_events:
        if args.live and prev is not None:
            time.sleep(min(max(ev["ts"] - prev, 0), 2.0) / max(args.speed, 0.1))
        prev = ev["ts"]
        show(ev, args.view)

    n_alerts = sum(1 for e in all_events if e.get("severity", "info") != "info")
    print(f"{B}  ── summary ──{R}")
    print(f"  packets: {meta['packets']} · alerts: {n_alerts} · "
          f"stories: {len(stories)} · threat score: {score}/100")
    vcol = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m",
            "COMPROMISED": "\033[91m"}[verdict] if sys.stdout.isatty() else ""
    print(f"  verdict: {vcol}{B}{verdict}{R}\n")

    if not args.no_playbooks:                 # v0.7: what to DO next
        print(playbooks.section(all_events))

    if args.export:                           # v1.0: standalone HTML report
        import os as _os
        import report
        analysis = {"file": {"name": _os.path.basename(args.pcap),
                             "size": _os.path.getsize(args.pcap),
                             "kind": "pcap"},
                    **meta, "score": score, "verdict": verdict,
                    "events": all_events, "stories": stories,
                    "playbooks": playbooks.for_analysis(all_events)}
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write(report.render(analysis))
        print(f"\n  report written → {args.export}")


if __name__ == "__main__":
    main()

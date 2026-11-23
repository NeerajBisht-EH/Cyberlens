#!/usr/bin/env python3
"""
CyberLens tshark adapter — protocol coverage by wrapping (v0.5).

Wireshark/tshark can dissect THOUSANDS of protocols — decades of decoding
work. We wrapped Suricata for detection depth (v0.4); this adapter wraps
tshark for protocol breadth:

    tshark:    decodes every protocol on earth        (its job)
    CyberLens: detects patterns, explains, tells the story   (our job)

Two ways to use it:

  1. With tshark installed (real live wrap):
        python3 tshark_adapter.py captures/demo.pcap
     (runs  tshark -r <file> -T json  and translates the decoded layers)

  2. Without tshark (pre-exported sample — works anywhere):
        python3 tshark_adapter.py captures/tshark-sample.json
     (a saved  tshark -T json  export; same parser, no tshark needed)

Real-world lesson built in: tshark's JSON format differs across versions —
values wrapped in arrays (old) vs plain strings (new), HTTP split into
method/uri fields (old) vs one request line (new), DNS query names flat
(old) vs nested under "Queries" (new). The helpers below normalise all of
it, and fall back to raw tcp/udp payloads when dissectors don't fire —
so this adapter survives tshark upgrades.

The detection brain is imported from replay.py — one brain, many mouths.
Pure stdlib.
"""
import argparse
import json
import shutil
import subprocess
import time

import correlator
from replay import build_events, show, SEV_W, dns_qname, R, B, D


def val(layer, key, default=""):
    """Read a field from a tshark layer, tolerating BOTH output formats:
    old tshark: "ip.src": ["192.168.1.24"]   new tshark: "ip.src": "192.168.1.24"
    """
    v = layer.get(key, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v


def tcp_flags(tcp):
    """tshark gives flags as hex ('0x0002') or as booleans — handle both."""
    raw = val(tcp, "tcp.flags", None)
    if raw:
        try:
            return int(raw, 16)
        except (TypeError, ValueError):
            pass
    flags = 0
    for key, bit in (("tcp.flags.syn", 0x02), ("tcp.flags.ack", 0x10),
                     ("tcp.flags.fin", 0x01), ("tcp.flags.reset", 0x04),
                     ("tcp.flags.push", 0x08)):
        if val(tcp, key, "False") == "True":
            flags |= bit
    return flags


def dns_query_name(dns_layer):
    """Find the queried name across tshark JSON generations:
    flat 'dns.qry.name' (old) or nested under 'Queries' (tshark 4.x)."""
    name = val(dns_layer, "dns.qry.name", None)
    if name:
        return name
    queries = dns_layer.get("Queries")
    if isinstance(queries, dict):
        for _, fields in queries.items():
            if isinstance(fields, dict):
                name = val(fields, "dns.qry.name", None)
                if name:
                    return name
        if queries:                     # the key itself is the queried name
            return next(iter(queries))
    return None


def http_request_line(layers, tcp):
    """Rebuild the HTTP request line from whatever tshark gave us.
    tshark's JSON has hidden the request line in a different place in
    almost every generation: split fields (method/uri/version), a
    'http.request.line' array, a 'http.request' boolean, or — in tshark
    4.x — as a KEY inside the http dict. Handle them all; the raw
    tcp-payload fallback also covers every other text protocol on earth."""
    http = layers.get("http") or {}
    # 1) tshark 4.x: the request line itself is a KEY in the http dict
    for key in http:
        if isinstance(key, str) and " HTTP/" in key and any(
                key.startswith(m) for m in ("GET ", "POST ", "PUT ",
                                            "HEAD ", "DELETE ", "PATCH ",
                                            "OPTIONS ")):
            return key.strip()
    # 2) old tshark: split fields
    method = val(http, "http.request.method", "")
    if method:
        uri = val(http, "http.request.uri", "")
        ver = val(http, "http.request.version", "HTTP/1.1")
        return f"{method} {uri} {ver}"
    # 3) some versions: an array of raw lines
    line0 = http.get("http.request.line")
    candidates = []
    if isinstance(line0, list):
        candidates = [e for e in line0 if isinstance(e, str)]
    elif isinstance(line0, dict):
        candidates = list(line0.keys())
    elif isinstance(line0, str):
        candidates = [line0]
    for entry in candidates:
        if entry.strip() and " HTTP/" in entry:
            return entry.strip()
    # 4) raw fallback: decode the bytes ourselves — works for ANY protocol
    hexpl = val(tcp, "tcp.payload", "")
    if isinstance(hexpl, str) and hexpl:
        try:
            return bytes.fromhex(hexpl).decode("latin1", "replace")
        except ValueError:
            return ""
    return ""


def records_from_tshark_json(docs):
    """Translate tshark's decoded layers into our source-agnostic records."""
    recs = []
    for doc in docs:
        layers = (doc.get("_source") or {}).get("layers") or {}
        frame = layers.get("frame") or {}
        ip = layers.get("ip") or {}
        if not ip:
            continue                       # ARP / non-IP: outside our focus
        try:
            ts = float(val(frame, "frame.time_epoch", "0"))
        except (TypeError, ValueError):
            ts = time.time()
        src = val(ip, "ip.src", "?")
        dst = val(ip, "ip.dst", "?")
        tcp = layers.get("tcp")
        udp = layers.get("udp")
        if tcp:
            sport = int(val(tcp, "tcp.srcport", "0"))
            dport = int(val(tcp, "tcp.dstport", "0"))
            recs.append((ts, "tcp", src, dst, sport, dport,
                         tcp_flags(tcp), http_request_line(layers, tcp), None))
        elif udp:
            sport = int(val(udp, "udp.srcport", "0"))
            dport = int(val(udp, "udp.dstport", "0"))
            dns_q = None
            if "dns" in layers:
                dns_q = dns_query_name(layers["dns"])
            if not dns_q and dport == 53:
                hexpl = val(udp, "udp.payload", "")
                if isinstance(hexpl, str) and hexpl:
                    try:
                        dns_q = dns_qname(bytes.fromhex(hexpl))
                    except ValueError:
                        pass
            recs.append((ts, "udp", src, dst, sport, dport, 0, "", dns_q))
        else:
            recs.append((ts, "ip", src, dst, 0, 0, 0, "", None))
    return recs


def load_records(path):
    """Either parse a saved tshark JSON export, or run tshark live on a pcap."""
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as fh:
            docs = json.load(fh)
        return records_from_tshark_json(docs), f"tshark export: {path}", len(docs)
    tshark = shutil.which("tshark")
    if not tshark:
        raise SystemExit(
            "tshark is not installed on this machine.\n"
            "  Option 1: install it (apt install tshark / brew install wireshark)\n"
            "  Option 2: run on the bundled sample export instead:\n"
            "        python3 tshark_adapter.py captures/tshark-sample.json")
    proc = subprocess.run([tshark, "-r", path, "-T", "json"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"tshark failed: {proc.stderr.strip()[:300]}")
    docs = json.loads(proc.stdout)
    return records_from_tshark_json(docs), f"live tshark on {path}", len(docs)


def main():
    ap = argparse.ArgumentParser(description="CyberLens — tshark adapter")
    ap.add_argument("input", help="a .pcap file (tshark runs live) or a saved "
                                  "tshark -T json export (.json)")
    ap.add_argument("--view", choices=["blue", "red"], default="blue")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ai", action="store_true",
                    help="optional AI companion layer (needs ai_config.json or "
                         "CYBERLENS_AI_* env vars; additive, never replaces the "
                         "built-in engine)")
    ap.add_argument("--no-playbooks", action="store_true",
                    help="hide the v0.7 'what to do next' response playbooks")
    args = ap.parse_args()

    if args.ai:
        import sys
        import ai_narrator
        if ai_narrator.activate():
            print(f"[ai] companion layer active ({ai_narrator.describe()})",
                  file=sys.stderr)
        else:
            print("[ai] not configured — built-in engine only "
                  "(see ai_narrator.py header)", file=sys.stderr)

    records, source, total = load_records(args.input)
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
        print(json.dumps({"source": source, **meta, "score": score,
                          "verdict": verdict, "events": all_events}, indent=1))
        return

    print(f"\n{B}  CyberLens <- tshark adapter  (protocol wrap, v0.5){R}")
    print(f"  {D}{source} — {meta['packets']} packets decoded by Wireshark's engine{R}\n")
    for ev in all_events:
        show(ev, args.view)

    n_alerts = sum(1 for e in all_events if e.get("severity", "info") != "info")
    print(f"{B}  ── summary ──{R}")
    print(f"  packets: {meta['packets']} · alerts: {n_alerts} · "
          f"stories: {len(stories)} · threat score: {score}/100")
    vcol = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m",
            "COMPROMISED": "\033[91m"}[verdict]
    print(f"  verdict: {vcol}{B}{verdict}{R}\n")

    import playbooks                                    # v0.7
    if not args.no_playbooks:
        print(playbooks.section(all_events))


if __name__ == "__main__":
    main()

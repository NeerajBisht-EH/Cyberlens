#!/usr/bin/env python3
"""
CyberLens Suricata adapter — the "wrap, don't rewrite" pattern (v0.4).

Suricata is a free, open-source intrusion detection engine with a community
rule library of 10,000+ signatures. We will never out-write it — and we don't
need to. This adapter READS Suricata's alert log (eve.json) and translates it
into CyberLens events:

    Suricata:  detects fast and deep                  (its job — 10k+ signatures)
    CyberLens: aggregates, explains, tells the story  (our job — the human layer)

Result: our 8 hand-written patterns become 10,000+ overnight, AND the alert
noise gets collapsed into a few readable events (alert fatigue = reduced).

On a machine running Suricata:
    suricata -i eth0 -l /var/log/suricata     # it writes eve.json there
    python3 suricata_adapter.py /var/log/suricata/eve.json

On the included sample:
    python3 suricata_adapter.py captures/eve-sample.json
    python3 suricata_adapter.py captures/eve-sample.json --json

Pure stdlib. Note: order matters in FAMILIES below — specific families are
matched before the generic "scan" family (a signature can contain both words).
"""
import argparse
import json
import time
from collections import defaultdict
from datetime import datetime

import correlator
from replay import show, SEV_W, R, B, D   # reuse the narrator's printer + scoring

# keyword -> family. Order = priority (most specific first).
FAMILIES = (
    (("tunnel", "exfil", "leak", "data theft"), "exfil"),
    (("brute", "login", "auth fail", "ssh", "telnet", "ftp"), "brute"),
    (("sql", "inject", "xss", "cross-site"), "webattack"),
    (("ddos", "dos ", "flood"), "dos"),
    (("trojan", "c2", "command and control", "botnet", "malware", "backdoor"), "malware"),
    (("portscan", "port scan", "syn scan", "sweep", "nmap", "scan"), "scan"),
)

META = {   # family -> (category, severity)
    "exfil": ("breach", "critical"), "brute": ("attack", "high"),
    "webattack": ("attack", "high"), "dos": ("attack", "medium"),
    "malware": ("breach", "critical"), "scan": ("recon", "medium"),
    "other": ("attack", "medium"),
}


def parse_ts(text):
    for fn in (lambda: datetime.fromisoformat(text).timestamp(),
               lambda: datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").timestamp()):
        try:
            return fn()
        except Exception:
            continue
    return time.time()


def classify(signature, category):
    text = f"{signature} {category}".lower()
    for keys, family in FAMILIES:
        if any(k in text for k in keys):
            return family
    return "other"


def narrate(family, src, dst, count, sig):
    """Translate a pile of Suricata alerts into one human paragraph."""
    if family == "scan":
        return (
            f"Suricata's rule library raised {count} scan alerts: {src} is probing "
            f"{dst} — knocking on many doors (ports) to map what's open. "
            f"Reconnaissance: step one of almost every attack.",
            "If this source is unknown, block it and audit which ports need to be open.",
            "Each open port reveals a service — the ingredient list for the next step.")
    if family == "brute":
        return (
            f"Suricata matched {count} login-attack signatures from {src} against "
            f"{dst} — password guessing, like a thief trying every key on the ring.",
            "Block the source; enforce key-based/MFA login; auto-block after failures.",
            "Every new connection is a fresh guess — cheap and quiet.")
    if family == "webattack":
        return (
            f"Suricata flagged {count} web-attack attempts ({sig}) — requests "
            f"crafted to make your application misbehave.",
            "Verify the app rejected them; fix with parameterized queries and input validation.",
            "Apps that paste user input into commands trust strangers to type innocent words.")
    if family == "malware":
        return (
            f"Suricata matched {count} malware/C2 signatures ({sig}) involving "
            f"{src} — traffic typical of a machine that is already compromised "
            f"and talking to its controller.",
            f"Treat {src} as compromised: isolate it, find the process, rebuild rather than 'clean'.",
            "A quiet heartbeat keeps a stolen foothold alive.")
    if family == "exfil":
        return (
            f"Suricata flagged {count} data-smuggling signatures ({sig}) from "
            f"{src} — stolen information may be leaving inside look-alike traffic.",
            "Isolate the host, identify what data fits, involve legal/management early.",
            "Hide the loot inside traffic nobody inspects.")
    if family == "dos":
        return (
            f"Suricata raised {count} flood/denial-of-service alerts targeting "
            f"{dst} — someone is trying to exhaust it.",
            "Rate-limit, filter upstream, and check service health.",
            "Cheapest attack in the book: overwhelm, don't outsmart.")
    return (
        f"Suricata's rule library (10,000+ signatures) flagged this traffic: "
        f"'{sig}'. It matched a known-bad pattern.",
        "Review the rule and the traffic; escalate if confirmed.",
        "Known-bad patterns are cheap to match — rule variety keeps detection fresh.")


# v0.7: which response playbook fits which Suricata alert family
# (None -> the alert still gets the generic 'triage basics' playbook)
FAMILY_PB = {"scan": "port_scan", "brute": "brute_force",
             "webattack": "web_attack", "exfil": "dns_exfil",
             "dos": None, "malware": None, "other": None}


def build_events(lines):
    groups = {}    # (src, dst, family) -> {count, first, last, sig}
    alerts_in = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event_type") != "alert":
            continue                    # flow / stats / dns records: not alerts
        alerts_in += 1
        src = rec.get("src_ip", "?")
        dst = rec.get("dest_ip", "?")
        alert = rec.get("alert", {})
        sig = alert.get("signature", "unknown signature")
        family = classify(sig, alert.get("category", ""))
        ts = parse_ts(rec.get("timestamp", ""))
        g = groups.setdefault((src, dst, family),
                              {"count": 0, "first": ts, "last": ts, "sig": sig})
        g["count"] += 1
        g["first"] = min(g["first"], ts)
        g["last"] = max(g["last"], ts)
        if len(sig) > len(g["sig"]):
            g["sig"] = sig

    events = []
    for (src, dst, family), g in groups.items():
        cat, sev = META[family]
        english, blue, red = narrate(family, src, dst, g["count"], g["sig"])
        clock1 = datetime.fromtimestamp(g["first"]).strftime("%H:%M:%S")
        clock2 = datetime.fromtimestamp(g["last"]).strftime("%H:%M:%S")
        raw = (f"[Suricata] signature: {g['sig']}\n"
               f"[Suricata] {g['count']} alert(s) {src} -> {dst}, "
               f"first {clock1}, last {clock2}")
        events.append(dict(title=f"Suricata: {family} activity — {src}",
                           raw=raw, english=english, category=cat, severity=sev,
                           src=src, dst=dst, blue=blue, red=red, ts=g["first"],
                           pb=FAMILY_PB.get(family)))
    events.sort(key=lambda e: e["ts"])
    return events, alerts_in


def main():
    ap = argparse.ArgumentParser(description="CyberLens — Suricata adapter")
    ap.add_argument("eve", help="path to Suricata eve.json (or the sample)")
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

    with open(args.eve, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    events, alerts_in = build_events(lines)
    end_ts = max((e["ts"] for e in events), default=time.time())

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
        print(json.dumps({"file": args.eve, "suricata_alerts": alerts_in,
                          "narrated_events": len(events), "score": score,
                          "verdict": verdict, "events": all_events}, indent=1))
        return

    print(f"\n{B}  CyberLens <- Suricata adapter  (wrap, don't rewrite){R}")
    print(f"  {D}reading {args.eve} — {alerts_in} raw alerts ingested{R}\n")
    for ev in all_events:
        show(ev, args.view)

    cut = 100 - int(len(events) / alerts_in * 100) if alerts_in else 0
    print(f"{B}  ── summary ──{R}")
    print(f"  Suricata alerts in: {alerts_in}  ->  narrated events out: "
          f"{len(events)}  (noise cut: ~{cut}%)")
    print(f"  stories: {len(stories)} · threat score: {score}/100 · "
          f"verdict: {verdict}\n")

    import playbooks                                    # v0.7
    if not args.no_playbooks:
        print(playbooks.section(all_events))


if __name__ == "__main__":
    main()

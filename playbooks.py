#!/usr/bin/env python3
"""
CyberLens response playbooks (v0.7) — what to DO, not just what happened.

The narrator explains events in plain English; the playbooks answer the next
question everyone asks: "okay… so what do I do now?"

Design rules (kept on purpose):
  - DEFENSIVE ONLY: check, contain, recover, prevent. No attack steps.
  - Plain, simple English — a junior on their first night shift can follow.
  - Deterministic: same event, same playbook. No AI, no randomness.
  - Every playbook has the same shape so tools (CLI, web UI) can render them
    without special cases.

Each playbook:
    name     — short human title
    icon     — one emoji, used by the CLI and the web UI
    trigger  — when this playbook applies (one line)
    why      — the reasoning in one sentence
    steps    — numbered actions, in the order they should be done
    watch    — the one thing people get wrong (the trap)

Used by replay.py (and the web UI) after the story is told. Normal/baseline
events get no playbook — you don't need instructions for "everything is fine".
"""


def _pb(name, icon, trigger, why, steps, watch):
    return {"name": name, "icon": icon, "trigger": trigger, "why": why,
            "steps": list(steps), "watch": watch}


PLAYBOOKS = {
    "port_scan": _pb(
        name="Port scan response",
        icon="🔎",
        trigger="One source probed many ports on your machines",
        why="A scan itself breaks nothing — the danger is what it FINDS and "
            "who now owns the map.",
        steps=[
            "Ask first: is this source one of ours? Check your asset list — "
            "monitoring tools and vulnerability scanners scan too.",
            "Check the firewall: which of the scanned ports actually ANSWERED? "
            "An open port is the only part of the scan that matters.",
            "For every open port, note the service and version, and confirm it "
            "is patched and safely configured.",
            "If the source is unknown and keeps probing, block it at the "
            "firewall and watch for it coming back from a new address.",
            "Prevent: close every port you do not truly need. A closed door "
            "cannot be picked.",
        ],
        watch="A scan is a question, not an attack. Respond to the answer "
              "(what stayed open), not the question."),

    "brute_force": _pb(
        name="Brute-force / password-guessing response",
        icon="🔑",
        trigger="Many logins from one source in a short time",
        why="Programs try thousands of passwords a minute; humans type one. "
            "Volume means automation.",
        steps=[
            "Answer the only question that matters: did any login SUCCEED "
            "after the failures? Check the authentication logs now.",
            "If one succeeded: treat that account as stolen. Disable it, "
            "change its password, and review everything it did afterwards.",
            "Block the source address at the firewall, and expect it to "
            "return from a different one.",
            "Turn on automatic blocking after a few failed attempts "
            "(fail2ban-style) so this never depends on a human watching.",
            "Prevent: switch SSH to key-based login and turn off password "
            "authentication entirely.",
        ],
        watch="Failed logins are noise; one SUCCESS is a breach. Always "
              "check for the success before anything else."),

    "web_attack": _pb(
        name="Web attack / injection response",
        icon="💉",
        trigger="Attack syntax found inside web requests",
        why="The request itself proves intent; what the application did with "
            "it decides whether this is a warning or a breach.",
        steps=[
            "Check the application and WAF logs: did the request fail, error, "
            "or return data? Each answer means something different.",
            "If data came back: assume a stranger made the database talk. "
            "Find out what that table contains and who else can reach it.",
            "Rotate database passwords, API keys, and other secrets the "
            "application can access.",
            "Fix the root cause: parameterized queries and safe APIs, so user "
            "input is always treated as data — never as code.",
            "Review other requests from the same source. Probes rarely come "
            "alone; scanners send the whole toolkit.",
        ],
        watch="One injected request that returns data is a breach, not a "
              "warning. Do not close the ticket as 'blocked attempt'."),

    "dns_exfil": _pb(
        name="DNS tunnelling / data-theft response",
        icon="🚚",
        trigger="Unusually long DNS queries carrying data out",
        why="DNS is trusted and almost never blocked on the way out — which "
            "makes it a perfect smuggler's road.",
        steps=[
            "Find the PROCESS on that machine making the long queries. The "
            "machine is talking; find the mouth.",
            "Estimate what fits inside those query names — typically chunks "
            "of a file, credentials, or internal hostnames.",
            "Block the destination domain and its name server at your "
            "resolver or firewall.",
            "Treat the machine as compromised: isolate it, scan it, and "
            "change every credential stored on it.",
            "Prevent: alert on unusually long DNS names, and consider DNS "
            "filtering so this road is watched too.",
        ],
        watch="By the time you see it, the data usually left hours ago. "
              "React to the machine, not just the queries."),

    "campaign": _pb(
        name="Full attack-chain / incident response",
        icon="🚨",
        trigger="Correlated story: the same actor moved through recon, "
                "attack, and breach",
        why="Single alerts are chapters; this is the whole book. It means the "
            "intruder succeeded at least once.",
        steps=[
            "Stop the bleeding: isolate the machines named in the story "
            "timeline from the network — but do NOT power them off.",
            "Preserve evidence FIRST: copy logs and memory from every step "
            "in the timeline before you clean anything.",
            "Hunt sideways: check what else the intruder touched since the "
            "first event in the story — the first step shows how they got in.",
            "Rotate every credential reachable from the affected machines, "
            "including service accounts and API keys.",
            "Close the exact door they used, then verify with the same "
            "evidence that it is really closed.",
        ],
        watch="Cleaning up before preserving evidence destroys the story of "
              "what happened — and the proof you will need."),

    "generic": _pb(
        name="Alert triage basics",
        icon="🧭",
        trigger="Any alert without a specific playbook yet",
        why="Most alerts are handled well by the same first four moves.",
        steps=[
            "Read the evidence yourself — never act on a summary alone.",
            "Ask: is this source known to us, and did anything SUCCEED, not "
            "just try?",
            "Check the blast radius: what could this asset reach if it is "
            "compromised?",
            "Decide: watch, block, or escalate — and write down which and why.",
            "Afterwards: note what the alert taught you about your monitoring "
            "gaps.",
        ],
        watch="Alerts age fast. An alert nobody looked at is worse than no "
              "alert at all."),
}

# how an event title maps to a playbook (deterministic, checked by tests)
TITLE_MAP = (
    ("Port scan", "port_scan"),
    ("Repeated SSH", "brute_force"),
    ("Attack syntax", "web_attack"),
    ("Suspicious DNS", "dns_exfil"),
)
CAMPAIGN_PB = "campaign"
GENERIC_PB = "generic"


def for_event(ev):
    """The playbook dict for one event, or None (normal events need none)."""
    if ev.get("category") == "campaign":
        return PLAYBOOKS[CAMPAIGN_PB]
    pid = ev.get("pb")
    if pid and pid in PLAYBOOKS:
        return PLAYBOOKS[pid]
    if ev.get("severity", "info") == "info":
        return None
    return PLAYBOOKS[GENERIC_PB]      # unknown alert -> safe basics


def for_analysis(events):
    """Ordered, de-duplicated playbooks for a finished analysis.
    Most severe first, campaigns before single patterns."""
    seen, out = set(), []
    order = {"campaign": 0, "breach": 1, "attack": 2, "recon": 3, "normal": 4}
    for ev in sorted(events, key=lambda e: (order.get(e.get("category"), 9),
                                            e.get("ts", 0))):
        pb = for_event(ev)
        if pb and pb["name"] not in seen:
            seen.add(pb["name"])
            out.append(pb)
    return out


def section(events, width=96):
    """The CLI's 'what to do next' block, plain text, ready to print."""
    pbs = for_analysis(events)
    if not pbs:
        return ""
    lines = [f"\n  ── response playbooks ({len(pbs)}) ──",
             "  What to DO about what this capture showed, in order:"]
    import textwrap
    for pb in pbs:
        lines.append("")
        lines.append(f"  {pb['icon']}  {pb['name']}")
        lines.append(textwrap.fill(f"applies when: {pb['trigger']}", width,
                                   initial_indent="     ",
                                   subsequent_indent="     "))
        for i, step in enumerate(pb["steps"], 1):
            lines.append(textwrap.fill(f"{i}. {step}", width,
                                       initial_indent="     ",
                                       subsequent_indent="        "))
        lines.append(textwrap.fill(f"⚠ watch out: {pb['watch']}", width,
                                   initial_indent="     ",
                                   subsequent_indent="     "))
    return "\n".join(lines)

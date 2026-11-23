"""
Correlation engine — the 'brain' that turns isolated alerts into attack stories.

A single alert says "something happened". A campaign says WHO did what, in
which order, over time — the story of one intruder (or one victim machine).
This is the most valuable upgrade a monitoring tool can get, because attackers
deliberately split one break-in into small, innocent-looking steps so each
step alone looks harmless. Asking "same who, over time?" breaks that trick.
"""
import threading
import time

WINDOW = 600        # how far back we connect the dots (seconds)
REANNOUNCE = 600    # after this long, a key may tell a fresh story again

CHAIN = ("recon", "attack", "breach")

LOCK = threading.Lock()
_phases = {}        # key (ip) -> [{ts, cat, sev, title, id}, ...]
_announced = {}     # key -> {"level": int, "ts": float}


def reset():
    """Forget everything (v0.9): long-running tools like the web UI analyze
    many files in one process — each new file must start with a clean brain,
    or stories from capture A would leak into capture B."""
    global _phases, _announced
    with LOCK:
        _phases = {}
        _announced = {}


def _internal(key):
    """Does this key look like one of our own machines (vs an outsider)?"""
    return key.startswith(("10.", "192.168.", "172."))


def _story(key, hist, level):
    hist = sorted(hist, key=lambda h: h["ts"])[-6:]
    timeline = "\n".join(
        "{}  {:<7}  {}".format(time.strftime("%H:%M:%S", time.localtime(h["ts"])),
                               h["cat"], h["title"])
        for h in hist)
    steps = [dict(ts=h["ts"], cat=h["cat"], title=h["title"], id=h["id"])
             for h in hist]
    victim = _internal(key)   # story about one of OUR machines vs an OUTSIDER

    if level >= 2:
        if victim:
            title = f"🚨 FULL ATTACK CHAIN: {key} is compromised"
            english = (
                f"Connect the dots: the events around your machine {key} form one "
                f"complete intrusion — it was scouted, then attacked, and now "
                f"someone is inside. Each event alone looked small and "
                f"explainable; together, in order, they tell the story of a real "
                f"compromise unfolding. This is exactly how real intrusions "
                f"hide: as a pile of 'minor' alerts nobody connected.")
            blue = (
                f"Treat {key} as compromised: isolate it from the network, "
                f"preserve evidence from every step below, hunt for anything the "
                f"intruder touched since the first event, and rotate credentials "
                f"reachable from it.")
        else:
            title = f"🚨 FULL ATTACK CHAIN by {key}"
            english = (
                f"Connect the dots: the outside address {key} appears across "
                f"several events that together form one complete intrusion — "
                f"scouting first, then attacking, then a successful break-in. "
                f"Each event alone looked small and explainable; together, in "
                f"order, they are the story of a real intruder at work. This is "
                f"exactly how real intrusions hide: as a pile of 'minor' alerts "
                f"nobody connected.")
            blue = (
                "Treat as a confirmed incident, not noise: isolate the breached "
                "machines, preserve evidence from every step below, hunt for "
                "anything this intruder touched since the first event, and "
                "rotate credentials reachable from them.")
        return dict(
            title=title,
            raw=f"correlated timeline for {key}:\n{timeline}",
            english=english,
            category="campaign", severity="critical", src=key, dst="—",
            blue=blue,
            red=("Attackers split one break-in into small innocent-looking steps "
                 "on purpose. Correlation — asking 'same who, over time?' — is "
                 "what breaks that trick."),
            steps=steps)

    if victim:
        title = f"Escalation: {key} is under attack"
        english = (
            f"Pattern found: activity around your machine {key} has escalated — "
            f"first it was quietly scouted (recon), now it is under active "
            f"attack. That order is not an accident: the map of {key} is drawn, "
            f"and now the lock is being picked. The cheapest moment to stop this "
            f"chain is right now, before step three.")
        blue = (
            f"Protect {key} now: block the source IPs from the timeline below at "
            f"the firewall. Cleaning up after a break-in costs far more than "
            f"stopping one.")
    else:
        title = f"Escalating attacker: {key}"
        english = (
            f"Pattern found: the outside address {key} has escalated — the same "
            f"intruder first scouted your network (recon) and is now actively "
            f"attacking. That order is not an accident: the map is drawn, and "
            f"now the lock is being picked. Stop the chain here, before step "
            f"three.")
        blue = (
            f"Blocking {key} now is cheap; cleaning up after a breach is not. "
            f"Also ask what the recon phase already learned about you.")
    return dict(
        title=title,
        raw=f"correlated timeline for {key}:\n{timeline}",
        english=english,
        category="campaign", severity="high", src=key, dst="—",
        blue=blue,
        red=("Recon finds the door; attack picks the lock. Escalation means the "
             "targeting decision is already made."),
        steps=steps)


def _check(key, now):
    """Does this key qualify for a story? Marks it announced if so."""
    hist = _phases.get(key, [])
    cats = {h["cat"] for h in hist}
    level = 0
    if "recon" in cats and "attack" in cats:
        level = 1
    if level == 1 and "breach" in cats:
        level = 2
    if not level:
        return None
    last = _announced.get(key)
    if last and now - last["ts"] > REANNOUNCE:
        last = None                      # old story expired — a new one may be told
    if last and last["level"] >= level:
        return None                      # already told this (or a bigger) story
    _announced[key] = {"level": level, "ts": now}
    return _story(key, hist, level)


def observe(event, now=None):
    """Feed every alert here. Returns a campaign event when a story emerges.

    `now` is optional: replay tools analyzing old captures can pass the
    capture's own clock so time-window math stays correct.
    """
    if event.get("severity") == "info" or event.get("category") not in CHAIN:
        return None
    keys = {k for k in (event.get("src"), event.get("dst")) if k and k != "—"}
    if not keys:
        return None
    now = now or time.time()
    ts = event.get("ts") or now   # defensive: sensors don't stamp ts themselves
    with LOCK:
        for key in keys:
            hist = _phases.setdefault(key, [])
            hist.append(dict(ts=ts, cat=event["category"],
                             sev=event.get("severity", ""),
                             title=event.get("title", ""), id=event.get("id", 0)))
            hist[:] = [h for h in hist if now - h["ts"] <= WINDOW]
        story = None
        for key in sorted(keys):
            found = _check(key, now)
            if found and story is None:
                story = found
        return story

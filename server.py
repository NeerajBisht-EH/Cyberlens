#!/usr/bin/env python3
"""
CyberLens — a tiny "all-rounder" security console (proof of concept).

One idea, end to end:
    sensors  ->  one event format  ->  plain-English translation  ->  live dashboard
    (blue-team view: what to do   |   red-team view: why it works)

Events here are SIMULATED by plugins in ./plugins/ so the demo runs anywhere,
safely. Swap a plugin for a real sensor (a tshark / Suricata / Zeek parser)
and the rest of the pipeline doesn't change — that's the whole lesson.
See README.md.

v0.2: correlator.py connects events into attack stories (campaigns).

Stdlib only.   Run:  python3 server.py   ->  http://localhost:8000
"""
import importlib.util
import json
import os
import random
import threading
import time
import urllib.parse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import correlator  # v0.2: the brain that turns events into attack stories

ROOT = os.path.dirname(os.path.abspath(__file__))
EVENTS = deque(maxlen=400)
LOCK = threading.Lock()
_next_id = 1


# --------------------------------------------------------------- plugins ----
def load_plugins():
    """Every file in ./plugins/ is a swappable sensor. Drop a file in, restart."""
    plugins = []
    pdir = os.path.join(ROOT, "plugins")
    for fname in sorted(os.listdir(pdir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                fname[:-3], os.path.join(pdir, fname))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "generate") and hasattr(mod, "CAT"):
                plugins.append(mod)
                print(f"[+] sensor loaded: plugins/{fname}")
        except Exception as exc:
            print(f"[!] sensor {fname} failed to load: {exc}")
    return plugins


PLUGINS = load_plugins()


# --------------------------------------------------------- event pipeline ----
def emit_dict(event):
    """Put one event into the pipeline: stamp it, store it."""
    global _next_id
    event["id"] = _next_id
    event["ts"] = time.time()
    _next_id += 1
    with LOCK:
        EVENTS.append(event)


def emit(plugin):
    """Run a sensor, then ask the correlation engine if a story emerged."""
    event = plugin.generate()
    emit_dict(event)
    campaign = correlator.observe(event)
    if campaign:
        emit_dict(campaign)
        print(f"[*] correlation -> {campaign['title']}", flush=True)


# Attacks come in waves: the generator shifts "mood" over time so the dashboard
# shows calm periods, suspicious noise, and real storms — like a live network.
MOODS = {
    "calm":   {"normal": 6.0, "recon": 0.5, "attack": 0.30, "breach": 0.15},
    "uneasy": {"normal": 1.3, "recon": 1.5, "attack": 1.10, "breach": 0.80},
    "storm":  {"normal": 0.5, "recon": 2.2, "attack": 2.60, "breach": 2.20},
}


def generator_loop():
    mood, until = "uneasy", time.time() + random.uniform(25, 60)
    while True:
        now = time.time()
        if now > until:
            mood = random.choices(["calm", "uneasy", "storm"],
                                  weights=[0.35, 0.40, 0.25])[0]
            until = now + random.uniform(30, 80)
            print(f"[*] network mood -> {mood}", flush=True)
        mult = MOODS[mood]
        weights = [getattr(p, "WEIGHT", 10) * mult.get(p.CAT, 1.0) for p in PLUGINS]
        plugin = random.choices(PLUGINS, weights=weights, k=1)[0]
        try:
            emit(plugin)
        except Exception as exc:
            print(f"[!] generator error: {exc}", flush=True)
        time.sleep(random.uniform(1.2, 3.2))


def recent_events(after):
    with LOCK:
        evs = list(EVENTS)
    if after <= 0:
        evs = evs[-30:]          # first page: only the last 30 events
    return [e for e in evs if e["id"] > after]


def stats():
    with LOCK:
        evs = list(EVENTS)
    now = time.time()
    recent = [e for e in evs if now - e["ts"] <= 150]
    sev_w = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 30}
    score = min(100, int(sum(sev_w.get(e.get("severity"), 0) for e in recent)))
    level = ("LOW" if score < 8 else "GUARDED" if score < 25
             else "ELEVATED" if score < 55 else "HIGH")
    alerts = [e for e in recent if e.get("severity", "info") != "info"]
    top = {}
    for e in alerts:
        if e.get("src"):
            top[e["src"]] = top.get(e["src"], 0) + 1
    return {
        "total": len(evs),
        "alerts": len(alerts),
        "score": score,
        "level": level,
        "top_src": max(top, key=top.get) if top else "—",
        "plugins": len(PLUGINS),
        "campaigns": sum(1 for e in evs
                         if e.get("category") == "campaign"
                         and now - e["ts"] <= 600),
    }


# ------------------------------------------------------------------- http ----
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(ROOT, "index.html"), "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, {"error": "index.html missing"})
        elif path == "/api/events":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                after = int(q.get("after", ["0"])[0])
            except ValueError:
                after = 0
            self._send(200, {"events": recent_events(after)})
        elif path == "/api/stats":
            self._send(200, stats())
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):   # keep the console quiet
        pass


if __name__ == "__main__":
    if not PLUGINS:
        raise SystemExit("no sensors found in ./plugins/")
    for _ in range(12):            # pre-fill, so the first visitor sees history
        try:
            emit(random.choices(PLUGINS, weights=[p.WEIGHT for p in PLUGINS])[0])
        except Exception as exc:
            print("[!] prefill error:", exc, flush=True)
    threading.Thread(target=generator_loop, daemon=True).start()
    print("CyberLens v0.2 running on http://0.0.0.0:8000  (Ctrl+C to stop)",
          flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

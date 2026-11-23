#!/usr/bin/env python3
"""
CyberLens web console (v0.9) — point-and-click, like Wireshark, but it
tells the story in plain English.

Serves a single-page dashboard (dashboard.html) plus a small local API:

    GET  /                    the app
    GET  /api/status          engine, AI and environment info
    POST /api/analyze         body = a .pcap / eve.json / tshark .json file
    GET  /api/demo            analyze the bundled demo capture
    GET  /api/playbooks       the full playbook library
    GET  /api/ai              AI layer config (key only ever shown as hint)
    POST /api/ai              save AI config (url / key / model)
    POST /api/ai/test         test the configured endpoint end-to-end
    POST /api/ai/insight      ask the AI layer to comment on ONE event
    POST /api/sim/start|stop  live-fire TRAINING simulation (labeled, fake)
    GET  /api/sim/events      poll simulated events (dashboard live mode)

Pure Python stdlib. The deterministic engine (replay.py + correlator.py)
stays the brain and the source of truth; the AI layer stays optional and
additive — exactly like the CLI.

Run:   python3 webui.py            ->  http://127.0.0.1:8787
       python3 webui.py --host 0.0.0.0 --port 9000 --no-browser
"""
import argparse
import importlib.util
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ai_narrator
import correlator
import live_capture
import playbooks
import report
import replay
import suricata_adapter
import tshark_adapter

ROOT = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.1.0"
UI_FILE = os.path.join(ROOT, "dashboard.html")
DEMO_PCAP = os.path.join(ROOT, "captures", "demo.pcap")
CONF_DIR = os.path.join(os.path.expanduser("~"), ".config", "cyberlens")
CONF_FILE = os.path.join(CONF_DIR, "ai_config.json")
MAX_UPLOAD = 200 * 1024 * 1024
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1",
               b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
TEST_EVENT = {
    "title": "AI connection test (not a real alert)",
    "category": "recon", "severity": "medium", "src": "203.0.113.7",
    "raw": "IP 203.0.113.7 > 10.0.0.5.8080: Flags [S]",
    "english": "This is a test event used only to check that the AI endpoint "
               "answers. Nothing happened on your network.",
    "blue": "Nothing to do — this is a connectivity test.",
}

AI_LOCK = threading.Lock()
LIVE = {"session": None}      # at most one live capture at a time


# ------------------------------------------------------------ the engine ----
def sniff(data, name):
    """What kind of capture is this? Returns (kind, error_message)."""
    if data[:4] in PCAP_MAGICS:
        return "pcap", None
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return None, ("This is a pcapNG file. Convert it once with: "
                      "tshark -F pcap -r in.pcapng -w out.pcap "
                      "(then drop out.pcap here).")
    if data.lstrip()[:1] in (b"{", b"["):
        txt = data.decode("utf-8", "replace").lstrip()
        # Suricata eve.json: one JSON object per line ({"event_type": ...})
        try:
            obj = json.loads(txt.splitlines()[0])
            if isinstance(obj, dict) and ("event_type" in obj or "alert" in obj):
                return "eve", None
        except (json.JSONDecodeError, IndexError):
            pass
        # tshark exports, three shapes:
        #   1) {"packets": [...]}                     (tshark -T json, some versions)
        #   2) [ {"_index":..., "_source": {...}} ]   (tshark -T json, elastic-style)
        #   3) one {"_index":...} object per line     (tshark -T ek)
        try:
            whole = json.loads(txt)
            if isinstance(whole, dict) and "packets" in whole:
                return "tshark", None
            if (isinstance(whole, list) and whole and isinstance(whole[0], dict)
                    and ("_index" in whole[0] or "_source" in whole[0])):
                return "tshark", None
        except json.JSONDecodeError:
            pass
        head = txt[:2000]
        if '"_source"' in head or '"layers"' in head or '"packets"' in head:
            return "tshark", None
        if '"event_type"' in head or '"alert"' in head:
            return "eve", None
        return None, ("JSON, but not a tshark -T json export or a Suricata "
                      "eve.json — those are the two JSON formats I read.")
    return None, ("Unrecognised file. I read: classic .pcap (tcpdump/"
                  "Wireshark), Suricata eve.json, and tshark -T json exports.")


def analyze(data, name):
    """Bytes of a capture -> the full narrated analysis (the CLI's brain)."""
    kind, err = sniff(data, name)
    if err:
        raise ValueError(err)
    t0 = time.perf_counter()
    # adapters dispatch by file extension — keep the temp suffix honest
    suffix = ".json" if kind in ("tshark", "eve") else ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as fh:
        fh.write(data)
        tmp = fh.name
    try:
        if kind == "pcap":
            records, total = replay.read_records(tmp)
            events, meta = replay.build_events(records, total)
            end_ts = max((r[0] for r in records), default=time.time())
        elif kind == "tshark":
            records, _source, total = tshark_adapter.load_records(tmp)
            events, meta = replay.build_events(records, total)
            end_ts = max((r[0] for r in records), default=time.time())
        else:                                    # Suricata eve.json
            with open(tmp, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            events, alerts_in = suricata_adapter.build_events(lines)
            end_ts = max((e["ts"] for e in events), default=time.time())
            meta = {"packets": alerts_in, "tcp": 0, "udp": 0, "other": 0,
                    "duration": 0.0, "suricata_alerts": alerts_in}

        correlator.reset()                       # fresh brain per file (v0.9)
        all_events, stories = [], []
        for ev in events:
            all_events.append(ev)
            st = correlator.observe(ev, now=end_ts + 1)
            if st:
                st["ts"] = ev["ts"]
                all_events.append(st)
                stories.append(st)
        score = min(100, sum(replay.SEV_W.get(e.get("severity"), 0)
                             for e in all_events))
        verdict = ("CLEAN" if score < 10 else "SUSPICIOUS" if score < 40
                   else "COMPROMISED")
        return {"file": {"name": name, "size": len(data), "kind": kind},
                **meta, "score": score, "verdict": verdict,
                "events": all_events, "stories": stories,
                "playbooks": playbooks.for_analysis(all_events),
                "took_ms": int((time.perf_counter() - t0) * 1000)}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ------------------------------------------------------------ AI layer ------
def read_conf():
    try:
        with open(CONF_FILE, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def write_conf(cfg):
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(CONF_FILE, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)


def ai_state():
    cfg = read_conf()
    key = cfg.get("key", "")
    return {"url": cfg.get("url", ""), "model": cfg.get("model", ""),
            "key_set": bool(key),
            "key_hint": ("…" + key[-4:]) if key else ""}


def ai_call(event):
    """One enrichment call through the saved config. Returns (ok, text)."""
    cfg = read_conf()
    if not cfg.get("url"):
        return False, ("No endpoint configured yet. Add a URL (and key) in "
                       "the AI Setup tab — or just keep using the built-in "
                       "engine: it needs nothing and works offline.")
    with AI_LOCK:                                # env is process-global
        os.environ["CYBERLENS_AI_URL"] = cfg.get("url", "")
        os.environ["CYBERLENS_AI_KEY"] = cfg.get("key", "")
        os.environ["CYBERLENS_AI_MODEL"] = cfg.get(
            "model", "llama-3.3-70b-versatile")
        ai_narrator.activate()
        note = ai_narrator.enrich(event)
    if note:
        return True, note
    return False, ("The endpoint did not answer in time. It may be offline, "
                   "the URL may be wrong, or the key may be invalid. The "
                   "built-in engine is unaffected.")


# ------------------------------------------------- training simulation ------
def load_plugins():
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
        except Exception:
            pass
    return plugins


PLUGINS = load_plugins()
SIM = {"running": False, "events": deque(maxlen=500), "next_id": 1,
       "lock": threading.Lock()}
SIM_MOODS = {                       # calm periods, then storms — like life
    "calm":   {"normal": 6.0, "recon": 0.5, "attack": 0.30, "breach": 0.15},
    "uneasy": {"normal": 1.3, "recon": 1.5, "attack": 1.10, "breach": 0.80},
    "storm":  {"normal": 0.5, "recon": 2.2, "attack": 2.60, "breach": 2.20},
}


def sim_emit():
    plugin = random.choices(
        PLUGINS, weights=[getattr(p, "WEIGHT", 10) * SIM_MOODS[SIM["mood"]]
                           .get(p.CAT, 1.0) for p in PLUGINS])[0]
    event = plugin.generate()
    with SIM["lock"]:
        event["id"] = SIM["next_id"]
        SIM["next_id"] += 1
        event["ts"] = time.time()
        SIM["events"].append(event)
    story = correlator.observe(event)
    if story:
        with SIM["lock"]:
            story["id"] = SIM["next_id"]
            SIM["next_id"] += 1
            story["ts"] = time.time()
            SIM["events"].append(story)


def sim_loop():
    SIM["mood"], until = "uneasy", time.time() + random.uniform(20, 40)
    while SIM["running"]:
        now = time.time()
        if now > until:
            SIM["mood"] = random.choices(["calm", "uneasy", "storm"],
                                         weights=[0.35, 0.40, 0.25])[0]
            until = now + random.uniform(30, 60)
        try:
            sim_emit()
        except Exception:
            pass
        time.sleep(random.uniform(1.2, 2.6))


def sim_stats():
    with SIM["lock"]:
        evs = list(SIM["events"])
    now = time.time()
    recent = [e for e in evs if now - e["ts"] <= 150]
    sev_w = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 30}
    score = min(100, int(sum(sev_w.get(e.get("severity"), 0)
                             for e in recent)))
    level = ("LOW" if score < 8 else "GUARDED" if score < 25
             else "ELEVATED" if score < 55 else "HIGH")
    return {"running": SIM["running"], "total": len(evs), "score": score,
            "level": level,
            "alerts": sum(1 for e in recent
                          if e.get("severity", "info") != "info")}


# ------------------------------------------------------------------ http ----
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

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            raise ValueError("File too big (limit 200 MB).")
        return self.rfile.read(n)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html", "/dashboard.html"):
            try:
                with open(UI_FILE, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(404, {"error": "dashboard.html missing"})
        elif path == "/api/status":
            self._send(200, {
                "version": VERSION, "app": "CyberLens",
                "engine": "deterministic rules + attack-story correlator",
                "python": sys.version.split()[0],
                "tshark": bool(shutil.which("tshark")),
                "plugins": len(PLUGINS),
                "playbooks": len(playbooks.PLAYBOOKS),
                "ai": ai_state()})
        elif path == "/api/playbooks":
            self._send(200, {"library": [{"id": k, **v} for k, v in
                                         playbooks.PLAYBOOKS.items()]})
        elif path == "/api/ai":
            self._send(200, ai_state())
        elif path == "/api/demo":
            try:
                with open(DEMO_PCAP, "rb") as fh:
                    self._send(200, analyze(fh.read(), "demo.pcap"))
            except OSError:
                self._send(404, {"error": "bundled demo capture missing"})
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
        elif path == "/api/sim/events":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                after = int(q.get("after", ["0"])[0])
            except ValueError:
                after = 0
            with SIM["lock"]:
                evs = list(SIM["events"])
            if after <= 0:
                evs = evs[-30:]
            self._send(200, {"events": [e for e in evs if e["id"] > after],
                             "running": SIM["running"]})
        elif path == "/api/sim/stats":
            self._send(200, sim_stats())
        elif path == "/api/live/interfaces":
            can = (os.geteuid() == 0 or bool(shutil.which("tshark"))
                   or live_capture.sudo_ok())
            self._send(200, {"interfaces": live_capture.list_interfaces(),
                             "can_capture": can,
                             "root": os.geteuid() == 0,
                             "tshark": bool(shutil.which("tshark"))})
        elif path == "/api/live/status":
            if LIVE["session"]:
                self._send(200, LIVE["session"].status())
            else:
                self._send(200, {"running": False})
        elif path == "/api/live/events":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                after = int(q.get("after", ["-1"])[0])
            except ValueError:
                after = -1
            if not LIVE["session"]:
                self._send(200, {"events": [], "running": False})
            else:
                allv = LIVE["session"].engine.all_events()
                out = [dict(e, id=i) for i, e in enumerate(allv) if i > after]
                if after < 0:
                    out = out[-30:]
                self._send(200, {"events": out,
                                 "running": LIVE["session"].running})
        elif path == "/api/live/analysis":
            if LIVE["session"]:
                self._send(200, LIVE["session"].engine.analysis())
            else:
                self._send(404, {"error": "no live session"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/api/analyze":
                data = self._body()
                name = self.headers.get("X-Filename") or "capture"
                self._send(200, analyze(data, name))
            elif path == "/api/ai":
                cfg = json.loads(self._body().decode("utf-8", "replace"))
                saved = read_conf()
                saved["url"] = str(cfg.get("url", "")).strip()
                saved["model"] = str(cfg.get("model", "")).strip() or \
                    "llama-3.3-70b-versatile"
                if str(cfg.get("key", "")).strip():      # empty = keep old
                    saved["key"] = str(cfg["key"]).strip()
                write_conf(saved)
                self._send(200, ai_state())
            elif path == "/api/ai/test":
                ok, text = ai_call(TEST_EVENT)
                self._send(200, {"ok": ok, "text": text})
            elif path == "/api/ai/insight":
                req = json.loads(self._body().decode("utf-8", "replace"))
                ok, text = ai_call(req.get("event", TEST_EVENT))
                self._send(200, {"ok": ok, "text": text})
            elif path == "/api/sim/start":
                if not PLUGINS:
                    self._send(400, {"error": "no sensor plugins found"})
                elif LIVE["session"] and LIVE["session"].running:
                    self._send(400, {"error": "a live capture is running — "
                                             "stop it first"})
                elif SIM["running"]:
                    self._send(200, {"ok": True, "note": "already running"})
                else:
                    correlator.reset()
                    SIM["running"] = True
                    threading.Thread(target=sim_loop, daemon=True).start()
                    self._send(200, {"ok": True})
            elif path == "/api/sim/stop":
                SIM["running"] = False
                self._send(200, {"ok": True})
            elif path == "/api/live/start":
                if SIM["running"]:
                    self._send(400, {"error": "the simulation is running — "
                                             "stop it first"})
                    return
                if LIVE["session"] and LIVE["session"].running:
                    self._send(200, {"ok": True, "note": "already running"})
                    return
                req = json.loads(self._body().decode("utf-8", "replace"))
                iface = str(req.get("iface", "")).strip() or "lo"
                names = [i["name"] for i in live_capture.list_interfaces()]
                if names and iface not in names:
                    self._send(400, {"error": f"unknown interface: {iface}"})
                    return
                try:
                    correlator.reset()
                    sess = live_capture.CaptureSession(iface)
                    sess.start()
                    LIVE["session"] = sess
                    self._send(200, {"ok": True, "transport": sess.transport})
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
            elif path == "/api/live/stop":
                if LIVE["session"]:
                    LIVE["session"].stop()
                    self._send(200, {"ok": True,
                                     "packets": len(
                                         LIVE["session"].engine.records)})
                else:
                    self._send(200, {"ok": True})
            elif path == "/api/report":
                req = json.loads(self._body().decode("utf-8", "replace"))
                data = report.render(req).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Disposition", "attachment; "
                                 'filename="cyberlens-report.html"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send(404, {"error": "not found"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except (Exception, SystemExit) as exc:       # never crash the server
            self._send(500, {"error": f"internal error: {exc}"})

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="CyberLens web console")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1 — this machine only; "
                         "use 0.0.0.0 to share on your LAN)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-browser", action="store_true",
                    help="do not try to open a browser tab")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    url = f"http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}"
    print(f"CyberLens v{VERSION} — web console on {url}   (Ctrl+C to stop)")
    print("  drop a .pcap on the page, or press 'live simulation' to train")
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye — stay curious, stay defensive.")
    finally:
        if LIVE["session"]:
            LIVE["session"].stop()
        srv.server_close()


if __name__ == "__main__":
    main()

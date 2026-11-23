#!/usr/bin/env python3
"""
The build loop's safety net. Run this after EVERY change:

    python3 tests.py

Exit code 0 = all green = safe to build the next feature.
Any red = fix it before anything else. That discipline — build, test,
improve, repeat — is what actually makes a tool world class.
"""
import importlib.util
import os
import random
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ("title", "raw", "english", "category", "severity",
            "src", "dst", "blue", "red")
VALID_CAT = {"normal", "recon", "attack", "breach"}
VALID_SEV = {"info", "low", "medium", "high", "critical"}

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


print("== 1. sensor plugins ==")
pdir = os.path.join(ROOT, "plugins")
plugins = [f for f in sorted(os.listdir(pdir))
           if f.endswith(".py") and not f.startswith("_")]
check("at least one sensor discovered", len(plugins) > 0, "plugins/ empty?")

for fname in plugins:
    try:
        mod = load(os.path.join(pdir, fname), fname[:-3])
        check(f"{fname}: declares WEIGHT + CAT",
              hasattr(mod, "WEIGHT") and hasattr(mod, "CAT"))
        ok, detail = True, ""
        for _ in range(50):
            ev = mod.generate()
            for field in REQUIRED:
                if not isinstance(ev.get(field), str) or not ev.get(field):
                    ok, detail = False, f"bad/missing field: {field}"
                    break
            if not ok:
                break
            if ev.get("category") not in VALID_CAT:
                ok, detail = False, f"bad category: {ev.get('category')}"
                break
            if ev.get("severity") not in VALID_SEV:
                ok, detail = False, f"bad severity: {ev.get('severity')}"
                break
            if len(ev.get("english", "")) < 40:
                ok, detail = False, "english explanation too short"
                break
        check(f"{fname}: 50 generations, all fields valid", ok, detail)
    except Exception:
        check(fname, False, "raised: " + traceback.format_exc(limit=1))

print("== 2. correlation engine ==")
corr = load(os.path.join(ROOT, "correlator.py"), "correlator_under_test")


def fake(cat, sev, src, dst, counter=[0]):
    counter[0] += 1
    return dict(category=cat, severity=sev, src=src, dst=dst, ts=time.time(),
                title=f"{cat} test event", id=counter[0])


atk, victim = "203.0.113.99", "10.0.0.99"
check("single recon event -> no story yet",
      corr.observe(fake("recon", "medium", atk, victim)) is None)
s1 = corr.observe(fake("attack", "high", atk, victim))
check("recon + attack -> escalation story",
      s1 is not None and s1["severity"] == "high"
      and s1["category"] == "campaign")
check("story carries a linked timeline",
      s1 is not None and len(s1.get("steps", [])) >= 2)
check("repeat attack -> no duplicate story",
      corr.observe(fake("attack", "high", atk, victim)) is None)
s2 = corr.observe(fake("breach", "critical", atk, victim))
check("breach completes the chain -> full story",
      s2 is not None and s2["severity"] == "critical")
check("normal events never trigger stories",
      corr.observe(fake("normal", "info", "192.168.1.50", "example.com")) is None)
check("isolated attacker with one event -> no story",
      corr.observe(fake("attack", "high", "198.51.100.77", "10.0.0.4")) is None)

print("== 3. pipeline smoke test (all sensors, 200 random events) ==")
random.seed(42)
mods = [load(os.path.join(pdir, f), "smoke_" + f[:-3]) for f in plugins]
errors = 0
for i in range(200):
    try:
        ev = random.choice(mods).generate()
        ev["id"] = i            # stamp it like the real pipeline does
        ev["ts"] = time.time()
        corr.observe(ev)
    except Exception:
        errors += 1
check("200 random generations survive the pipeline", errors == 0,
      f"{errors} errors")

print("== 4. pcap replay (real-file pipeline) ==")
import subprocess
import tempfile
import json as _json

tmpd = tempfile.mkdtemp()
cap = os.path.join(tmpd, "test.pcap")
r = subprocess.run([sys.executable, os.path.join(ROOT, "make_demo_pcap.py"), cap],
                   capture_output=True, text=True)
check("demo pcap builder runs",
      r.returncode == 0 and os.path.getsize(cap) > 0, r.stderr[-200:])
r2 = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"), cap, "--json"],
                    capture_output=True, text=True)
if r2.returncode == 0:
    out = _json.loads(r2.stdout)
    cats = [e["category"] for e in out["events"]]
    check(f"narrator parsed {out['packets']} real packets", out["packets"] >= 60)
    check("port scan detected in real capture", "recon" in cats)
    check("brute-force detected in real capture", "attack" in cats)
    check("data-theft pattern detected in real capture", "breach" in cats)
    check("attack story correlated from real capture", "campaign" in cats)
    check("verdict computed", out["verdict"] in ("CLEAN", "SUSPICIOUS", "COMPROMISED"))
else:
    for name in ("narrator parsed packets", "port scan detected",
                 "brute-force detected", "data-theft pattern detected",
                 "attack story correlated", "verdict computed"):
        check(name, False, "replay failed: " + r2.stderr[-200:])

print("== 5. Suricata adapter (wrap, don't rewrite) ==")
sample = os.path.join(ROOT, "captures", "eve-sample.json")
check("sample eve.json exists", os.path.exists(sample))
r = subprocess.run([sys.executable, os.path.join(ROOT, "suricata_adapter.py"),
                    "--json", sample], capture_output=True, text=True)
if r.returncode == 0:
    out = _json.loads(r.stdout)
    cats = [e["category"] for e in out["events"]]
    check(f"ingested {out['suricata_alerts']} Suricata alerts",
          out["suricata_alerts"] >= 10)
    check("alerts aggregated (noise reduced)",
          out["narrated_events"] < out["suricata_alerts"])
    check("recon/attack/breach families all recognised",
          {"recon", "attack", "breach"} <= set(cats))
    check("attack story correlated from Suricata alerts", "campaign" in cats)
    check("verdict computed",
          out["verdict"] in ("CLEAN", "SUSPICIOUS", "COMPROMISED"))
else:
    for name in ("ingested alerts", "aggregation", "families recognised",
                 "story correlated", "verdict"):
        check(name, False, "adapter failed: " + r.stderr[-200:])

print("== 6. tshark adapter (protocol wrap, v0.5) ==")
import shutil as _shutil

tsample = os.path.join(ROOT, "captures", "tshark-sample.json")
check("sample tshark export exists", os.path.exists(tsample))
r = subprocess.run([sys.executable, os.path.join(ROOT, "tshark_adapter.py"),
                    "--json", tsample], capture_output=True, text=True)
if r.returncode == 0:
    out = _json.loads(r.stdout)
    cats = [e["category"] for e in out["events"]]
    check(f"translated {out['packets']} tshark-decoded packets",
          out["packets"] >= 20)
    check("port scan detected through tshark layers", "recon" in cats)
    check("brute force detected through tshark layers", "attack" in cats)
    check("dns tunnelling detected through tshark layers", "breach" in cats)
    check("attack story correlated through tshark layers", "campaign" in cats)
    check("verdict computed",
          out["verdict"] in ("CLEAN", "SUSPICIOUS", "COMPROMISED"))
else:
    for name in ("translated packets", "port scan", "brute force",
                 "dns tunnelling", "attack story", "verdict"):
        check(name, False, "adapter failed: " + r.stderr[-200:])

if _shutil.which("tshark"):
    rl = subprocess.run([sys.executable, os.path.join(ROOT, "tshark_adapter.py"),
                         "--json", os.path.join(ROOT, "captures", "demo.pcap")],
                        capture_output=True, text=True)
    ok = rl.returncode == 0 and "campaign" in rl.stdout
    check("LIVE wrap: real tshark run on demo.pcap + story correlated", ok,
          rl.stderr[-200:] if rl.returncode else "no campaign in output")
else:
    print("  SKIP  live tshark not installed here — sample path proves the logic")

print("== 7. AI companion layer (optional, additive — v0.6) ==")
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 7a. default: OFF — output identical to v0.5, no AI section anywhere
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap")],
                   capture_output=True, text=True)
check("without --ai: no AI section (built-in engine only)",
      r.returncode == 0 and "🤖" not in r.stdout)

# 7b. mock provider: the full HTTP path, end-to-end, no external API needed
class _MockAI(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = _json.dumps({"choices": [{"message": {"content":
            "Mock insight: a scan like this is the first domino — what matters "
            "is which door stayed open for the next event."}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockAI)
threading.Thread(target=srv.serve_forever, daemon=True).start()
env_ai = dict(os.environ,
              CYBERLENS_AI_URL=(f"http://127.0.0.1:{srv.server_address[1]}"
                                "/v1/chat/completions"),
              CYBERLENS_AI_KEY="test-key", CYBERLENS_AI_MODEL="mock-model")
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap"), "--ai"],
                   capture_output=True, text=True, env=env_ai)
check("with --ai + configured endpoint: AI section appears",
      r.returncode == 0 and "Mock insight" in r.stdout)
check("AI adds, never replaces (built-in text still present)",
      "knocking on every door" in r.stdout)
srv.shutdown()

# 7c. unreachable endpoint -> fail-safe: the tool completes on built-in alone
env_bad = dict(os.environ,
               CYBERLENS_AI_URL="http://127.0.0.1:9/v1/chat/completions",
               CYBERLENS_AI_KEY="x")
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap"), "--ai"],
                   capture_output=True, text=True, env=env_bad)
check("AI unreachable -> tool still completes, built-in only",
      r.returncode == 0 and "Mock insight" not in r.stdout
      and "knocking on every door" in r.stdout)

# 7d. unit checks on the module itself
ai_mod = load(os.path.join(ROOT, "ai_narrator.py"), "ai_under_test")
ai_mod.deactivate()
check("enrich() is fail-safe (returns None when the layer is off)",
      ai_mod.enrich({"title": "t", "raw": "r", "english": "e"}) is None)
ai_mod.CONFIG_FILE = os.path.join(tmpd, "no-such-config.json")
os.environ.pop("CYBERLENS_AI_URL", None)
check("unconfigured -> activate() reports unavailable", not ai_mod.activate())

print("== 8. response playbooks (v0.7) ==")
pb_mod = load(os.path.join(ROOT, "playbooks.py"), "playbooks_under_test")

r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap")],
                   capture_output=True, text=True)
check("default run shows the playbook section",
      r.returncode == 0 and "response playbooks" in r.stdout
      and "Port scan response" in r.stdout)
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap"),
                    "--no-playbooks"], capture_output=True, text=True)
check("--no-playbooks hides the section",
      r.returncode == 0 and "response playbooks" not in r.stdout)
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap"), "--json"],
                   capture_output=True, text=True)
out = _json.loads(r.stdout) if r.returncode == 0 else {}
pbl = out.get("playbooks", [])
check("JSON carries the playbooks (incl. the campaign one)",
      len(pbl) >= 4 and any("attack-chain" in p["name"] for p in pbl))
check("every playbook is complete (name, trigger, 4+ steps, watch-out)",
      all(p.get("name") and p.get("trigger") and p.get("watch")
          and len(p.get("steps", [])) >= 4 for p in pbl))
check("TITLE_MAP ids all exist in the library",
      all(pid in pb_mod.PLAYBOOKS for _, pid in pb_mod.TITLE_MAP))
_allsteps = " ".join(s.lower() for p in pb_mod.PLAYBOOKS.values()
                     for s in p["steps"])
check("playbooks stay defensive (no attack-tool instructions)",
      not any(w in _allsteps for w in ("nmap", "sqlmap", "hydra ",
                                       "metasploit", "exploit-db")))
r = subprocess.run([sys.executable, os.path.join(ROOT, "suricata_adapter.py"),
                    sample], capture_output=True, text=True)
check("suricata adapter shows playbooks too",
      r.returncode == 0 and "response playbooks" in r.stdout)
r = subprocess.run([sys.executable, os.path.join(ROOT, "tshark_adapter.py"),
                    tsample, "--no-playbooks"], capture_output=True, text=True)
check("tshark adapter honours --no-playbooks",
      r.returncode == 0 and "response playbooks" not in r.stdout)

print("== 9. scale test (v0.8 — thousands of packets) ==")
big1 = os.path.join(tmpd, "big1.pcap")
big2 = os.path.join(tmpd, "big2.pcap")
r = subprocess.run([sys.executable, os.path.join(ROOT, "make_big_pcap.py"),
                    "--packets", "3000", "--out", big1],
                   capture_output=True, text=True)
check("big-capture builder runs (3000 packets)",
      r.returncode == 0 and os.path.getsize(big1) > 0, r.stderr[-200:])
subprocess.run([sys.executable, os.path.join(ROOT, "make_big_pcap.py"),
                "--packets", "3000", "--out", big2], capture_output=True)
check("generator is deterministic (same bytes every run)",
      open(big1, "rb").read() == open(big2, "rb").read())
t0 = time.time()
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    big1, "--json"], capture_output=True, text=True)
elapsed = time.time() - t0
out = _json.loads(r.stdout) if r.returncode == 0 else {}
cats = [e["category"] for e in out.get("events", [])]
check(f"3000 packets parsed exactly (took {elapsed:.2f}s)",
      out.get("packets") == 3000, f"got {out.get('packets')}")
check("attack chain survives at scale (recon+attack+breach+story)",
      {"recon", "attack", "breach", "campaign"} <= set(cats))
check("verdict at scale", out.get("verdict") == "COMPROMISED")
check(f"speed: at least 1000 pkt/s (actual {3000/max(elapsed,0.001):,.0f}/s)",
      elapsed < 30 and 3000 / max(elapsed, 0.001) > 1000)

print("== 10. web console (v0.9 — real HTTP, in-process) ==")
import urllib.request as _ureq
import urllib.error as _uerr

webui_mod = load(os.path.join(ROOT, "webui.py"), "webui_under_test")
webui_mod.CONF_DIR = tmpd                       # never touch the real config
webui_mod.CONF_FILE = os.path.join(tmpd, "ai_config.json")

srv_ui = ThreadingHTTPServer(("127.0.0.1", 0), webui_mod.Handler)
threading.Thread(target=srv_ui.serve_forever, daemon=True).start()
UI = f"http://127.0.0.1:{srv_ui.server_address[1]}"


def _get(p):
    return _json.loads(_ureq.urlopen(UI + p, timeout=10).read())


def _post(p, data, hdrs=None):
    req = _ureq.Request(UI + p, data=data, headers=hdrs or {})
    try:
        return _json.loads(_ureq.urlopen(req, timeout=15).read())
    except _uerr.HTTPError as e:
        return {"_http": e.code, **_json.loads(e.read())}


st = _get("/api/status")
check("status endpoint: version, engine, 6 playbooks",
      st.get("version", "").startswith("1.")
      and st.get("playbooks") == 6)
page = _ureq.urlopen(UI + "/", timeout=10).read().decode()
check("dashboard page served (with embedded demo analysis)",
      "CyberLens" in page and "COMPROMISED" in page)
check("playbook library endpoint", len(_get("/api/playbooks")["library"]) == 6)
r = _post("/api/analyze", open(os.path.join(ROOT, "captures", "demo.pcap"),
                               "rb").read(), {"X-Filename": "demo.pcap"})
check("upload .pcap -> full analysis over HTTP",
      r.get("verdict") == "COMPROMISED" and r.get("packets") == 76
      and len(r.get("playbooks", [])) >= 4)
r = _post("/api/analyze", open(os.path.join(ROOT, "captures",
                                            "eve-sample.json"), "rb").read(),
          {"X-Filename": "eve.json"})
check("upload eve.json -> analysis",
      r.get("file", {}).get("kind") == "eve"
      and r.get("verdict") == "COMPROMISED")
r = _post("/api/analyze", open(os.path.join(ROOT, "captures",
                                            "tshark-sample.json"), "rb").read(),
          {"X-Filename": "t.json"})
check("upload tshark json -> analysis",
      r.get("file", {}).get("kind") == "tshark"
      and len(r.get("stories", [])) == 2)
r = _post("/api/analyze", b"\x0a\x0d\x0d\x0a" + b"x" * 50,
          {"X-Filename": "a.pcapng"})
check("pcapng politely rejected, with conversion hint",
      r.get("_http") == 400 and "tshark" in r.get("error", ""))
r = _post("/api/analyze", b"just some bytes", {"X-Filename": "x"})
check("garbage input rejected with a friendly error", r.get("_http") == 400)

srv_mock = ThreadingHTTPServer(("127.0.0.1", 0), _MockAI)
threading.Thread(target=srv_mock.serve_forever, daemon=True).start()
r = _post("/api/ai", _json.dumps({
    "url": f"http://127.0.0.1:{srv_mock.server_address[1]}/v1/chat/completions",
    "key": "test-key", "model": "mock-model"}).encode(),
    {"Content-Type": "application/json"})
check("AI config saved through the API (key only shown as hint)",
      r.get("key_set") and "test-key" not in _json.dumps(r)
      and r.get("key_hint", "") != "")
ev0 = _post("/api/analyze", open(os.path.join(ROOT, "captures", "demo.pcap"),
                                 "rb").read(), {"X-Filename": "demo.pcap"})
r = _post("/api/ai/insight", _json.dumps({"event": ev0["events"][0]}).encode(),
          {"Content-Type": "application/json"})
check("per-event AI insight works through the web API (mock provider)",
      r.get("ok") and "Mock insight" in r.get("text", ""))
for var in ("CYBERLENS_AI_URL", "CYBERLENS_AI_KEY", "CYBERLENS_AI_MODEL"):
    os.environ.pop(var, None)                    # keep the test env clean

_post("/api/sim/start", b"{}")
time.sleep(3.5)
evs = _get("/api/sim/events?after=0")
check("live simulation streams events (labeled training mode)",
      evs.get("running") and len(evs.get("events", [])) >= 1)
_post("/api/sim/stop", b"{}")
r = _post("/api/analyze", open(os.path.join(ROOT, "captures", "demo.pcap"),
                               "rb").read(), {"X-Filename": "demo.pcap"})
check("analysis after simulation is untouched (correlator reset)",
      r.get("packets") == 76 and len(r.get("stories", [])) == 2)
check("live API lists interfaces", len(_get("/api/live/interfaces")["interfaces"]) >= 1)
check("live API initially idle", not _get("/api/live/status")["running"])
check("live API rejects unknown interface", "error" in _post("/api/live/start", b'{"iface":"nonexistent-cyberlens"}'))
check("idle live event poll is empty", _get("/api/live/events")["events"] == [])
check("idle capture stop succeeds", _post("/api/live/stop", b"{}")["ok"])
_report_req = _ureq.Request(UI + "/api/report", data=_json.dumps(r).encode(), headers={"Content-Type":"application/json"})
with _ureq.urlopen(_report_req) as _resp:
    _html=_resp.read().decode()
    check("report API returns downloadable HTML", "attachment" in _resp.headers.get("Content-Disposition", "") and "COMPROMISED" in _html)
srv_ui.shutdown()
srv_mock.shutdown()

print("== 11. .deb package (v0.9 — installable like a real Kali app) ==")
if _shutil.which("dpkg-deb"):
    debdir = os.path.join(tmpd, "deb")
    r = subprocess.run(["bash", os.path.join(ROOT, "packaging", "build_deb.sh"),
                        debdir], capture_output=True, text=True)
    debs = [f for f in os.listdir(debdir) if f.endswith(".deb")] \
        if r.returncode == 0 and os.path.isdir(debdir) else []
    check("build_deb.sh produces a .deb", bool(debs), r.stderr[-200:])
    if debs:
        deb = os.path.join(debdir, debs[0])
        info = subprocess.run(["dpkg-deb", "-I", deb],
                              capture_output=True, text=True).stdout
        check("control metadata is correct",
              "Package: cyberlens" in info and "Depends: python3" in info
              and "Architecture: all" in info)
        listing = subprocess.run(["dpkg-deb", "-c", deb],
                                 capture_output=True, text=True).stdout
        needed = ("/usr/bin/cyberlens", "/usr/bin/cyberlens-web",
                  "/usr/share/applications/cyberlens.desktop",
                  "/usr/share/icons/hicolor/scalable/apps/cyberlens.svg",
                  "usr/share/cyberlens/replay.py",
                  "usr/share/cyberlens/webui.py",
                  "usr/share/cyberlens/playbooks.py",
                  "usr/share/cyberlens/dashboard.html",
                  "usr/share/cyberlens/captures/demo.pcap",
                  "usr/share/doc/cyberlens/copyright")
        check("package contains app + menu entry + icon + docs",
              all(n.lstrip("/") in listing.replace("./", "") or
                  n in listing for n in needed))
        xdir = os.path.join(tmpd, "extracted")
        subprocess.run(["dpkg-deb", "-x", deb, xdir], check=True)
        r = subprocess.run([sys.executable,
                            os.path.join(xdir, "usr/share/cyberlens/replay.py"),
                            os.path.join(xdir, "usr/share/cyberlens/captures/demo.pcap"),
                            "--json"], capture_output=True, text=True)
        ok = r.returncode == 0 and "COMPROMISED" in r.stdout
        check("the packaged code RUNS straight out of the .deb", ok,
              r.stderr[-200:])
else:
    print("  SKIP  dpkg-deb not available here — build script still shipped")

print("== 12. live capture + report export (v1.0) ==")
live_mod = load(os.path.join(ROOT, "live_capture.py"), "live_under_test")
rep_mod = load(os.path.join(ROOT, "report.py"), "report_under_test")

check("network interfaces listed", len(live_mod.list_interfaces()) >= 1)
mdemo = load(os.path.join(ROOT, "make_demo_pcap.py"), "mdemo_for_live")
frame = mdemo.eth(mdemo.ATK, mdemo.SRV, mdemo.ip4(
    mdemo.ATK, mdemo.SRV, 6, mdemo.tcp(mdemo.ATK, mdemo.SRV, 40000, 3389,
                                       2000, 0, 0x02)))
rec = live_mod.frame_to_record(frame, 1792941303.0)
check("raw frame -> record (same shape as the file parser)",
      rec is not None and rec[1] == "tcp" and rec[3] == "10.0.0.5"
      and rec[5] == 3389)

eng = live_mod.LiveEngine("test")
base = 1792941300.0
eng.add_records([(base + i * 0.1, "tcp", "203.0.113.5", "10.0.0.9",
                  40000 + i, 1000 + i, 0x02, "", None) for i in range(12)])
new = eng.tick(now=base + 3)
check("live engine detects a scan from raw records",
      any("Port scan" in e["title"] for e in new))
check("stable-key diff: re-tick creates no duplicates", eng.tick(now=base + 4) == [])
eng.add_records([(base + 5 + i * 0.1, "tcp", "203.0.113.5", "10.0.0.9",
                  41000 + i, 2000 + i, 0x02, "", None) for i in range(3)])
eng.tick(now=base + 6)
check("a growing scan stays ONE event (numbers stripped from identity)",
      len([e for e in eng.all_events() if "Port scan" in e["title"]]) == 1
      and "15 ports" in [e for e in eng.all_events()
                         if "Port scan" in e["title"]][0]["title"])

analysis = webui_mod.analyze(
    open(os.path.join(ROOT, "captures", "demo.pcap"), "rb").read(), "demo.pcap")
doc = rep_mod.render(analysis)
check("report renders the full analysis (verdict, story, playbook)",
      all(s in doc for s in ("COMPROMISED", "FULL ATTACK CHAIN",
                             "Port scan response")))
check("report is standalone (inline styles, no external assets)",
      "src=\"http" not in doc and "@import" not in doc and "<link" not in doc)
evil = {"file": {"name": "x", "size": 1, "kind": "pcap"}, "packets": 1,
        "tcp": 1, "udp": 0, "other": 0, "duration": 0.0, "score": 0,
        "verdict": "CLEAN",
        "events": [{"title": "t <img onerror=1>",
                    "raw": "<script>alert(1)</script>",
                    "english": "e & <b>", "category": "normal",
                    "severity": "info", "src": "1.1.1.1", "dst": "2.2.2.2",
                    "blue": "b", "red": "r", "ts": 0}],
        "stories": [], "playbooks": []}
doc2 = rep_mod.render(evil)
check("report escapes hostile evidence (safe HTML)",
      "<script>alert" not in doc2 and "&lt;script&gt;" in doc2
      and "<img onerror" not in doc2)

rep_out = os.path.join(tmpd, "report.html")
r = subprocess.run([sys.executable, os.path.join(ROOT, "replay.py"),
                    os.path.join(ROOT, "captures", "demo.pcap"),
                    "--export", rep_out], capture_output=True, text=True)
check("CLI --export writes the report file",
      r.returncode == 0 and os.path.getsize(rep_out) > 5000
      and "COMPROMISED" in open(rep_out, encoding="utf-8").read())

# live end-to-end: real packets on the loopback interface (skip gracefully
# on machines without capture rights — file mode proves the pipeline there)
_have_lo = any(i["name"] == "lo" for i in live_mod.list_interfaces())
try:
    _can = _have_lo and (os.geteuid() == 0
                         or _shutil.which("tshark") or live_mod.sudo_ok())
except Exception:
    _can = False
if _can:
    import socket as _sock
    sess = live_mod.CaptureSession("lo")
    try:
        sess.start()
        time.sleep(2.5)                            # let the transport come up
        for p in range(9310, 9328):                # a mini scan: 18 SYNs
            s = _sock.socket(); s.settimeout(0.15)
            try: s.connect(("127.0.0.1", p))
            except OSError: pass
            finally: s.close()
            time.sleep(0.09)
        time.sleep(7)                              # let several ticks run
        st = sess.status()
        titles = [e["title"] for e in sess.engine.all_events()]
        check(f"LIVE: real packets captured on lo ({st['packets']})",
              st["packets"] > 0)
        check("LIVE: a live port scan narrated in real time",
              any("Port scan" in t for t in titles), str(titles[:3]))
        snap = sess.engine.analysis()
        check("LIVE: snapshot analysis shaped like a file analysis",
              snap["packets"] == st["packets"]
              and snap["verdict"] in ("CLEAN", "SUSPICIOUS", "COMPROMISED"))
    finally:
        sess.stop()
    time.sleep(0.5)
    check("LIVE: session stops cleanly", not sess.status()["running"])
else:
    print("  SKIP  no capture rights here — live logic proven by unit checks")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)

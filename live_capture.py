#!/usr/bin/env python3
"""
CyberLens live capture (v1.0) — narrate a REAL interface as traffic arrives.

The architecture rule stays: one brain, many mouths. Live mode does NOT get
its own detector code — the record accumulator is re-run through the SAME
deterministic build_events() every tick (at our speed that costs nothing:
~225,000 packets/second), then a stable-key diff tells us which events are
NEW. So live mode is guaranteed to agree with replay mode. Same brain, no
drift, by construction.

Two transports, same records, picked automatically:
  running as root   -> raw AF_PACKET socket, pure stdlib (this file, --child)
  tshark installed  -> `tshark -i IF -n -l -w - -F pcap` streams a CLASSIC
                       pcap to stdout, parsed by the same native reader logic
                       the file mode uses. (tshark's default stream format is
                       pcapNG — we force -F pcap.) If plain tshark lacks
                       capture rights it dies instantly with a permission
                       error; we then escalate ONCE to `sudo -n tshark`.
  sudo -n allowed   -> sudo python3 live_capture.py --child IF  (raw socket)

Child mode (internal):  python3 live_capture.py --child lo
  opens the raw socket, prints one JSON record per line, flushes immediately.
"""
import json
import importlib.util
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import correlator
import playbooks
import replay

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\x4d\x3c\xb2\xa1": ("<", 1e9),
               b"\xa1\xb2\xc3\xd4": (">", 1e6), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
MAX_FRAME = 262144


# ----------------------------------------------------------- interfaces ----
def list_interfaces():
    """Network interfaces from /sys (Linux), with friendly hints."""
    out = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        names = []
    for name in names:
        try:
            with open(f"/sys/class/net/{name}/type") as fh:
                itype = fh.read().strip()
            with open(f"/sys/class/net/{name}/flags") as fh:
                flags = int(fh.read().strip(), 16)
        except (OSError, ValueError):
            continue
        out.append({"name": name, "loopback": itype == "776" or name == "lo",
                    "up": bool(flags & 0x1)})
    return out


def sudo_ok():
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True,
                              timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# ------------------------------------------------------------- records ----
def frame_to_record(frame, ts):
    """One raw Ethernet frame -> one record (same shape as replay's)."""
    d = replay.decode(frame)
    if d is None:
        return None
    proto, src, dst, sport, dport, flags, payload = d
    dns_q = None
    if proto == "udp" and dport == 53 and len(payload) >= 16:
        dns_q = replay.dns_qname(payload)
    if isinstance(payload, bytes):
        pay = payload.decode("latin1", "replace")
    else:
        pay = str(payload)
    return [ts, proto, src, dst, sport, dport, flags, pay, dns_q]


# ---------------------------------------------------------- child mode ----
def _child(iface):
    """Root-side raw sniffer. Prints JSON records, one per line."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.ntohs(0x0003))
    s.bind((iface, 0))
    try:
        while True:
            frame, _ = s.recvfrom(65535)
            rec = frame_to_record(frame, time.time())
            if rec is not None:
                print(json.dumps(rec), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


# ------------------------------------------------------- the live engine ----
def _stable_key(ev):
    """Identity of an event with all numbers stripped, so a port scan that
    grows from 12 to 30 ports stays ONE story, not two alerts."""
    return (re.sub(r"\d+", "", ev.get("title", "")) + "|"
            + ev.get("category", "") + "|" + str(ev.get("src")) + "|" + str(ev.get("dst")))


class LiveEngine:
    """Accumulate records; every tick re-run the batch brain and diff."""

    def __init__(self, label):
        self.label = label
        spec = importlib.util.spec_from_file_location("live_correlator", correlator.__file__)
        self.correlator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.correlator)
        self.lock = threading.RLock()
        self.limit = 100000
        self.records = []
        self.events = {}          # stable key -> event (updated in place)
        self.order = []           # stable keys in first-seen order
        self.stories = []
        self.meta = {}

    def add_records(self, recs):
        with self.lock:
            self.records.extend(recs[:max(0, self.limit - len(self.records))])

    def tick(self, now=None):
        """Returns the NEW events (base + stories) since last tick."""
        now = now or time.time()
        evs, meta = replay.build_events(list(self.records), len(self.records))
        self.meta = meta
        new = []
        for ev in evs:
            key = _stable_key(ev)
            if key not in self.events:
                self.events[key] = ev
                self.order.append(key)
                new.append(ev)
                story = self.correlator.observe(ev, now=now)
                if story:
                    story["ts"] = now
                    skey = "story|" + story["title"]
                    self.events[skey] = story
                    self.order.append(skey)
                    new.append(story)
                    self.stories.append(story)
            else:
                self.events[key] = ev          # counts grow: update in place
        return new

    def all_events(self):
        return [self.events[k] for k in self.order]

    def analysis(self):
        """A snapshot shaped exactly like a file analysis (export, tabs)."""
        events = self.all_events()
        score = min(100, sum(replay.SEV_W.get(e.get("severity"), 0)
                             for e in events))
        verdict = ("CLEAN" if score < 10 else "SUSPICIOUS" if score < 40
                   else "COMPROMISED")
        started = self.records[0][0] if self.records else time.time()
        return {"file": {"name": self.label, "size": 0, "kind": "live"},
                "packets": len(self.records),
                "tcp": self.meta.get("tcp", 0), "udp": self.meta.get("udp", 0),
                "other": self.meta.get("other", 0),
                "duration": round(time.time() - started, 1),
                "score": score, "verdict": verdict, "events": events,
                "stories": self.stories,
                "playbooks": playbooks.for_analysis(events),
                "took_ms": 0}


# ------------------------------------------------------ capture session ----
class CaptureSession:
    """Manages one live capture: transport process + reader + ticker."""

    def __init__(self, iface):
        self.iface = iface
        self.engine = LiveEngine(f"live: {iface}")
        self.proc = None
        self.transport = ""
        self.running = False
        self.error = ""
        self.started = 0
        self.last_pkt = 0
        self.pps = 0
        self._escalated = False
        self._pps_window = (time.time(), 0)
        self._lock = threading.RLock()

    # -- transport -----------------------------------------------------
    def _tshark_cmd(self, sudo=False):
        # -w - : stream to stdout   -F pcap : force CLASSIC pcap (tshark's
        # stream default is pcapNG, which our native reader does not parse)
        t = shutil.which("tshark")
        cmd = [t, "-i", self.iface, "-n", "-l", "-w", "-", "-F", "pcap"]
        return (["sudo", "-n"] + cmd) if sudo else cmd

    def _raw_cmd(self, sudo=False):
        cmd = [sys.executable, os.path.abspath(__file__), "--child", self.iface]
        return (["sudo", "-n"] + cmd) if sudo else cmd

    def _pick_transport(self):
        if os.geteuid() == 0:
            return self._raw_cmd(), "raw socket (root)"
        if shutil.which("tshark"):
            return self._tshark_cmd(), "tshark (Wireshark engine)"
        if sudo_ok():
            return self._raw_cmd(sudo=True), "raw socket (sudo)"
        raise ValueError(
            "Live capture needs permission to see packets. Either:\n"
            "  1) install tshark (apt install tshark) and give it capture "
            "rights, or\n"
            "  2) run with root rights (sudo cyberlens-web), or\n"
            "  3) allow passwordless sudo for this user.\n"
            "File analysis works without any of this — only live mode needs it.")

    # -- lifecycle ------------------------------------------------------
    def start(self):
        cmd, transport = self._pick_transport()
        self._spawn(cmd)
        self.transport = transport
        self.running = True
        self.started = time.time()
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._ticker, daemon=True).start()

    def _spawn(self, cmd):
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)

    def stop(self):
        self.running = False
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                except OSError:
                    pass

        with self._lock:
            self.engine.tick()

    # -- low-level pipe helpers (never block forever) -------------------
    @staticmethod
    def _wait(fd, timeout):
        try:
            r, _, _ = select.select([fd], [], [], timeout)
            return bool(r)
        except (OSError, ValueError):
            return True                      # select unavailable: block on

    @staticmethod
    def _read_fd(fd):
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""

    def _died_early(self):
        """Process already exited: was it a permission problem?"""
        if self.proc.poll() is None:
            return False                     # still running: not a death
        try:
            err = (self.proc.stderr.read() or b"").decode("utf-8", "replace")
        except (OSError, ValueError):
            err = ""
        self.error = err[:400] or "capture process ended"
        return ("permission" in err.lower()
                or "not permitted" in err.lower())

    # -- threads --------------------------------------------------------
    def _reader(self):
        try:
            if "raw socket" in self.transport:
                self._read_json_lines()
            else:
                self._read_pcap_stream()
        finally:
            self.running = False
            if self.proc and self.proc.poll() is None:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                except OSError:
                    pass

    def _read_json_lines(self):
        """Our raw-socket child speaks JSON lines."""
        while self.running:
            line = self.proc.stdout.readline().decode("utf-8", "replace")
            if not line:
                self._died_early()
                return
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, list) and len(rec) == 9:
                    self.engine.add_records([tuple(rec)])
                    self.last_pkt = time.time()
            except json.JSONDecodeError:
                pass

    def _read_pcap_stream(self):
        """tshark -w - -F pcap : classic pcap bytes on stdout, parsed with
        the same logic as replay.read_pcap — but streaming, and with one
        sudo escalation if plain tshark lacks capture rights."""
        while True:
            fd = self.proc.stdout.fileno()
            buf = b""
            t0 = time.time()
            while len(buf) < 24 and self.running:      # global pcap header
                if self._wait(fd, 0.5) or self.proc.poll() is not None:
                    chunk = self._read_fd(fd)
                    if chunk:
                        buf += chunk
                    elif self.proc.poll() is not None:
                        break
                if time.time() - t0 > 6:
                    break
            if len(buf) >= 24 and buf[:4] in PCAP_MAGICS:
                self._consume_pcap(fd, buf)
                return
            # no pcap header: died, or silent — maybe escalate once
            if (not self._escalated and self._died_early() and sudo_ok()
                    and shutil.which("tshark")):
                self._escalated = True
                self._spawn(self._tshark_cmd(sudo=True))
                self.transport = "tshark via sudo"
                self.error = ""                     # stale error, we're back
                continue
            if not self.error:
                self.error = ("tshark produced no pcap stream (interface "
                              "down, or capture not permitted)")
            return

    def _consume_pcap(self, fd, buf):
        """State machine over the pcap record stream (header, body, ...)."""
        endian, div = PCAP_MAGICS[buf[:4]]
        linktype = struct.unpack(endian + "I", buf[20:24])[0]
        if linktype != 1:
            self.error = f"Unsupported capture link type {linktype}; select an Ethernet interface (not any/monitor)."
            return
        buf = buf[24:]
        need_hdr, pending, ts = True, 0, 0.0
        while self.running:
            progressed = True
            while progressed:                          # drain what we have
                progressed = False
                if need_hdr and len(buf) >= 16:
                    sec, frac, incl, _ = struct.unpack(
                        endian + "IIII", buf[:16])
                    if incl > MAX_FRAME:
                        self.error = "pcap stream corrupted"
                        return
                    buf = buf[16:]
                    pending, ts, need_hdr = incl, sec + frac / div, False
                    progressed = True
                elif not need_hdr and len(buf) >= pending:
                    frame, buf = buf[:pending], buf[pending:]
                    rec = frame_to_record(frame, ts)
                    if rec is not None:
                        if self.error:
                            self.error = ""         # packets flow: all good
                        self.engine.add_records([rec])
                        self.last_pkt = time.time()
                    need_hdr, progressed = True, True
            if not self._wait(fd, 1.0):
                continue
            chunk = self._read_fd(fd)
            if not chunk:
                if self.running:
                    self.error = self.error or "capture stream ended"
                return
            buf += chunk

    def _ticker(self):
        while self.running:
            time.sleep(1.5)
            with self._lock:
                if not self.running:
                    break
                self.engine.tick()
                if len(self.engine.records) >= self.engine.limit:
                    self.error = "100,000-record session limit reached. Export this snapshot and start a new capture."
                    self.stop()
                    break
                now, seen = self._pps_window
                total = len(self.engine.records)
                self.pps = int((total - seen) / max(time.time() - now, 0.001))
                self._pps_window = (time.time(), total)

    # -- status ----------------------------------------------------------
    def status(self):
        with self._lock:
            return {"running": self.running, "iface": self.iface,
                    "transport": self.transport,
                    "packets": len(self.engine.records), "pps": self.pps,
                    "events": len(self.engine.order),
                    "uptime_s": round(time.time() - self.started, 1)
                    if self.started else 0,
                    "last_pkt_ago": round(time.time() - self.last_pkt, 1)
                    if self.last_pkt else None,
                    "error": self.error}


if __name__ == "__main__":
    if "--child" in sys.argv:
        _child(sys.argv[sys.argv.index("--child") + 1])
    else:
        print("interfaces:", json.dumps(list_interfaces(), indent=1))

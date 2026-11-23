#!/usr/bin/env python3
"""
Build a BIG realistic capture for the v0.8 scale test.

Same honest style as make_demo_pcap.py, just bigger and deterministic:
  - thousands of normal packets (web browsing, DNS, TLS handshakes, NTP)
    from a pool of office machines
  - plus ONE compact attack chain near the end (scan -> brute force ->
    SQL injection -> DNS exfiltration), inside the correlator's window so
    the story still connects

Deterministic: fixed random seed -> identical file every run, so the scale
test in tests.py can assert exact findings.   Usage:

    python3 make_big_pcap.py --packets 20000 --out big.pcap
"""
import argparse
import random
import time

import make_demo_pcap as demo


def _mac(ip):
    """Stable fake MAC for any address (02 = locally administered)."""
    n = sum((i + 1) * int(o) for i, o in enumerate(ip.split(".")))
    return bytes([0x02, n & 0xFF, (n >> 3) & 0xFF, (n >> 5) & 0xFF,
                  (n >> 7) & 0xFF, (n >> 9) & 0xFF])


CLIENTS = [f"192.168.1.{20 + i}" for i in range(18)]
SITES = {"93.184.216.34": "example.com",
         "104.18.32.115": "cdn.example.net",
         "151.101.1.69": "news.example.org"}
TLS_IP = "104.16.132.229"
ATK = "203.0.113.7"
for ip in CLIENTS + list(SITES) + [TLS_IP]:
    demo.MACS.setdefault(ip, _mac(ip))

PATHS = ("/", "/index.html", "/about", "/api/v2/status", "/reports/q3.pdf",
         "/articles/how-to-notice-a-scan", "/cart", "/login", "/static/app.js",
         "/search?q=weather", "/dashboard", "/health")
NAMES = ("example.com", "cdn.example.net", "news.example.org", "wikipedia.org",
         "mail.example.net", "updates.example.net", "api.example.org")


def build(n_packets, t0):
    random.seed(42)                      # deterministic file, every run
    pkts = []

    def T(t, s, d, sp, dp, flags, payload=b"", seq=1000, ack=0):
        pkts.append((t, demo.eth(s, d, demo.ip4(
            s, d, 6, demo.tcp(s, d, sp, dp, seq, ack, flags, payload)))))

    def U(t, s, d, sp, dp, payload):
        pkts.append((t, demo.eth(s, d, demo.ip4(
            s, d, 17, demo.udp(s, d, sp, dp, payload)))))

    # ---- the compact attack chain (61 packets, inside one window) ---------
    ATTACK = 61
    target = max(n_packets - ATTACK, ATTACK + 100)

    t = t0
    # 1 - thousands of normal packets ---------------------------------------
    while len(pkts) < target:
        cli = random.choice(CLIENTS)
        kind = random.random()
        t += random.uniform(0.05, 1.2)
        if kind < 0.45:                              # web session
            site = random.choice(list(SITES))
            sport = random.randint(40000, 60000)
            path = random.choice(PATHS)
            req = (f"GET {path} HTTP/1.1\r\nHost: {SITES[site]}\r\n\r\n"
                   .encode())
            T(t, cli, site, sport, 80, 0x02)
            T(t + 0.02, cli, site, sport, 80, 0x18, req)
            T(t + 0.04, site, cli, 80, sport, 0x18,
              b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        elif kind < 0.70:                            # DNS lookup
            U(t, cli, demo.GATEWAY, random.randint(40000, 60000), 53,
              demo.dns_query(random.choice(NAMES), random.randint(1, 60000)))
        elif kind < 0.85:                            # TLS handshake start
            T(t, cli, TLS_IP, random.randint(40000, 60000), 443, 0x02)
            T(t + 0.02, TLS_IP, cli, 443, random.randint(40000, 60000), 0x12)
        else:                                        # NTP
            U(t, cli, demo.GATEWAY, random.randint(40000, 60000), 123,
              b"\x23" + b"\x00" * 47)
    # pad to the exact target with single DNS packets (1 pkt each)
    while len(pkts) < target:
        t += 0.05
        U(t, random.choice(CLIENTS), demo.GATEWAY, 53000, 53,
          demo.dns_query(random.choice(NAMES), random.randint(1, 60000)))

    # 2 - attack chain: recon -> brute force -> web attack -> exfil ----------
    t += 5
    for i, port in enumerate((21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
                              1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                              9000, 27017)):
        T(t, ATK, demo.SRV, 40000 + i, port, 0x02, seq=2000 + i)
        t += 0.3
    t += 1
    for i in range(8):                                # SSH brute force
        T(t, ATK, demo.SRV, 41000 + i, 22, 0x02, seq=3000 + i)
        T(t + 0.01, demo.SRV, ATK, 22, 41000 + i, 0x12, seq=4000 + i,
          ack=3001 + i)
        T(t + 0.02, ATK, demo.SRV, 41000 + i, 22, 0x10, ack=4001 + i)
        T(t + 0.03, ATK, demo.SRV, 41000 + i, 22, 0x18,
          b"SSH-2.0-OpenSSH_9.6\r\n")
        t += 2
    sqli = ("GET /products.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\n"
            "Host: shop.local\r\n\r\n").encode()
    T(t, ATK, demo.SRV, 42000, 80, 0x02)
    T(t + 0.02, ATK, demo.SRV, 42000, 80, 0x18, sqli)
    t += 2
    for i in range(6):                                # DNS exfiltration
        q = f"b7k2p9x4m6z1w3q8rt5yu.slice{i}.backup2015.shady-example.ru"
        U(t, demo.SRV, demo.EXFIL_NS, 53500 + i, 53,
          demo.dns_query(q, 500 + i, qtype=16))
        t += 5
    return pkts


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CyberLens — big-capture builder")
    ap.add_argument("--packets", type=int, default=5000)
    ap.add_argument("--out", default="big.pcap")
    args = ap.parse_args()
    # fixed reference time -> the file is byte-identical on every run
    # (the scale test in tests.py depends on this determinism)
    pkts = build(args.packets, 1_769_000_000.0)
    demo.write_pcap(args.out, pkts)
    print(f"wrote exactly {len(pkts)} packets to {args.out} "
          f"({args.packets} requested) — deterministic, opens in Wireshark")

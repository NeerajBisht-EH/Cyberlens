#!/usr/bin/env python3
"""
Build a realistic demo capture: captures/demo.pcap

The capture tells ONE story across ~75 seconds:
  1. normal office traffic    (DNS, HTTP browsing, TLS, NTP)
  2. an outside attacker scans 21 ports on server 10.0.0.5
  3. the attacker hammers SSH with repeated connections (brute force)
  4. one SQL-injection probe over HTTP
  5. the (now compromised) server smuggles data out inside long DNS queries

Valid classic-pcap with correct checksums — opens in Wireshark/tcpdump.
Pure stdlib.    Usage:  python3 make_demo_pcap.py [output.pcap]
"""
import os
import socket
import struct
import sys
import time

GATEWAY = "192.168.1.1"
CLI = "192.168.1.24"
CLI2 = "192.168.1.31"
WEB = "93.184.216.34"
TLS = "104.16.132.229"
ATK = "203.0.113.7"
SRV = "10.0.0.5"
EXFIL_NS = "45.155.204.11"

MACS = {GATEWAY: bytes.fromhex("020000000001"), CLI: bytes.fromhex("021122334455"),
        CLI2: bytes.fromhex("021122334466"), WEB: bytes.fromhex("02aabbccddee"),
        TLS: bytes.fromhex("02aabbccddef"), ATK: bytes.fromhex("02deadbeef01"),
        SRV: bytes.fromhex("025555666677"), EXFIL_NS: bytes.fromhex("02deadbeef02")}


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(src_ip, dst_ip, payload, ethertype=0x0800):
    return MACS[dst_ip] + MACS[src_ip] + struct.pack("!H", ethertype) + payload


def ip4(src, dst, proto, payload, ident=1):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                         0x4000, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def tcp(src, dst, sport, dport, seq=1000, ack=0, flags=0x02, payload=b"",
        window=64240):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags,
                         window, 0, 0)
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + struct.pack("!BBH", 0, 6, len(header) + len(payload)))
    c = checksum(pseudo + header + payload) or 0xFFFF
    header = header[:16] + struct.pack("!H", c) + header[18:]
    return header + payload


def udp(src, dst, sport, dport, payload=b""):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + struct.pack("!BBH", 0, 17, 8 + len(payload)))
    c = checksum(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", c) + header[8:] + payload


def dns_query(qname, qid, qtype=1):
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in qname.split("."):
        msg += bytes([len(label)]) + label.encode()
    return msg + b"\x00" + struct.pack("!HH", qtype, 1)


def write_pcap(path, pkts):
    folder = os.path.dirname(os.path.abspath(path))
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, frame in pkts:
            sec = int(t)
            usec = int(round((t - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, 0
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


def build(t0):
    pkts = []

    def T(t, s, d, sp, dp, flags, payload=b"", seq=1000, ack=0):
        pkts.append((t, eth(s, d, ip4(s, d, 6, tcp(s, d, sp, dp, seq, ack,
                                                   flags, payload)))))

    def U(t, s, d, sp, dp, payload):
        pkts.append((t, eth(s, d, ip4(s, d, 17, udp(s, d, sp, dp, payload)))))

    t = t0
    # 1 - normal office traffic --------------------------------------------
    for i, host in enumerate(("example.com", "cdn.example.net", "mail.example.net")):
        U(t, CLI, GATEWAY, 53000 + i, 53, dns_query(host, 100 + i))
        t += 2
    for i, path in enumerate(("/index.html", "/dashboard", "/api/v2/status",
                              "/reports/q3.pdf")):
        req = f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        T(t, CLI, WEB, 51000 + i, 80, 0x02)
        T(t + 0.02, CLI, WEB, 51000 + i, 80, 0x18, req)
        t += 3
    U(t, CLI2, GATEWAY, 53010, 123, b"\x23" + b"\x00" * 47)          # NTP
    U(t + 0.5, CLI2, GATEWAY, 53011, 53, dns_query("wikipedia.org", 120))
    T(t + 1, CLI2, TLS, 52001, 443, 0x02)
    T(t + 1.02, CLI2, TLS, 52001, 443, 0x18, b"\x17\x03\x03\x00\x10" + b"\xaa" * 16)
    t += 4

    # 2 - port scan ----------------------------------------------------------
    for i, port in enumerate((21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
                              1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                              9000, 27017)):
        T(t, ATK, SRV, 40000 + i, port, 0x02, seq=2000 + i)
        t += 0.3
    t += 1

    # 3 - SSH brute force (repeated connections) ------------------------------
    for i in range(8):
        T(t, ATK, SRV, 41000 + i, 22, 0x02, seq=3000 + i)
        T(t + 0.01, SRV, ATK, 22, 41000 + i, 0x12, seq=4000 + i, ack=3001 + i)
        T(t + 0.02, ATK, SRV, 41000 + i, 22, 0x10, ack=4001 + i)
        T(t + 0.03, ATK, SRV, 41000 + i, 22, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n")
        t += 2

    # 4 - SQL injection probe (URL-encoded, exactly like real scanners send it,
    #     so tshark's HTTP dissector parses it and we decode it for detection)
    sqli = ("GET /products.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\n"
            "Host: shop.local\r\n\r\n").encode()
    T(t, ATK, SRV, 42000, 80, 0x02)
    T(t + 0.02, ATK, SRV, 42000, 80, 0x18, sqli)
    t += 2

    # 5 - data exfiltration through DNS ----------------------------------------
    for i in range(6):
        q = f"a8f3k2x9m1q7w2e5rt8z4.slice{i}.backup2015.shady-example.ru"
        U(t, SRV, EXFIL_NS, 53500 + i, 53, dns_query(q, 500 + i, qtype=16))
        t += 5

    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "captures/demo.pcap"
    pkts = build(time.time() - 240)     # "captured 4 minutes ago"
    write_pcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out} "
          f"({os.path.getsize(out)} bytes) — opens in Wireshark/tcpdump")

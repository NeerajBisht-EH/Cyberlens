"""Malware 'calling home' — the heartbeat of an already-compromised machine."""
import random

WEIGHT = 7
CAT = "breach"

CONTROLLERS = ["185.220.101.4", "91.240.118.172", "45.155.204.11"]
HOSTS = ["10.0.0.5", "10.0.0.8", "192.168.1.64"]


def generate():
    host = random.choice(HOSTS)
    c2 = random.choice(CONTROLLERS)
    every = random.choice([30, 60, 90])
    jitter = random.choice(["±0.4 s", "±2 s", "none"])
    return dict(
        title=f"Malware check-in signal from {host}",
        raw=(f"IP {host}.{random.randint(49152, 65535)} > {c2}:8443: TLS\n"
             f"packet length 128 bytes, every {every}s ({jitter} jitter) — "
             f"47 check-ins in a row"),
        english=(f"Your machine {host} is sending a tiny 'I'm here' message to the "
                 f"same outside address ({c2}) every {every} seconds — regular "
                 f"like a heartbeat. People don't work like clocks; malware does. "
                 f"This pattern means a program on {host} is probably compromised "
                 f"and is waiting for orders from its controller (command & "
                 f"control)."),
        category="breach", severity="critical", src=host, dst=c2,
        blue=(f"Treat {host} as compromised: isolate it from the network, find "
              f"which process makes these connections (netstat / ss, then the "
              f"binary behind it), capture its memory if possible, and rebuild "
              f"the machine rather than 'cleaning' it."),
        red=("A fixed-interval heartbeat of small packets keeps a stolen foothold "
             "alive. Random jitter exists to slip past exactly this detection."))

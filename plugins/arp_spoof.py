"""LAN attack: someone is lying about being the gateway (MITM setup)."""
import random

WEIGHT = 7
CAT = "attack"


def generate():
    atk = f"192.168.1.{random.randint(90, 199)}"
    host = f"192.168.1.{random.randint(20, 80)}"
    gw = "192.168.1.1"
    return dict(
        title="ARP spoofing — impersonating the gateway",
        raw=(f"ARP reply (unsolicited): {atk} claims 'I am 192.168.1.1'\n"
             f"ARP reply (unsolicited): {atk} claims 'I am 192.168.1.1'  (x8 in 4 s)\n"
             f"victim {host} is now sending its traffic through {atk}"),
        english=(f"On the office LAN, a device ({atk}) is loudly lying: it keeps "
                 f"announcing 'I am the router' to {host}. If {host} believes it, "
                 f"all of its traffic flows through the liar first — who can now "
                 f"silently read or even change everything (logins, sessions) "
                 f"while staying invisible in the middle."),
        category="attack", severity="high", src=atk, dst=gw,
        blue=("Enable Dynamic ARP Inspection on switches if available; keep static "
              "ARP entries for critical hosts; run arpwatch to alarm on conflicts. "
              "The attacker's MAC address identifies the machine."),
        red=("Nobody verifies ARP on a local network — trust is assumed, so "
             "claiming the gateway's address quietly re-routes traffic through "
             "the attacker."))

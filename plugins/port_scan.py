"""Reconnaissance: quietly mapping the target before attacking."""
import random

WEIGHT = 13
CAT = "recon"

ATTACKERS = ["203.0.113.7", "198.51.100.23", "45.148.10.92", "91.240.118.172"]
SERVERS = ["10.0.0.5", "10.0.0.8", "192.168.1.1"]


def generate():
    atk, srv = random.choice(ATTACKERS), random.choice(SERVERS)
    n = random.choice([42, 88, 137, 241])
    kind = random.choice(["syn", "service"])
    if kind == "syn":
        return dict(
            title=f"Port scan detected on {srv}",
            raw=(f"IP {atk}.{random.randint(40000, 65000)} > {srv}.22: "
                 f"Flags [S], seq {random.randint(1000, 9999)}\n"
                 f"… same source probed {n} ports on {srv} in 6 seconds …"),
            english=(f"An outside computer ({atk}) is rapidly knocking on {n} "
                     f"different doors (ports) of your server {srv}. Nobody "
                     f"legitimate needs to knock on every door — this is someone "
                     f"drawing a map of what's open before choosing how to break "
                     f"in. It's the reconnaissance phase: step one of almost every "
                     f"real attack."),
            category="recon", severity="medium", src=atk, dst=srv,
            blue=(f"If you don't recognise {atk}, block it at the firewall and "
                  f"watch for it returning. Run your own scan (nmap -sV {srv}) "
                  f"and close every port you don't truly need."),
            red=("Scanning is cheap and almost silent: each open port reveals a "
                 "service, often its exact version — the ingredient list for the "
                 "next step."))
    return dict(
        title=f"Service fingerprinting on {srv}",
        raw=(f"IP {atk}.51 > {srv}.80: Flags [S] -> SYN/ACK\n"
             f"GET /server-status -> 403 | GET /.git/config -> 404 | "
             f"GET /admin -> 200"),
        english=(f"{atk} found an open web door on {srv} and is quietly asking it "
                 f"questions ('do you have /admin?', 'is there a .git folder "
                 f"here?') to learn exactly what software runs there and where "
                 f"the weak spots are. Reading the room before the attack."),
        category="recon", severity="medium", src=atk, dst=srv,
        blue=("Audit what your web server exposes: remove backup/.git files, "
              "disable directory listing, return generic error pages."),
        red=("Web servers leak their configuration through small tells — status "
             "codes differ for paths that exist."))

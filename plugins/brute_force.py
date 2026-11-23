"""Password-guessing attacks against remote-access services."""
import random

WEIGHT = 10
CAT = "attack"

ATTACKERS = ["198.51.100.23", "45.148.10.92", "141.98.11.20", "103.97.203.6"]
TARGETS = [
    ("10.0.0.5", "ssh", "root"),
    ("10.0.0.5", "ssh", "admin"),
    ("10.0.0.8", "rdp", "administrator"),
    ("10.0.0.12", "smtp", "billing"),
]


def generate():
    atk = random.choice(ATTACKERS)
    srv, svc, user = random.choice(TARGETS)
    tries = random.choice([8, 19, 34, 61])
    samples = "\n".join(
        f"auth: FAILED login for '{user}' from {atk} "
        f"port {random.randint(49000, 64000)} ({svc})"
        for _ in range(3)
    )
    raw = (f"[auth/{svc}] {srv}:\n{samples}\n"
           f"… {tries} failed logins for '{user}' in 60 seconds …")
    if random.random() < 0.2:      # sometimes it succeeds — that's the scary lesson
        raw += f"\n[auth/{svc}] ACCEPTED login for '{user}' from {atk}  <- SUCCESS"
        return dict(
            title=f"Brute-force SUCCEEDED on {srv} ({svc})",
            raw=raw,
            english=(f"Someone from {atk} kept guessing the password of the "
                     f"'{user}' account on your server {srv} — {tries} wrong "
                     f"tries, and then one worked. They are inside now. This is "
                     f"the exact moment a break-in happens: from here they can "
                     f"read files, install malware, and move deeper into your "
                     f"network."),
            category="breach", severity="critical", src=atk, dst=srv,
            blue=("Isolate the machine immediately, disable the account, rotate "
                  "every password and key it could have reached, and preserve the "
                  "logs. Assume they changed something — verify everything, trust "
                  "nothing."),
            red=("Password guessing is free and quiet. One lucky guess is enough — "
                 "and key-based logins remove the guessing game entirely."))
    return dict(
        title=f"Password brute-force on {srv} ({svc})",
        raw=raw,
        english=(f"Someone from {atk} is trying to guess the password of "
                 f"'{user}' on your server {srv} — {tries} wrong passwords in one "
                 f"minute, like a thief trying every key on a keyring. So far, "
                 f"every try has failed."),
        category="attack", severity="high", src=atk, dst=srv,
        blue=(f"Block {atk}; add automatic blocking after a few failures "
              f"(fail2ban); move {svc} to key-based or MFA login so guessing is "
              f"pointless."),
        red=("Guessing costs nothing and makes no noise — unless someone counts "
             "the failures. Defences fail when nobody counts."))

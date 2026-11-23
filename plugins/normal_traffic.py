"""Everyday baseline traffic. A defender who can't recognise 'normal'
can never spot 'abnormal' — so the toolbox starts here."""
import random

WEIGHT = 40
CAT = "normal"

SITES = ["example.com", "cdn.example.net", "portal.company.io",
         "docs.python.org", "mail.company.io", "en.wikipedia.org"]


def _host():
    return f"192.168.1.{random.randint(20, 80)}"


def generate():
    host = _host()
    kind = random.choice(["web", "dns", "video", "update"])
    if kind == "web":
        site = random.choice(SITES)
        path = random.choice(["/index.html", "/dashboard", "/api/v2/status",
                              "/reports/q3-summary.pdf", "/inbox"])
        return dict(
            title="Normal web browsing",
            raw=(f"IP {host}.{random.randint(49152, 65535)} > {site}:443: "
                 f"Flags [P.], length {random.randint(180, 950)}\n"
                 f"GET {path} HTTP/2 (TLS 1.3)"),
            english=(f"A computer inside your network ({host}) is loading a page "
                     f"from {site} over an encrypted connection. Ordinary web "
                     f"browsing — like someone reading a website."),
            category="normal", severity="info", src=host, dst=site,
            blue="No action needed. This is your baseline.",
            red="Baseline traffic is what attackers try to blend into.")
    if kind == "dns":
        site = random.choice(SITES)
        return dict(
            title="DNS lookup (phone-book check)",
            raw=(f"IP {host}.{random.randint(49152, 65535)} > 192.168.1.1.53: "
                 f"UDP, length 54\nA? {site}  ->  answer: 93.184.216.34"),
            english=(f"{host} asked the network's phone book (DNS) for the address "
                     f"of {site} and got an answer. This happens before every "
                     f"connection — completely normal."),
            category="normal", severity="info", src=host, dst="192.168.1.1",
            blue="No action needed.",
            red=("DNS answers are trusted blindly — which is why attackers love "
                 "hiding data inside them (see the breach events)."))
    if kind == "video":
        return dict(
            title="Video call / streaming",
            raw=(f"IP {host}.{random.randint(49152, 65535)} > media.company.io:5004: "
                 f"UDP, length 1316\nsteady ~4 Mbps stream, "
                 f"running {random.randint(2, 25)} min"),
            english=(f"{host} is in a video call or watching a stream — a steady "
                     f"flow of small UDP packets to a media server. Nothing unusual."),
            category="normal", severity="info", src=host, dst="media.company.io",
            blue="No action needed. If it ever floods the link, that's a capacity problem, not an attack.",
            red="Live streams create so much noise that small attacks can hide inside them.")
    return dict(
        title="Software update check",
        raw=(f"IP {host}.{random.randint(49152, 65535)} > updates.ubuntu.com:443: TLS 1.3\n"
             f"GET /dists/noble/InRelease  200 OK ({random.randint(3, 40)} KB)"),
        english=(f"{host} checked for software updates and downloaded a small signed "
                 f"file. Patching closes known holes — this is healthy behaviour."),
        category="normal", severity="info", src=host, dst="updates.ubuntu.com",
        blue="No action needed. Patching is your cheapest defence.",
        red="Unpatched machines are an attacker's favourite door — old software means known exploits.")

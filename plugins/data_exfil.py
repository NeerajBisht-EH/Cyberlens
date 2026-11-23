"""The attacker's final goal: data leaving the network."""
import random

WEIGHT = 5
CAT = "breach"


def generate():
    host = random.choice(["10.0.0.5", "10.0.0.8"])
    gb = random.choice([0.8, 1.9, 2.4, 4.1])
    kind = random.choice(["dns", "https"])
    if kind == "dns":
        return dict(
            title="Data smuggling through DNS",
            raw=(f"IP {host} > ns1.shady-example.ru.53: UDP\n"
                 f"TXT? a8f3k2x9m1.customerstable.slice1.shady-example.ru\n"
                 f"TXT? q7w2e5rt8.customerstable.slice2.shady-example.ru\n"
                 f"… ~{gb} GB carried in {int(gb * 1000)}+ fake lookups "
                 f"over 40 minutes …"),
            english=(f"Your server {host} is mailing out stolen data in tiny "
                     f"pieces hidden inside DNS 'lookups' — about {gb} GB in "
                     f"total, spread over thousands of fake domain questions to a "
                     f"strange server. Real DNS questions are a few dozen bytes; "
                     f"nobody legitimately sends gigabytes this way. This is data "
                     f"theft in progress."),
            category="breach", severity="critical", src=host, dst="ns1.shady-example.ru",
            blue=("This confirms a serious breach: isolate the host, find what "
                  "data fits those packets (file audit), involve legal/management "
                  "early, and force-reset credentials for everything that machine "
                  "could read."),
            red=("DNS is almost never blocked on the way out, so it's a classic "
                 "smuggling tunnel: hide the loot inside questions nobody reads."))
    return dict(
        title="Bulk upload to unknown cloud storage",
        raw=(f"IP {host}.52 > storage.unknown-cdn.ru:443: TLS\n"
             f"PUT /drop/bx92.tar.gz.aes  — {gb} GB uploaded in 18 min "
             f"(domain registered 3 days ago)"),
        english=(f"Your server {host} pushed a {gb} GB encrypted archive to a "
                 f"cloud storage no one in your company uses — a domain "
                 f"registered only days ago. It looks like someone packed up "
                 f"your files and carried them out the back door."),
        category="breach", severity="critical", src=host, dst="storage.unknown-cdn.ru",
        blue=("Snapshot the machine for evidence, identify the archive contents "
              "and where the upload tool came from, then rotate every secret the "
              "host could access."),
        red=("Encryption and 'trusted' cloud services make exfiltration look like "
             "ordinary backup traffic."))

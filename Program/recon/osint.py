# language: Python, file: Program/recon/osint.py, target: Red Sky recon — OSINT
# Username / email / domain OSINT. Real queries, real results.

import json
import sys
import time
from typing import List

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

PLATFORMS = {
    "github":     "https://github.com/{}",
    "gitlab":     "https://gitlab.com/{}",
    "twitter":    "https://twitter.com/{}",
    "instagram":  "https://instagram.com/{}",
    "tiktok":     "https://tiktok.com/@{}",
    "reddit":     "https://reddit.com/user/{}",
    "twitch":     "https://twitch.tv/{}",
    "youtube":    "https://youtube.com/@{}",
    "telegram":   "https://t.me/{}",
    "discord":    "https://discord.com/users/{}",
    "steam":      "https://steamcommunity.com/id/{}",
    "roblox":     "https://www.roblox.com/user.aspx?username={}",
    "pinterest":  "https://pinterest.com/{}",
    "medium":     "https://medium.com/@{}",
    "hackernews": "https://news.ycombinator.com/user?id={}",
    "keybase":    "https://keybase.io/{}",
    "patreon":    "https://patreon.com/{}",
    "soundcloud": "https://soundcloud.com/{}",
    "spotify":    "https://open.spotify.com/user/{}",
    "snapchat":   "https://snapchat.com/add/{}",
}


def username_lookup(username: str) -> int:
    print_info(f"username lookup: {username}")
    headers = {"User-Agent": UA}
    hits = []

    for name, tpl in PLATFORMS.items():
        url = tpl.format(username)
        try:
            r = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            if r.status_code == 200:
                hits.append({"platform": name, "url": url, "status": 200})
                print_ok(f"{name:<14} {url}")
            elif r.status_code in (301, 302) and username.lower() in r.url.lower():
                hits.append({"platform": name, "url": r.url, "status": r.status_code})
                print_ok(f"{name:<14} {r.url}  (redirect)")
        except requests.RequestException:
            continue

    print()
    print_kv("hits", len(hits))

    out = OUTPUT_DIR / f"osint_username_{username}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def email_lookup(email: str) -> int:
    print_info(f"email lookup: {email}")
    results = {"email": email}

    # basic format
    if "@" not in email:
        print_err("not a valid email")
        return 1

    local, domain = email.split("@", 1)
    results["local"] = local
    results["domain"] = domain

    # MX record
    try:
        import dns.resolver
        mx = [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX")]
        results["mx"] = mx
        print_ok(f"MX: {', '.join(mx)}")
    except Exception:
        results["mx"] = []
        print_warn("no MX records")

    # SPF
    try:
        import dns.resolver
        spf = [str(r) for r in dns.resolver.resolve(domain, "TXT") if "v=spf1" in str(r)]
        results["spf"] = spf
        if spf:
            print_ok(f"SPF: {spf[0][:80]}")
    except Exception:
        results["spf"] = []

    # Gravatar
    import hashlib
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar = f"https://www.gravatar.com/avatar/{h}"
    try:
        r = requests.head(gravatar + "?d=404", timeout=8)
        results["gravatar"] = (r.status_code == 200)
        if r.status_code == 200:
            print_ok(f"gravatar: {gravatar}")
    except requests.RequestException:
        results["gravatar"] = False

    # HIBP
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                         headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            breaches = [b["Name"] for b in r.json()]
            results["hibp"] = breaches
            print_ok(f"HIBP: {len(breaches)} breaches — {', '.join(breaches[:8])}")
        elif r.status_code == 404:
            results["hibp"] = []
            print_info("HIBP: no breaches found")
        elif r.status_code == 401:
            results["hibp"] = "needs-api-key"
            print_warn("HIBP: needs API key (free tier)")
        else:
            results["hibp"] = f"status {r.status_code}"
    except requests.RequestException:
        results["hibp"] = "unreachable"

    print()
    out = OUTPUT_DIR / f"osint_email_{email.replace('@', '_at_')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print_kv("saved", out)
    return 0


def domain_lookup(domain: str) -> int:
    print_info(f"domain lookup: {domain}")
    results = {"domain": domain}

    try:
        import whois
        w = whois.whois(domain)
        results["registrar"] = str(w.registrar) if w.registrar else ""
        results["creation"] = str(w.creation_date) if w.creation_date else ""
        results["expiry"] = str(w.expiration_date) if w.expiration_date else ""
        results["name_servers"] = [str(ns) for ns in (w.name_servers or [])]
        print_ok(f"registrar: {results['registrar']}")
        print_ok(f"created:   {results['creation']}")
        print_ok(f"expires:   {results['expiry']}")
        for ns in results["name_servers"]:
            print_bullet(f"ns: {ns}")
    except Exception as e:
        print_warn(f"whois failed: {e}")

    print()
    out = OUTPUT_DIR / f"osint_domain_{domain}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, default=str))
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if len(args) < 2:
        print_err("usage: redsky recon osint <username|email|domain> <target>")
        return 2

    what, target = args[0], args[1]
    if what == "username":
        return username_lookup(target)
    if what == "email":
        return email_lookup(target)
    if what == "domain":
        return domain_lookup(target)
    print_err(f"unknown osint type: {what}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

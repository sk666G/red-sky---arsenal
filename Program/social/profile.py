# language: Python, file: Program/social/profile.py, target: Red Sky social — person profile
# Takes a starting identifier (name / email / phone / username) and pivots across
# public sources: username enumeration, email MX, phone carrier, Gravatar, HIBP-style
# local lookup against the csint index. Output is a merged dossier.

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


PLATFORMS = {
    "github":     "https://github.com/{}",
    "gitlab":     "https://gitlab.com/{}",
    "twitter":    "https://twitter.com/{}",
    "x":          "https://x.com/{}",
    "instagram":  "https://instagram.com/{}",
    "tiktok":     "https://tiktok.com/@{}",
    "reddit":     "https://reddit.com/user/{}",
    "twitch":     "https://twitch.tv/{}",
    "youtube":    "https://youtube.com/@{}",
    "telegram":   "https://t.me/{}",
    "linkedin":   "https://linkedin.com/in/{}",
    "pinterest":  "https://pinterest.com/{}",
    "medium":     "https://medium.com/@{}",
    "hackernews": "https://news.ycombinator.com/user?id={}",
    "keybase":    "https://keybase.io/{}",
    "patreon":    "https://patreon.com/{}",
    "soundcloud": "https://soundcloud.com/{}",
    "spotify":    "https://open.spotify.com/user/{}",
    "snapchat":   "https://snapchat.com/add/{}",
    "steam":      "https://steamcommunity.com/id/{}",
    "roblox":     "https://www.roblox.com/user.aspx?username={}",
}


def _http_get(url: str, timeout: int = 8):
    try:
        return requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                            allow_redirects=True)
    except requests.RequestException:
        return None


def _is_email(s: str) -> bool:
    return "@" in s and "." in s.split("@", 1)[1]


def _is_phone(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    return 7 <= len(digits) <= 15


def _is_username(s: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9_.\-]{2,32}$", s)) and "@" not in s


def _is_name(s: str) -> bool:
    parts = s.split()
    return 2 <= len(parts) <= 4 and all(p[0:1].isalpha() for p in parts if p)


def username_scan(username: str) -> List[Dict]:
    hits = []
    for platform, tpl in PLATFORMS.items():
        url = tpl.format(username)
        r = _http_get(url, timeout=8)
        if not r:
            continue
        if r.status_code == 200:
            hits.append({"platform": platform, "url": url, "status": 200})
            print_ok(f"{platform:<12} {url}")
        elif r.status_code in (301, 302) and username.lower() in r.url.lower():
            hits.append({"platform": platform, "url": r.url, "status": r.status_code})
            print_ok(f"{platform:<12} {r.url}  (redirect)")
    return hits


def email_pivot(email: str) -> Dict:
    result = {"email": email}
    local, domain = email.split("@", 1)
    result["local"] = local
    result["domain"] = domain

    # MX
    try:
        import dns.resolver
        mx = [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX")]
        result["mx"] = mx
        if mx:
            print_ok(f"MX: {', '.join(mx[:3])}")
    except Exception:
        result["mx"] = []

    # Gravatar
    import hashlib
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    grav = f"https://www.gravatar.com/avatar/{h}"
    r = _http_get(grav + "?d=404", timeout=8)
    if r and r.status_code == 200:
        result["gravatar"] = grav
        print_ok(f"gravatar: {grav}")

    # HIBP
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                         headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            breaches = [b["Name"] for b in r.json()]
            result["hibp"] = breaches
            print_ok(f"HIBP: {len(breaches)} breach(es) — {', '.join(breaches[:5])}")
        elif r.status_code == 404:
            result["hibp"] = []
            print_info("HIBP: no breaches")
        elif r.status_code == 401:
            result["hibp"] = "needs-api-key"
    except requests.RequestException:
        pass

    return result


def phone_pivot(phone: str) -> Dict:
    digits = re.sub(r"\D", "", phone)
    result = {"phone": phone, "digits": digits}
    # crude country code guess
    cc_map = {
        "1": "US/CA", "44": "UK", "33": "FR", "49": "DE", "39": "IT",
        "34": "ES", "31": "NL", "32": "BE", "41": "CH", "43": "AT",
        "48": "PL", "7": "RU", "81": "JP", "82": "KR", "86": "CN",
        "91": "IN", "55": "BR", "61": "AU",
    }
    for cc_len in (1, 2):
        prefix = digits[:cc_len]
        if prefix in cc_map:
            result["country"] = cc_map[prefix]
            result["country_code"] = prefix
            break
    return result


def name_pivot(name: str) -> Dict:
    """Given a name, try a few common email patterns and username derivations."""
    parts = [p.strip().lower() for p in name.split() if p.strip()]
    if len(parts) < 2:
        return {"name": name, "candidates": []}
    first, last = parts[0], parts[-1]
    result = {
        "name": name,
        "parts": {"first": first, "last": last},
        "email_candidates": [
            f"{first}.{last}@gmail.com",
            f"{first}{last}@gmail.com",
            f"{first[0]}{last}@gmail.com",
            f"{first}@{last}.com",
        ],
        "username_candidates": [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first[0]}{last}",
            f"{first}_{last}",
        ],
    }
    return result


def cmd_profile(target: str, deep: bool = False) -> int:
    SOCIAL_DIR.mkdir(parents=True, exist_ok=True)
    print_info(f"building profile for: {target}")
    print()

    dossier: Dict = {"target": target, "ts": int(time.time())}

    if _is_email(target):
        print(f"{ARTERY}{BOLD}── email pivot{RESET}")
        dossier["email"] = email_pivot(target)
        local = target.split("@", 1)[0]
        if deep:
            print()
            print(f"{ARTERY}{BOLD}── username scan ({local}){RESET}")
            dossier["username_hits"] = username_scan(local)
    elif _is_phone(target):
        print(f"{ARTERY}{BOLD}── phone pivot{RESET}")
        dossier["phone"] = phone_pivot(target)
    elif _is_name(target):
        print(f"{ARTERY}{BOLD}── name pivot{RESET}")
        dossier["name_pivot"] = name_pivot(target)
        for c in dossier["name_pivot"]["email_candidates"]:
            print(f"  {ARTERY}▓{RESET} {BONE}{c}{RESET}")
        print()
        print(f"{ARTERY}{BOLD}  username candidates{RESET}")
        for c in dossier["name_pivot"]["username_candidates"]:
            print(f"  {ARTERY}▓{RESET} {BONE}{c}{RESET}")
        if deep:
            print()
            print(f"{ARTERY}{BOLD}── scanning top candidate across platforms{RESET}")
            dossier["username_hits"] = username_scan(
                dossier["name_pivot"]["username_candidates"][0])
    elif _is_username(target):
        print(f"{ARTERY}{BOLD}── username scan{RESET}")
        dossier["username_hits"] = username_scan(target)
    else:
        print_err(f"unrecognized target: {target}")
        print_info("accepts: email, phone, name (First Last), username")
        return 1

    # cross-reference against local csint index
    try:
        from Program.csint.breach_query import DB_FILE as CSINT_DB
        if CSINT_DB.exists() and _is_email(target):
            import sqlite3
            db = sqlite3.connect(str(CSINT_DB))
            rows = db.execute(
                "SELECT password, source FROM creds WHERE email = ? LIMIT 20",
                (target.lower(),)
            ).fetchall()
            db.close()
            if rows:
                dossier["csint_hits"] = [{"password": p, "source": s} for p, s in rows]
                print()
                print(f"{SCARLET}{BOLD}── csint local hits{RESET}")
                for p, s in rows:
                    print(f"  {ARTERY}▓{RESET} {BONE}{p:<32}{RESET} {ASH}{s}{RESET}")
    except Exception:
        pass

    out = SOCIAL_DIR / f"dossier_{re.sub(r'[^A-Za-z0-9]', '_', target)}.json"
    out.write_text(json.dumps(dossier, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky social profile <email|phone|name|username> [--deep]")
        return 2
    return cmd_profile(args[0], deep="--deep" in args)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

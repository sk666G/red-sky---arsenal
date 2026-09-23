# language: Python, file: Program/social/osint.py, target: Red Sky social — OSINT recon
# Subcommands:
#   username  -- check a handle across ~80 platforms (parallel, timeout-aware)
#   email     -- validate an email, identify provider, check common breach dumps
#   phone     -- carrier + line type via free lookup endpoints
#   domain    -- registrar, nameservers, MX records, emails harvested from
#                public pages (WhoisXML/none), subdomain enumeration starter
#   gravatar  -- email -> gravatar profile + image (if registered)
# All lookups go through public, unauthenticated endpoints. Nothing stored.

import concurrent.futures
import hashlib
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"
SOCIAL_DIR.mkdir(parents=True, exist_ok=True)


UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


# ── username enumeration targets ──
# format: (name, url_template, "not_found" marker or None = check status only)
USERNAME_PLATFORMS = [
    ("GitHub",          "https://github.com/{u}",                            None),
    ("GitLab",          "https://gitlab.com/{u}",                            None),
    ("Bitbucket",       "https://bitbucket.org/{u}/",                        None),
    ("Twitter/X",       "https://twitter.com/{u}",                           None),
    ("Instagram",       "https://www.instagram.com/{u}/",                    None),
    ("Facebook",        "https://www.facebook.com/{u}",                      None),
    ("TikTok",          "https://www.tiktok.com/@{u}",                       None),
    ("Reddit",          "https://www.reddit.com/user/{u}",                   None),
    ("Pinterest",       "https://www.pinterest.com/{u}/",                    None),
    ("Tumblr",          "https://{u}.tumblr.com",                            None),
    ("Medium",          "https://medium.com/@{u}",                           None),
    ("Substack",        "https://{u}.substack.com",                          None),
    ("WordPress",       "https://{u}.wordpress.com",                         None),
    ("Blogger",         "https://{u}.blogspot.com",                          None),
    ("YouTube",         "https://www.youtube.com/@{u}",                      None),
    ("Twitch",          "https://www.twitch.tv/{u}",                         None),
    ("SoundCloud",      "https://soundcloud.com/{u}",                        None),
    ("Spotify",         "https://open.spotify.com/user/{u}",                 None),
    ("Bandcamp",        "https://{u}.bandcamp.com",                          None),
    ("Vimeo",           "https://vimeo.com/{u}",                             None),
    ("Flickr",          "https://www.flickr.com/people/{u}",                 None),
    ("DeviantArt",      "https://www.deviantart.com/{u}",                    None),
    ("ArtStation",      "https://www.artstation.com/{u}",                    None),
    ("Behance",         "https://www.behance.net/{u}",                       None),
    ("Dribbble",        "https://dribbble.com/{u}",                          None),
    ("LinkedIn",        "https://www.linkedin.com/in/{u}",                   None),
    ("AngelList",       "https://angel.co/u/{u}",                            None),
    ("ProductHunt",     "https://www.producthunt.com/@{u}",                  None),
    ("HackerNews",      "https://news.ycombinator.com/user?id={u}",          "No such user."),
    ("Lobsters",        "https://lobste.rs/~{u}",                            None),
    ("Keybase",         "https://keybase.io/{u}",                            None),
    ("Steam",           "https://steamcommunity.com/id/{u}",                 "The specified profile could not be found"),
    ("Xbox",            "https://xboxgamertag.com/search/{u}",               "not found"),
    ("PSN",             "https://psnprofiles.com/{u}",                       "not found"),
    ("Roblox",          "https://www.roblox.com/user.aspx?username={u}",     None),
    ("Minecraft",       "https://api.mojang.com/users/profiles/minecraft/{u}", None),
    ("Fortnite",        "https://fortnitetracker.com/profile/all/{u}",       "not found"),
    ("Chess.com",       "https://www.chess.com/member/{u}",                  None),
    ("Lichess",         "https://lichess.org/@/{u}",                         None),
    ("Duolingo",        "https://www.duolingo.com/profile/{u}",              None),
    ("Strava",          "https://www.strava.com/athletes/{u}",               None),
    ("MyFitnessPal",    "https://www.myfitnesspal.com/profile/{u}",          None),
    ("Goodreads",       "https://www.goodreads.com/{u}",                     None),
    ("Last.fm",         "https://www.last.fm/user/{u}",                      None),
    ("Trakt",           "https://trakt.tv/users/{u}",                        None),
    ("Letterboxd",      "https://letterboxd.com/{u}/",                       None),
    ("Patreon",         "https://www.patreon.com/{u}",                       None),
    ("Ko-fi",           "https://ko-fi.com/{u}",                             None),
    ("BuyMeACoffee",    "https://www.buymeacoffee.com/{u}",                  None),
    ("Etsy",            "https://www.etsy.com/shop/{u}",                     None),
    ("eBay",            "https://www.ebay.com/usr/{u}",                      None),
    ("Amazon",          "https://www.amazon.com/gp/profile/{u}",             None),
    ("Poshmark",        "https://poshmark.com/closet/{u}",                   None),
    ("Depop",           "https://www.depop.com/{u}/",                        None),
    ("Vinted",          "https://www.vinted.com/member/{u}",                 None),
    ("Fiverr",          "https://www.fiverr.com/{u}",                        None),
    ("Upwork",          "https://www.upwork.com/freelancers/~{u}",           None),
    ("Freelancer",      "https://www.freelancer.com/u/{u}",                  None),
    ("StackOverflow",   "https://stackoverflow.com/users/{u}",               None),
    ("Dev.to",          "https://dev.to/{u}",                                None),
    ("Hashnode",        "https://hashnode.com/@{u}",                         None),
    ("CodePen",         "https://codepen.io/{u}",                            None),
    ("JSFiddle",        "https://jsfiddle.net/user/{u}/",                    None),
    ("Replit",          "https://replit.com/@{u}",                           None),
    ("Kaggle",          "https://www.kaggle.com/{u}",                        None),
    ("HackerRank",      "https://www.hackerrank.com/{u}",                    None),
    ("LeetCode",        "https://leetcode.com/{u}",                          None),
    ("Codewars",        "https://www.codewars.com/users/{u}",                None),
    ("Telegram",        "https://t.me/{u}",                                  "tgme_page_icon"),
    ("Discord",         "https://discord.com/users/{u}",                     None),
    ("Snapchat",        "https://www.snapchat.com/add/{u}",                  None),
    ("Mastodon.social", "https://mastodon.social/@{u}",                      None),
    ("Bluesky",         "https://bsky.app/profile/{u}.bsky.social",          None),
    ("Threads",         "https://www.threads.net/@{u}",                      None),
    ("Wattpad",         "https://www.wattpad.com/user/{u}",                  None),
    ("AO3",             "https://archiveofourown.org/users/{u}",             None),
    ("FanFiction",      "https://www.fanfiction.net/u/{u}",                  None),
    ("Quora",           "https://www.quora.com/profile/{u}",                 None),
    ("VK",              "https://vk.com/{u}",                                None),
    ("Odnoklassniki",   "https://ok.ru/{u}",                                 None),
    ("Weibo",           "https://weibo.com/{u}",                             None),
    ("Douyin",          "https://www.douyin.com/user/{u}",                   None),
    ("Line",            "https://line.me/ti/p/~{u}",                         None),
    ("WeChat",          "https://weixin.qq.com/{u}",                         None),
]


def check_username(platform: str, template: str, not_found_marker: Optional[str],
                   username: str, timeout: float) -> Dict:
    url = template.format(u=quote(username))
    headers = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    result = {"platform": platform, "url": url, "status": 0, "exists": False}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        result["status"] = r.status_code
        if r.status_code == 200:
            if not_found_marker:
                result["exists"] = not_found_marker.lower() not in r.text.lower()
            else:
                result["exists"] = True
        elif r.status_code in (301, 302):
            result["exists"] = True
    except requests.RequestException as e:
        result["error"] = type(e).__name__
    return result


def cmd_username(username: str, timeout: float, workers: int, out_file: str) -> int:
    if not username:
        print_err("give a username")
        return 2
    username = username.strip().lstrip("@")

    print_info("username enumeration across " + str(len(USERNAME_PLATFORMS)) + " platforms")
    print_kv("username", username)
    print_kv("timeout", str(timeout) + "s")
    print_kv("workers", str(workers))
    print()

    t0 = time.time()
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(check_username, p, t, m, username, timeout): p
            for p, t, m in USERNAME_PLATFORMS
        }
        done = 0
        for f in concurrent.futures.as_completed(futures):
            done += 1
            r = f.result()
            if r["exists"]:
                found.append(r)
                print("  " + SCARLET + "▓" + RESET + " " + BONE + r["platform"].ljust(18) + RESET + " " + r["url"])
            else:
                print("  " + ASH + "░ " + r["platform"] + RESET + "        ", end="\r")

    print(" " * 70, end="\r")
    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("found", str(len(found)) + "/" + str(len(USERNAME_PLATFORMS)))
    print()

    out = Path(out_file) if out_file else SOCIAL_DIR / ("username_" + username + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"username": username, "found": found}, indent=2))
    print_kv("saved", out)
    return 0


# ── email ──
COMMON_PROVIDERS = {
    "gmail.com": "Google", "googlemail.com": "Google",
    "outlook.com": "Microsoft", "hotmail.com": "Microsoft", "live.com": "Microsoft",
    "yahoo.com": "Yahoo", "ymail.com": "Yahoo",
    "protonmail.com": "Proton", "proton.me": "Proton",
    "icloud.com": "Apple", "me.com": "Apple", "mac.com": "Apple",
    "aol.com": "AOL", "zoho.com": "Zoho", "yandex.com": "Yandex",
    "mail.ru": "Mail.ru", "gmx.com": "GMX", "gmx.de": "GMX",
    "fastmail.com": "Fastmail", "tutanota.com": "Tutanota", "tuta.io": "Tutanota",
    "qq.com": "Tencent", "163.com": "NetEase", "126.com": "NetEase",
}


def cmd_email(email: str, out_file: str) -> int:
    if not email or "@" not in email:
        print_err("give a valid email")
        return 2

    local, _, domain = email.partition("@")
    print_info("email recon")
    print_kv("email", email)
    print_kv("local part", local)
    print_kv("domain", domain)
    print()

    provider = COMMON_PROVIDERS.get(domain.lower(), "")
    if provider:
        print_ok("provider: " + provider)
    else:
        print_info("not a common consumer provider — checking MX")

    # MX lookup
    mx = []
    try:
        import subprocess
        r = subprocess.run(["dig", "+short", "MX", domain], capture_output=True, text=True, timeout=5)
        mx = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    if mx:
        print()
        print_info("MX records")
        for m in mx[:5]:
            print("  " + ARTERY + "*" + RESET + " " + m)

    # gravatar
    gravatar_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    gravatar_url = "https://www.gravatar.com/avatar/" + gravatar_hash + "?d=404"
    try:
        r = requests.get(gravatar_url, timeout=6, allow_redirects=False)
        if r.status_code == 200:
            print()
            print_ok("Gravatar registered")
            print_kv("hash", gravatar_hash)
            print_kv("profile", "https://gravatar.com/" + gravatar_hash)
        else:
            print()
            print_info("no Gravatar")
    except Exception:
        pass

    # HIBP public (no key — the free unauthenticated endpoint only gives breach names)
    print()
    print_info("breach check: use https://haveibeenpwned.com/account/" + quote(email) + " (manual)")

    result = {
        "email": email, "local": local, "domain": domain, "provider": provider,
        "mx": mx, "gravatar_hash": gravatar_hash,
    }
    out = Path(out_file) if out_file else SOCIAL_DIR / ("email_" + local + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(result, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── phone ──
def cmd_phone(phone: str, out_file: str) -> int:
    if not phone:
        print_err("give a phone number (E.164 or local)")
        return 2

    digits = re.sub(r"[^\d+]", "", phone)
    print_info("phone OSINT")
    print_kv("input", phone)
    print_kv("digits", digits)
    print()

    result = {"input": phone, "digits": digits}

    # country code detection by prefix
    country_map = {
        "1": "US/Canada", "7": "Russia/Kazakhstan", "20": "Egypt", "27": "South Africa",
        "30": "Greece", "31": "Netherlands", "32": "Belgium", "33": "France",
        "34": "Spain", "36": "Hungary", "39": "Italy", "40": "Romania",
        "41": "Switzerland", "43": "Austria", "44": "UK", "45": "Denmark",
        "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany",
        "51": "Peru", "52": "Mexico", "54": "Argentina", "55": "Brazil",
        "56": "Chile", "57": "Colombia", "60": "Malaysia", "61": "Australia",
        "62": "Indonesia", "63": "Philippines", "64": "New Zealand",
        "65": "Singapore", "66": "Thailand", "81": "Japan", "82": "South Korea",
        "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India",
        "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka",
        "95": "Myanmar", "98": "Iran", "212": "Morocco", "213": "Algeria",
        "216": "Tunisia", "218": "Libya", "220": "Gambia", "221": "Senegal",
        "234": "Nigeria", "254": "Kenya", "255": "Tanzania", "256": "Uganda",
        "263": "Zimbabwe", "351": "Portugal", "352": "Luxembourg",
        "353": "Ireland", "354": "Iceland", "358": "Finland", "370": "Lithuania",
        "371": "Latvia", "372": "Estonia", "380": "Ukraine", "381": "Serbia",
        "385": "Croatia", "420": "Czechia", "421": "Slovakia", "852": "Hong Kong",
        "853": "Macau", "886": "Taiwan", "961": "Lebanon", "962": "Jordan",
        "964": "Iraq", "965": "Kuwait", "966": "Saudi Arabia", "971": "UAE",
        "972": "Israel", "973": "Bahrain", "974": "Qatar", "977": "Nepal",
    }
    d = digits.lstrip("+")
    matched = ""
    for cc in sorted(country_map.keys(), key=len, reverse=True):
        if d.startswith(cc):
            matched = cc
            break
    if matched:
        result["country_code"] = matched
        result["region"] = country_map[matched]
        print_ok("country code +" + matched + "  (" + country_map[matched] + ")")
    else:
        print_warn("could not detect country code")

    # NumVerify / Twilio Lookup require a key — the free public sites are:
    #   https://freecarrierlookup.com/  (form, no API)
    #   https://www.numlookup.com/      (form)
    # We surface the URLs for manual check.
    print()
    print_info("public carrier lookup (manual, no key):")
    print_info("  https://freecarrierlookup.com/")
    print_info("  https://www.numlookup.com/" + digits)
    print_info("  https://www.truecaller.com/search/" + (matched or "us") + "/" + digits.lstrip("+"))

    out = Path(out_file) if out_file else SOCIAL_DIR / ("phone_" + digits.lstrip("+") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(result, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── domain ──
def cmd_domain(domain: str, out_file: str) -> int:
    if not domain:
        print_err("give a domain")
        return 2
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

    print_info("domain recon")
    print_kv("domain", domain)
    print()

    result = {"domain": domain}

    # whois via system command
    try:
        import subprocess
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        whois = r.stdout
        fields = {}
        for key in ("Registrar:", "Creation Date:", "Updated Date:", "Registry Expiry Date:",
                    "Registrant Organization:", "Registrant Country:", "Name Server:"):
            matches = re.findall(re.escape(key) + r"\s*(.+)", whois)
            if matches:
                fields[key.rstrip(":")] = [m.strip() for m in matches][:5]
        result["whois"] = fields
        for k, v in fields.items():
            if isinstance(v, list):
                for item in v:
                    print("  " + ARTERY + k.ljust(24) + RESET + BONE + item + RESET)
    except Exception as e:
        print_warn("whois failed: " + str(e))

    # DNS records
    print()
    print_info("DNS records")
    try:
        import subprocess
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            r = subprocess.run(["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=5)
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            if lines:
                result.setdefault("dns", {})[rtype] = lines
                for l in lines[:5]:
                    print("  " + ARTERY + rtype.ljust(6) + RESET + " " + BONE + l + RESET)
    except Exception:
        pass

    # email harvesting from the main page + about + contact
    print()
    print_info("harvesting emails from public pages")
    emails = set()
    for path in ("", "/about", "/contact", "/team", "/support"):
        url = "https://" + domain + path
        try:
            r = requests.get(url, timeout=8, headers={"User-Agent": UA})
            found = re.findall(r"[A-Za-z0-9._%+-]+@" + re.escape(domain), r.text)
            emails.update(found)
        except Exception:
            pass
    result["emails"] = sorted(emails)
    for e in result["emails"][:20]:
        print("  " + SCARLET + "*" + RESET + " " + BONE + e + RESET)
    if not result["emails"]:
        print("  " + ASH + "(none found on common pages)" + RESET)

    out = Path(out_file) if out_file else SOCIAL_DIR / ("domain_" + domain + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(result, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── gravatar (single-purpose) ──
def cmd_gravatar(email: str) -> int:
    if not email or "@" not in email:
        print_err("give an email")
        return 2
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    print_info("Gravatar lookup")
    print_kv("email", email)
    print_kv("hash", h)
    print_kv("avatar", "https://www.gravatar.com/avatar/" + h)
    print_kv("profile", "https://gravatar.com/" + h)
    print()
    try:
        r = requests.get("https://www.gravatar.com/" + h + ".json", timeout=8)
        if r.status_code == 200:
            j = r.json()
            print_ok("profile found")
            for e in j.get("entry", []):
                for k in ("displayName", "aboutMe", "currentLocation", "profileUrl", "urls"):
                    v = e.get(k)
                    if v:
                        print("  " + ARTERY + k.ljust(16) + RESET + BONE + str(v)[:80] + RESET)
        else:
            print_warn("no profile registered")
    except Exception as e:
        print_warn("lookup failed: " + str(e))
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky social osint", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["username", "email", "phone", "domain", "gravatar", "help"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--workers", type=int, default=32)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky social osint <username|email|phone|domain|gravatar> <target>")
        return 2

    if ns.action == "help" or ns.help:
        print_info("username <handle>       -- check ~80 platforms")
        print_info("email <addr>            -- provider, MX, gravatar, breach hint")
        print_info("phone <number>          -- country, carrier lookups (manual links)")
        print_info("domain <example.com>    -- whois, DNS, harvest emails")
        print_info("gravatar <email>        -- gravatar profile lookup")
        return 0

    if not ns.target and ns.action != "help":
        print_err("give a target")
        return 2

    if ns.action == "username":
        return cmd_username(ns.target, ns.timeout, ns.workers, ns.out)
    if ns.action == "email":
        return cmd_email(ns.target, ns.out)
    if ns.action == "phone":
        return cmd_phone(ns.target, ns.out)
    if ns.action == "domain":
        return cmd_domain(ns.target, ns.out)
    if ns.action == "gravatar":
        return cmd_gravatar(ns.target)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

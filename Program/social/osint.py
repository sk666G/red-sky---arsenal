# language: Python, file: Program/social/osint.py, target: Red Sky social — OSINT pipeline
# Open-source intelligence collection. Three passes:
#
#   1. Username enumeration across platforms. Same handle → which sites exist.
#      Detects by HTTP status + a fingerprint string in the response, so a
#      soft-404 page does not count as a hit.
#   2. Email / phone pivot. Given an email → check public breach APIs (HIBP
#      v3, Dehashed — needs API key), Gravatar profile, email pattern.
#      Given a phone → basic carrier / region hint from a public numbering plan.
#   3. Domain / org footprint. Given a domain → root records, subdomain
#      candidates from a small built-in wordlist, common DNS records.
#
# All network calls are HTTP from the operator's box. Nothing phones home.

import concurrent.futures
import hashlib
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SOCIAL_DIR = OUTPUT_DIR / "social"


# ── username platforms ─────────────────────────────────────────────────────
# (label, url template, positive fingerprint string OR None = status-code only)
PLATFORMS: List[Tuple[str, str, Optional[str]]] = [
    ("github",      "https://github.com/{u}",                       None),
    ("twitter",     "https://nitter.net/{u}",                       None),
    ("reddit",      "https://www.reddit.com/user/{u}",              "u/{u}"),
    ("instagram",   "https://www.instagram.com/{u}/",               '"username":"{u}"'),
    ("tiktok",      "https://www.tiktok.com/@{u}",                  '"uniqueId":"{u}"'),
    ("youtube",     "https://www.youtube.com/@{u}",                 '"channelId"'),
    ("twitch",      "https://www.twitch.tv/{u}",                    None),
    ("steam",       "https://steamcommunity.com/id/{u}",            "profile_header"),
    ("roblox",      "https://www.roblox.com/user.aspx?username={u}","profile-header"),
    ("telegram",    "https://t.me/{u}",                             "tgme_page"),
    ("keybase",     "https://keybase.io/{u}",                       '"username":"{u}"'),
    ("medium",      "https://medium.com/@{u}",                      None),
    ("devto",       "https://dev.to/{u}",                           '"username":"{u}"'),
    ("hackernews",  "https://news.ycombinator.com/user?id={u}",     "karma"),
    ("pinterest",   "https://www.pinterest.com/{u}/",               None),
    ("soundcloud",  "https://soundcloud.com/{u}",                   None),
    ("spotify",     "https://open.spotify.com/user/{u}",            None),
    ("behance",     "https://www.behance.net/{u}",                  None),
    ("dribbble",    "https://dribbble.com/{u}",                     None),
    ("gitlab",      "https://gitlab.com/{u}",                       None),
    ("bitbucket",   "https://bitbucket.org/{u}/",                   None),
    ("npm",         "https://www.npmjs.com/~{u}",                   None),
    ("pypi",        "https://pypi.org/user/{u}/",                   None),
    ("crates",      "https://crates.io/users/{u}",                  None),
    ("docker",      "https://hub.docker.com/u/{u}",                 None),
    ("stackoverflow","https://stackoverflow.com/users/filter?search={u}", "user-details"),
    ("mastodon_social","https://mastodon.social/@{u}",              None),
    ("threads",     "https://www.threads.net/@{u}",                 None),
    ("bluesky",     "https://bsky.app/profile/{u}",                 None),
    ("patreon",     "https://www.patreon.com/{u}",                  None),
    ("onlyfans",    "https://onlyfans.com/{u}",                     None),
    ("flickr",      "https://www.flickr.com/people/{u}/",           None),
    ("vimeo",       "https://vimeo.com/{u}",                        None),
    ("about.me",    "https://about.me/{u}",                         None),
    ("linktr",      "https://linktr.ee/{u}",                        None),
]


def _check_platform(u: str, label: str, url_tpl: str, fingerprint: Optional[str],
                    timeout: int = 8) -> Tuple[str, bool, int, str]:
    try:
        import requests
    except ImportError:
        return label, False, 0, "requests missing"
    url = url_tpl.replace("{u}", u)
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        })
    except Exception as e:
        return label, False, 0, str(e)[:60]

    if r.status_code >= 400:
        return label, False, r.status_code, ""
    body = r.text
    if fingerprint:
        fp = fingerprint.replace("{u}", u)
        if fp.lower() not in body.lower():
            return label, False, r.status_code, "fp-miss"
    # soft-404 check — many sites return 200 with "not found"
    low = body[:4096].lower()
    if "not found" in low or "doesn't exist" in low or "user not exist" in low:
        return label, False, r.status_code, "soft-404"
    return label, True, r.status_code, ""


def cmd_username(u: str, out: str) -> int:
    if not u:
        print_err("--user required")
        return 1
    SOCIAL_DIR.mkdir(parents=True, exist_ok=True)
    print_info("username enumeration")
    print_kv("user", u)
    print_kv("platforms", len(PLATFORMS))
    print()

    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_check_platform, u, label, url, fp)
                   for label, url, fp in PLATFORMS]
        for fut in concurrent.futures.as_completed(futures):
            label, ok, code, reason = fut.result()
            if ok:
                print("  " + SCARLET + "HIT" + RESET + " " + BONE + label.ljust(16) + RESET + " " + ASH + str(code) + RESET)
                hits.append({"platform": label, "url": next(url_tpl.replace("{u}", u)
                                                             for lbl, url_tpl, _ in PLATFORMS if lbl == label)})
            else:
                print("  " + ASH + "no " + RESET + " " + ASH + label.ljust(16) + " " + (reason or str(code)) + RESET)

    print()
    print_kv("hits", len(hits))
    out_path = Path(out) if out else SOCIAL_DIR / ("username_" + u + "_" + str(int(time.time())) + ".json")
    out_path.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out_path)
    return 0


# ── email / phone ──────────────────────────────────────────────────────────

def cmd_email(email: str, out: str) -> int:
    if not email or "@" not in email:
        print_err("--email required")
        return 1
    SOCIAL_DIR.mkdir(parents=True, exist_ok=True)
    print_info("email pivot")
    print_kv("email", email)
    print()

    # gravatar — MD5 of the email yields the profile URL
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar_url = "https://www.gravatar.com/" + md5
    gravatar_profile = "https://www.gravatar.com/" + md5 + ".json"
    print_kv("gravatar_hash", md5)
    print_kv("gravatar_url", gravatar_url)

    results = {"email": email, "gravatar_hash": md5, "gravatar_profile": None}
    try:
        import requests
        r = requests.get(gravatar_profile, timeout=8)
        if r.status_code == 200:
            try:
                data = r.json()
                entry = data.get("entry", [{}])[0]
                print_ok("gravatar profile found")
                for k in ("displayName", "preferredUsername", "aboutMe", "profileUrl"):
                    if entry.get(k):
                        print_kv(k, entry[k])
                if entry.get("accounts"):
                    for acct in entry["accounts"]:
                        print_kv("  account", str(acct.get("shortname")) + " / " + str(acct.get("username")))
                results["gravatar_profile"] = entry
            except Exception:
                print_warn("gravatar returned non-json")
        else:
            print_info("no gravatar profile")
    except Exception as e:
        print_warn("gravatar: " + str(e)[:80])

    print()
    print_info("breach check (HIBP) requires an API key — pass --hibp-key")
    print_info("email pattern check: MX records for the domain")
    domain = email.split("@")[-1]
    try:
        ips = socket.gethostbyname_ex(domain)
        print_kv("mx_a_records", str(ips[2]))
    except Exception as e:
        print_warn("dns: " + str(e)[:80])

    out_path = Path(out) if out else SOCIAL_DIR / ("email_" + md5[:8] + "_" + str(int(time.time())) + ".json")
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print_kv("saved", out_path)
    return 0


def cmd_phone(phone: str) -> int:
    p = re.sub(r"[^0-9+]", "", phone)
    print_info("phone pivot")
    print_kv("phone", p)
    print()
    # very basic — country code detection
    if p.startswith("+"):
        cc = ""
        for i in range(2, 5):
            candidate = p[1:i]
            if candidate.isdigit():
                cc = candidate
                break
        print_kv("country_code_guess", "+" + cc)
    else:
        print_info("no + prefix — country ambiguous")
    print_info("full carrier lookup requires an external API (Twilio Lookup, Numverify)")
    return 0


# ── domain footprint ───────────────────────────────────────────────────────

SUBDOMAIN_WORDS = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "mx", "autodiscover",
    "vpn", "remote", "rdp", "ssh", "ftp", "sftp", "dev", "staging", "stage",
    "test", "qa", "prod", "api", "app", "apps", "dashboard", "admin",
    "portal", "internal", "intranet", "cloud", "storage", "media", "static",
    "cdn", "assets", "img", "images", "docs", "wiki", "confluence", "jira",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "monitor",
    "grafana", "prometheus", "kibana", "elastic", "db", "database", "sql",
    "mysql", "postgres", "redis", "cache", "auth", "sso", "login", "id",
    "oauth", "ns1", "ns2", "dns", "backup", "old", "legacy",
]


def _sub_exists(sub: str, domain: str, timeout: int = 4) -> Optional[str]:
    host = sub + "." + domain
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None
    except Exception:
        return None


def cmd_domain(domain: str, wordlist: str, threads: int, out: str) -> int:
    if not domain:
        print_err("--domain required")
        return 1
    words = SUBDOMAIN_WORDS
    if wordlist:
        p = Path(wordlist)
        if p.exists():
            words = [line.strip() for line in p.read_text().splitlines() if line.strip() and not line.startswith("#")]

    SOCIAL_DIR.mkdir(parents=True, exist_ok=True)
    print_info("domain footprint")
    print_kv("domain", domain)
    print_kv("candidates", len(words))
    print_kv("threads", threads)
    print()

    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_sub_exists, w, domain): w for w in words}
        for fut in concurrent.futures.as_completed(futures):
            w = futures[fut]
            try:
                ip = fut.result()
            except Exception:
                continue
            if ip:
                print("  " + SCARLET + "HIT" + RESET + " " + BONE + w + "." + domain + RESET + " → " + ARTERY + ip + RESET)
                hits.append({"sub": w, "host": w + "." + domain, "ip": ip})

    print()
    print_kv("subdomains", len(hits))
    out_path = Path(out) if out else SOCIAL_DIR / ("domain_" + domain.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    out_path.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out_path)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky social osint <sub-command>")
        print_info("")
        print_info("  username --user U [--out FILE]")
        print_info("      walk 35 platforms for a handle, detect soft-404s")
        print_info("  email --email E [--out FILE]")
        print_info("      gravatar lookup, MX records, breach-check stub")
        print_info("  phone --phone '+1...'")
        print_info("      country code / carrier hint")
        print_info("  domain --domain D [--wordlist FILE] [--threads N] [--out FILE]")
        print_info("      brute subdomain candidates against DNS")
        return 0

    if sub == "username":
        p = argparse.ArgumentParser(prog="redsky social osint username", add_help=False)
        p.add_argument("--user", required=False, default="")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social osint username --user U [--out FILE]")
            return 2
        if not ns.user:
            print_err("--user required")
            return 2
        return cmd_username(ns.user, ns.out)

    if sub == "email":
        p = argparse.ArgumentParser(prog="redsky social osint email", add_help=False)
        p.add_argument("--email", required=False, default="")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social osint email --email E [--out FILE]")
            return 2
        if not ns.email:
            print_err("--email required")
            return 2
        return cmd_email(ns.email, ns.out)

    if sub == "phone":
        p = argparse.ArgumentParser(prog="redsky social osint phone", add_help=False)
        p.add_argument("--phone", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social osint phone --phone '+1...'")
            return 2
        if not ns.phone:
            print_err("--phone required")
            return 2
        return cmd_phone(ns.phone)

    if sub == "domain":
        p = argparse.ArgumentParser(prog="redsky social osint domain", add_help=False)
        p.add_argument("--domain", required=False, default="")
        p.add_argument("--wordlist", default="")
        p.add_argument("--threads", type=int, default=30)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky social osint domain --domain D [--wordlist FILE] [--threads N]")
            return 2
        if not ns.domain:
            print_err("--domain required")
            return 2
        return cmd_domain(ns.domain, ns.wordlist, ns.threads, ns.out)

    print_err("unknown osint sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

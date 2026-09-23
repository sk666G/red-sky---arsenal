# language: Python, file: Program/crypto/hash_crack.py, target: Red Sky crypto — hash ID + attack planner
# Identifies a hash from its format/length/charset, maps it to hashcat -m and
# john --format, suggests the fastest attack (wordlist, rules, mask, combinator),
# and can generate a mask from the hash type. Also parses /etc/shadow-style
# composite hashes and Kerberos ticket hashes ($krb5asrep$, $krb5tgs$).

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CRYPTO_DIR = OUTPUT_DIR / "crypto"
HASH_DIR = CRYPTO_DIR / "hash"
HASH_DIR.mkdir(parents=True, exist_ok=True)


# ── hash database ──
# Each entry: name, regex or length+charset, hashcat mode, john format, notes
HASH_DB: List[Dict] = [
    # md5 / sha family
    {"name": "MD5",            "regex": r"^[a-f0-9]{32}$",            "hc": "0",     "john": "raw-md5",       "notes": "32 hex"},
    {"name": "MD5 (half)",     "regex": r"^[a-f0-9]{16}$",            "hc": "5100",  "john": "half-md5",      "notes": "16 hex"},
    {"name": "SHA-1",          "regex": r"^[a-f0-9]{40}$",            "hc": "100",   "john": "raw-sha1",      "notes": "40 hex"},
    {"name": "SHA-224",        "regex": r"^[a-f0-9]{56}$",            "hc": "1300",  "john": "raw-sha224",    "notes": "56 hex"},
    {"name": "SHA-256",        "regex": r"^[a-f0-9]{64}$",            "hc": "1400",  "john": "raw-sha256",    "notes": "64 hex"},
    {"name": "SHA-384",        "regex": r"^[a-f0-9]{96}$",            "hc": "10800", "john": "raw-sha384",    "notes": "96 hex"},
    {"name": "SHA-512",        "regex": r"^[a-f0-9]{128}$",           "hc": "1700",  "john": "raw-sha512",    "notes": "128 hex"},
    {"name": "SHA3-256",       "regex": r"^[a-f0-9]{64}$",            "hc": "17400", "john": "raw-sha3-256",  "notes": "same length as SHA-256"},
    {"name": "SHA3-512",       "regex": r"^[a-f0-9]{128}$",           "hc": "17600", "john": "raw-sha3-512",  "notes": "same length as SHA-512"},
    {"name": "BLAKE2b-256",    "regex": r"^[a-f0-9]{64}$",            "hc": "600",   "john": "raw-blake2b-256","notes": ""},
    {"name": "BLAKE2b-512",    "regex": r"^[a-f0-9]{128}$",           "hc": "610",   "john": "raw-blake2b-512","notes": ""},

    # base64-encoded (may be b64 of a binary hash)
    {"name": "MD5 (base64)",   "regex": r"^[A-Za-z0-9+/]{22}==$",     "hc": "0",     "john": "raw-md5",       "notes": "b64 of 16 bytes"},
    {"name": "SHA-1 (base64)", "regex": r"^[A-Za-z0-9+/]{27}=$",      "hc": "100",   "john": "raw-sha1",      "notes": "b64 of 20 bytes"},
    {"name": "SHA-256 (base64)","regex": r"^[A-Za-z0-9+/]{43}=$",     "hc": "1400",  "john": "raw-sha256",    "notes": "b64 of 32 bytes"},

    # bcrypt / scrypt / argon2
    {"name": "bcrypt",         "regex": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",  "hc": "3200",  "john": "bcrypt",    "notes": "Blowfish, $2a$/$2b$/$2y$ prefix"},
    {"name": "scrypt",         "regex": r"^\$7\$",                                  "hc": "8900",  "john": "scrypt",    "notes": "aix-style scrypt"},
    {"name": "argon2i",        "regex": r"^\$argon2i\$",                            "hc": "13300", "john": "argon2",    "notes": "argon2i"},
    {"name": "argon2id",       "regex": r"^\$argon2id\$",                           "hc": "13400", "john": "argon2",    "notes": "argon2id (default)"},

    # unix crypt / shadow
    {"name": "descrypt",       "regex": r"^[./A-Za-z0-9]{13}$",       "hc": "1500",  "john": "descrypt",   "notes": "classic 13-char crypt(3)"},
    {"name": "md5crypt",       "regex": r"^\$1\$",                    "hc": "500",   "john": "md5crypt",   "notes": "$1$"},
    {"name": "sha256crypt",    "regex": r"^\$5\$",                    "hc": "7400",  "john": "sha256crypt","notes": "$5$"},
    {"name": "sha512crypt",    "regex": r"^\$6\$",                    "hc": "1800",  "john": "sha512crypt","notes": "$6$ (default on modern Linux)"},
    {"name": "yescrypt",       "regex": r"^\$y\$",                    "hc": "15900", "john": "yescrypt",   "notes": "$y$ (Debian/Ubuntu default)"},

    # windows / AD
    {"name": "NTLM",           "regex": r"^[a-f0-9]{32}$",            "hc": "1000",  "john": "nt",         "notes": "same format as MD5 — try both"},
    {"name": "LM",             "regex": r"^[a-f0-9]{32}$",            "hc": "3000",  "john": "lm",         "notes": ""},
    {"name": "NetNTLMv1",      "regex": r"^[A-Za-z0-9+/=]+::[A-Za-z0-9+/=]+:[a-f0-9]+$",  "hc": "5500", "john": "netntlm", "notes": ""},
    {"name": "NetNTLMv2",      "regex": r"^[^:]+::[^:]+:[a-f0-9]+:[a-f0-9]+:[a-f0-9]+$", "hc": "5600", "john": "netntlmv2","notes": ""},
    {"name": "Kerberos AS-REP","regex": r"^\$krb5asrep\$",            "hc": "18200", "john": "krb5asrep",  "notes": "AS-REP roast"},
    {"name": "Kerberos TGS",   "regex": r"^\$krb5tgs\$",              "hc": "13100", "john": "krb5tgs",    "notes": "Kerberoast"},

    # hashes with prefixes
    {"name": "phpBB3",         "regex": r"^\$H\$",                    "hc": "400",   "john": "phpbb3",     "notes": ""},
    {"name": "Drupal7",        "regex": r"^\$S\$",                    "hc": "7900",  "john": "drupal7",    "notes": ""},
    {"name": "Joomla",         "regex": r"^[a-f0-9]{32}:[A-Za-z0-9]{32}$", "hc": "11", "john": "joomla",   "notes": ""},
    {"name": "WordPress",      "regex": r"^\$P\$",                    "hc": "400",   "john": "phpass",     "notes": "phpass portable"},
    {"name": "vBulletin",      "regex": r"^[a-f0-9]{32}:[a-f0-9]{3,}$", "hc": "2611", "john": "vbulletin", "notes": ""},

    # django / flask
    {"name": "Django (pbkdf2)","regex": r"^pbkdf2_sha256\$",          "hc": "10000", "john": "django",     "notes": ""},
    {"name": "Django (sha1)",  "regex": r"^sha1\$",                    "hc": "124",   "john": "django",     "notes": ""},
    {"name": "Werkzeug",       "regex": r"^pbkdf2:sha256:",            "hc": "10900", "john": "werkzeug",   "notes": "Flask default"},

    # database
    {"name": "MySQL 4.1+",     "regex": r"^\*[A-F0-9]{40}$",          "hc": "300",   "john": "mysql-sha1", "notes": "starts with *"},
    {"name": "MySQL <4.1",     "regex": r"^[a-f0-9]{16}$",            "hc": "200",   "john": "mysql",      "notes": "old"},
    {"name": "PostgreSQL",     "regex": r"^md5[a-f0-9]{32}$",         "hc": "12",    "john": "postgres",   "notes": "md5 prefix"},

    # misc
    {"name": "Cisco IOS",      "regex": r"^\$1\$[^$]*\$",             "hc": "500",   "john": "md5crypt",   "notes": "same as md5crypt"},
    {"name": "Cisco ASA",      "regex": r"^[A-Za-z0-9+/]{40,}$",      "hc": "9300",  "john": "asa",        "notes": ""},
    {"name": "APR1-MD5",       "regex": r"^\$apr1\$",                 "hc": "1600",  "john": "md5crypt",   "notes": "Apache htpasswd"},
]


def identify(h: str) -> List[Dict]:
    h = h.strip()
    hits = []
    for entry in HASH_DB:
        if entry.get("regex"):
            if re.match(entry["regex"], h):
                hits.append(entry)
        elif entry.get("len"):
            if len(h) == entry["len"] and re.match(r"^[a-f0-9]+$", h, re.I):
                hits.append(entry)
    return hits


def cmd_id(hash_str: str, out_file: str) -> int:
    h = hash_str.strip()
    if not h:
        print_err("give a hash string")
        return 2

    print_info("hash identification")
    print_kv("input", h[:100] + ("..." if len(h) > 100 else ""))
    print_kv("length", str(len(h)))
    print()

    hits = identify(h)
    if not hits:
        print_warn("no direct match in the database")
        print_info("try one of these tools for a second opinion:")
        print_info("  hashid -m " + h[:40] + "...")
        print_info("  haiti " + h[:40] + "...")
        return 1

    print_ok(str(len(hits)) + " match(es)")
    print()

    # rank: prefer most-specific (with prefix)
    hits_sorted = sorted(hits, key=lambda x: (not x.get("regex", "").startswith("^\\$"), x["name"]))
    for i, entry in enumerate(hits_sorted, 1):
        print(BOLD + SCARLET + str(i) + ". " + entry["name"] + RESET)
        print("   " + ASH + "hashcat:  " + RESET + BONE + "-m " + entry["hc"] + RESET)
        print("   " + ASH + "john:     " + RESET + BONE + "--format=" + entry["john"] + RESET)
        if entry.get("notes"):
            print("   " + ASH + "notes:    " + RESET + CLOT + entry["notes"] + RESET)
        print()

    out = Path(out_file) if out_file else HASH_DIR / ("id_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"hash": h, "matches": hits_sorted}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_plan(hash_str: str, wordlist: str, out_file: str) -> int:
    """Given a hash, produce the exact attack command chain."""
    h = hash_str.strip()
    if not h:
        print_err("give a hash")
        return 2

    hits = identify(h)
    if not hits:
        print_err("cannot identify hash")
        return 1
    entry = sorted(hits, key=lambda x: (not x.get("regex", "").startswith("^\\$"), x["name"]))[0]

    wordlist = wordlist or "/usr/share/wordlists/rockyou.txt"
    rules_dir = "/usr/share/hashcat/rules"

    print_info("attack plan for " + entry["name"])
    print_kv("hashcat mode", entry["hc"])
    print_kv("john format", entry["john"])
    print_kv("wordlist", wordlist)
    print()

    print(BOLD + "Stage 1: wordlist" + RESET)
    print("  hashcat -m " + entry["hc"] + " -a 0 " + h[:60] + "... " + wordlist)
    print()
    print(BOLD + "Stage 2: wordlist + best64 rules" + RESET)
    print("  hashcat -m " + entry["hc"] + " -a 0 -r " + rules_dir + "/best64.rule hash " + wordlist)
    print()
    print(BOLD + "Stage 3: wordlist + OneRuleToRuleThemAll" + RESET)
    print("  hashcat -m " + entry["hc"] + " -a 0 -r " + rules_dir + "/OneRuleToRuleThemAll.rule hash " + wordlist)
    print()

    # mask suggestion per hash type
    mask_map = {
        "NTLM":       "?u?l?l?l?l?l?d?d",
        "MD5":        "?u?l?l?l?l?l?d?d",
        "SHA-256":    "?u?l?l?l?l?l?d?d",
        "bcrypt":     "?u?l?l?l?l?l?d?d",
        "sha512crypt": "?u?l?l?l?l?l?d?d",
        "Kerberos TGS": "?u?l?l?l?l?l?d?d",
    }
    mask = mask_map.get(entry["name"], "?u?l?l?l?l?l?d?d")
    print(BOLD + "Stage 4: mask (brute force last resort)" + RESET)
    print("  hashcat -m " + entry["hc"] + " -a 3 hash '" + mask + "'")
    print()

    print(BOLD + "Stage 5: combinator with common suffixes" + RESET)
    print("  hashcat -m " + entry["hc"] + " -a 1 hash " + wordlist + " digits.txt")
    print()

    plan = {
        "hash": h,
        "identified_as": entry["name"],
        "hashcat_mode": entry["hc"],
        "john_format": entry["john"],
        "stages": [
            {"name": "wordlist", "cmd": "hashcat -m " + entry["hc"] + " -a 0 HASH " + wordlist},
            {"name": "best64",   "cmd": "hashcat -m " + entry["hc"] + " -a 0 -r " + rules_dir + "/best64.rule HASH " + wordlist},
            {"name": "onerule",  "cmd": "hashcat -m " + entry["hc"] + " -a 0 -r " + rules_dir + "/OneRuleToRuleThemAll.rule HASH " + wordlist},
            {"name": "mask",     "cmd": "hashcat -m " + entry["hc"] + " -a 3 HASH " + mask},
        ],
    }
    out = Path(out_file) if out_file else HASH_DIR / ("plan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(plan, indent=2))
    print_kv("saved", out)
    return 0


def cmd_shadow(shadow_path: str, out_file: str) -> int:
    """Parse /etc/shadow-style file, identify each hash, emit an unshadowed file
    and per-hash attack commands."""
    p = Path(shadow_path).expanduser()
    if not p.exists():
        print_err("file not found: " + str(p))
        return 1

    print_info("shadow file analysis")
    print()

    findings = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user = parts[0]
        h = parts[1]
        if not h or h in ("*", "!", "!!", "x", "NP"):
            print("  " + ASH + user.ljust(20) + " (no hash)" + RESET)
            continue

        hits = identify(h)
        if not hits:
            print("  " + ARTERY + user.ljust(20) + RESET + " (unrecognized: " + h[:20] + "...)")
            findings.append({"user": user, "hash": h, "identified": "unknown"})
            continue

        entry = sorted(hits, key=lambda x: (not x.get("regex", "").startswith("^\\$"), x["name"]))[0]
        print("  " + SCARLET + "▓ " + RESET + BONE + user.ljust(20) + RESET
              + ARTERY + entry["name"] + RESET
              + "  " + ASH + "(-m " + entry["hc"] + ")" + RESET)
        findings.append({
            "user": user,
            "hash": h,
            "identified": entry["name"],
            "hashcat": entry["hc"],
            "john": entry["john"],
        })

    out = Path(out_file) if out_file else HASH_DIR / ("shadow_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(findings, indent=2))
    print()
    print_kv("users", len(findings))
    print_kv("saved", out)
    return 0


def cmd_db(out_file: str) -> int:
    print_info(str(len(HASH_DB)) + " hash types in database")
    print()
    for entry in HASH_DB:
        print("  " + BONE + entry["name"].ljust(22) + RESET
              + ASH + "-m " + entry["hc"].ljust(8) + RESET
              + CLOT + entry.get("notes", "")[:60] + RESET)

    out = Path(out_file) if out_file else HASH_DIR / ("db_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(HASH_DB, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky crypto hash", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["id", "plan", "shadow", "db", "help"])
    p.add_argument("hash", nargs="?", default="")
    p.add_argument("--wordlist", default="")
    p.add_argument("--in", dest="infile", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky crypto hash <id|plan|shadow|db> [hash|file] [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("id <hash>              -- identify hash type + hashcat/john mappings")
        print_info("plan <hash>            -- attack plan with exact hashcat commands")
        print_info("shadow --in file       -- parse /etc/shadow-style file")
        print_info("db                     -- list the whole hash database")
        return 0

    if ns.action == "id":
        if not ns.hash:
            print_err("give a hash")
            return 2
        return cmd_id(ns.hash, ns.out)
    if ns.action == "plan":
        if not ns.hash:
            print_err("give a hash")
            return 2
        return cmd_plan(ns.hash, ns.wordlist, ns.out)
    if ns.action == "shadow":
        if not ns.infile:
            print_err("--in file required")
            return 2
        return cmd_shadow(ns.infile, ns.out)
    if ns.action == "db":
        return cmd_db(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

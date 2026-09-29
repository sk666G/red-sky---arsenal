# language: Python, file: Program/crypto/hash_crack.py, target: Red Sky crypto — hash cracking
# Hash identification + cracking. Two paths:
#
#   1. Hashcat / John wrappers. Detect which is on PATH, shell with the right
#      mode (-m for hashcat, --format for john). Handle the common modes:
#      md5, sha1, sha256, sha512, ntlm, netntlmv2, bcrypt, md5crypt,
#      sha512crypt, argon2.
#
#   2. Pure-python fallback for the un-salted fast hashes (md5, sha1,
#      sha256, sha512, ntlm). Runs a wordlist through hashlib and reports
#      hits. Slow but works without external tools.

import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CRYPTO_DIR = OUTPUT_DIR / "crypto"
HASH_DIR = CRYPTO_DIR / "hash"


# Hash signature catalog. Each entry: (label, regex, hashcat_mode, john_format).
# regex matches the hex/base64 shape.
SIGNATURES: List[Tuple[str, re.Pattern, str, str]] = [
    ("md5",         re.compile(r"^[a-fA-F0-9]{32}$"),                          "0",    "raw-md5"),
    ("sha1",        re.compile(r"^[a-fA-F0-9]{40}$"),                          "100",  "raw-sha1"),
    ("sha224",      re.compile(r"^[a-fA-F0-9]{56}$"),                          "1300", "raw-sha224"),
    ("sha256",      re.compile(r"^[a-fA-F0-9]{64}$"),                          "1400", "raw-sha256"),
    ("sha384",      re.compile(r"^[a-fA-F0-9]{96}$"),                          "10800","raw-sha384"),
    ("sha512",      re.compile(r"^[a-fA-F0-9]{128}$"),                         "1700", "raw-sha512"),
    ("ntlm",        re.compile(r"^[a-fA-F0-9]{32}$"),                          "1000", "nt"),
    ("mysql4",      re.compile(r"^[a-fA-F0-9]{16}$"),                          "200",  "mysql"),
    ("bcrypt",      re.compile(r"^\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}$"),       "3200", "bcrypt"),
    ("md5crypt",    re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),"500",  "md5crypt"),
    ("sha256crypt", re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),"7400", "sha256crypt"),
    ("sha512crypt", re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),"1800", "sha512crypt"),
    ("argon2",      re.compile(r"^\$argon2(id|i|d)\$"),                        "32000","argon2"),
    ("netntlmv2",   re.compile(r"^[A-Za-z0-9+/=]+::[A-Za-z0-9:]+$"),            "5600", "netntlmv2"),
    ("phpass",      re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"),                    "400",  "phpass"),
    ("django",      re.compile(r"^[a-z0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$"),       "",     "django"),
    ("jwt_hs256",   re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"), "16500", "jwt"),
]


PY_HASHERS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def detect(h: str) -> List[Dict[str, str]]:
    """Return every signature that matches. Some shapes are ambiguous (md5 vs
    ntlm both 32 hex) — return all so the operator picks."""
    matches = []
    for label, rx, hc, jn in SIGNATURES:
        if rx.match(h):
            matches.append({"label": label, "hashcat_mode": hc, "john_format": jn})
    return matches


def ntlm_hash(pw: str) -> str:
    return hashlib.new("md4", pw.encode("utf-16le")).hexdigest()


def _which(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _run(cmd: List[str], timeout: int = 3600) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)


# ── commands ───────────────────────────────────────────────────────────────

def cmd_identify(h: str) -> int:
    if not h:
        print_err("--hash required")
        return 1
    matches = detect(h)
    if not matches:
        print_err("no known signature matches")
        print_info("len = " + str(len(h)) + " chars, charset = " + ("hex" if re.match(r'^[a-fA-F0-9]+$', h) else "mixed"))
        return 1
    print_info("hash identification")
    print_kv("hash", h[:80] + ("..." if len(h) > 80 else ""))
    print_kv("length", len(h))
    print()
    for m in matches:
        print("  " + SCARLET + m["label"].ljust(14) + RESET
              + " hashcat -m " + m["hashcat_mode"].ljust(6)
              + " john --format=" + m["john_format"])
    return 0


def cmd_pure(h: str, algo: str, wordlist: str) -> int:
    if algo not in PY_HASHERS and algo != "ntlm":
        print_err("pure-python supports: " + ", ".join(list(PY_HASHERS.keys()) + ["ntlm"]))
        return 1
    if not wordlist:
        print_err("--wordlist required for pure mode")
        return 1
    wl = Path(wordlist)
    if not wl.exists():
        print_err("wordlist not found: " + wordlist)
        return 1

    target = h.lower()
    print_info("pure-python crack")
    print_kv("algo", algo)
    print_kv("wordlist", wl)
    print()

    n = 0
    t0 = time.time()
    with wl.open("rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if algo == "ntlm":
                got = ntlm_hash(pw.decode("utf-8", errors="replace"))
            else:
                got = PY_HASHERS[algo](pw).hexdigest()
            n += 1
            if got == target:
                print_ok("HIT")
                print_kv("word", pw.decode("utf-8", errors="replace"))
                print_kv("tried", n)
                print_kv("elapsed", str(round(time.time() - t0, 2)) + "s")
                return 0
            if n % 100000 == 0:
                print("  " + ASH + str(n) + " tried in " + str(round(time.time() - t0, 1)) + "s" + RESET)
    print()
    print_err("no match")
    print_kv("tried", n)
    print_kv("elapsed", str(round(time.time() - t0, 2)) + "s")
    return 1


def cmd_hashcat(h: str, mode: str, wordlist: str, rules: str) -> int:
    hc = _which("hashcat")
    if not hc:
        print_err("hashcat not on PATH — apt install hashcat, or use --pure")
        return 1
    if not wordlist:
        print_err("--wordlist required")
        return 1
    HASH_DIR.mkdir(parents=True, exist_ok=True)
    hf = HASH_DIR / ("target_" + str(int(time.time())) + ".txt")
    hf.write_text(h + "\n")

    cmd = [hc, "-m", mode, str(hf), wordlist, "--quiet",
           "--potfile-path", str(HASH_DIR / "hashcat.pot"),
           "--outfile", str(HASH_DIR / "cracked.txt"),
           "--outfile-format", "2"]
    if rules:
        cmd += ["-r", rules]

    print_info("hashcat")
    print_kv("mode", mode)
    print_kv("wordlist", wordlist)
    if rules:
        print_kv("rules", rules)
    print()
    rc, out, err = _run(cmd)
    if rc == 0:
        cracked = HASH_DIR / "cracked.txt"
        if cracked.exists() and cracked.stat().st_size > 0:
            print_ok("cracked")
            print(cracked.read_text())
            return 0
    print_err("hashcat rc=" + str(rc))
    if err:
        print_warn(err.strip().splitlines()[-1] if err.strip() else "")
    return 1


def cmd_john(h: str, format_: str, wordlist: str) -> int:
    jn = _which("john", "johnny")
    if not jn:
        print_err("john not on PATH — apt install john, or use --pure")
        return 1
    HASH_DIR.mkdir(parents=True, exist_ok=True)
    hf = HASH_DIR / ("target_john_" + str(int(time.time())) + ".txt")
    hf.write_text(h + "\n")
    cmd = [jn, "--format=" + format_, "--wordlist=" + wordlist, str(hf)]
    print_info("john")
    print_kv("format", format_)
    print_kv("wordlist", wordlist)
    print()
    rc, out, err = _run(cmd)
    print(out)
    if err:
        print_warn(err.strip())
    # ask john to show
    rc2, out2, _ = _run([jn, "--show", "--format=" + format_, str(hf)])
    if out2.strip():
        print_ok("results:")
        print(out2)
        return 0
    return 1


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky crypto hash <sub-command>")
        print_info("")
        print_info("  identify --hash H")
        print_info("      guess hash type from shape, print hashcat -m / john --format")
        print_info("  crack --hash H [--algo md5|sha1|sha256|...] --wordlist FILE [--pure]")
        print_info("        [--mode HASH M] [--rules FILE] [--tool hashcat|john]")
        print_info("      crack a hash — hashcat / john / pure-python fallback")
        print_info("  ntlm --password 'text'")
        print_info("      compute NTLM hash of a password")
        return 0

    if sub == "identify":
        p = argparse.ArgumentParser(prog="redsky crypto hash identify", add_help=False)
        p.add_argument("--hash", dest="h", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto hash identify --hash H")
            return 2
        return cmd_identify(ns.h)

    if sub == "ntlm":
        p = argparse.ArgumentParser(prog="redsky crypto hash ntlm", add_help=False)
        p.add_argument("--password", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto hash ntlm --password 'text'")
            return 2
        if not ns.password:
            print_err("--password required")
            return 2
        print(ntlm_hash(ns.password))
        return 0

    if sub in ("crack", "crack-all"):
        p = argparse.ArgumentParser(prog="redsky crypto hash crack", add_help=False)
        p.add_argument("--hash", dest="h", required=False, default="")
        p.add_argument("--algo", default="")
        p.add_argument("--wordlist", default="")
        p.add_argument("--pure", action="store_true")
        p.add_argument("--mode", default="")
        p.add_argument("--format", dest="format_", default="")
        p.add_argument("--rules", default="")
        p.add_argument("--tool", default="auto", choices=["auto", "hashcat", "john", "pure"])
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto hash crack --hash H --algo md5 --wordlist FILE [--pure]")
            return 2
        if not ns.h:
            print_err("--hash required")
            return 2

        # auto-pick tool
        if ns.tool == "auto":
            if ns.pure:
                ns.tool = "pure"
            elif _which("hashcat"):
                ns.tool = "hashcat"
            elif _which("john"):
                ns.tool = "john"
            else:
                ns.tool = "pure"

        # auto-detect algo / mode from hash if not given
        matches = detect(ns.h)
        if not ns.algo and matches:
            ns.algo = matches[0]["label"]
        if not ns.mode and matches:
            ns.mode = matches[0]["hashcat_mode"]
        if not ns.format_ and matches:
            ns.format_ = matches[0]["john_format"]

        if ns.tool == "pure":
            return cmd_pure(ns.h, ns.algo or "md5", ns.wordlist)
        if ns.tool == "hashcat":
            if not ns.mode:
                print_err("could not auto-detect hashcat mode — pass --mode N")
                return 2
            return cmd_hashcat(ns.h, ns.mode, ns.wordlist, ns.rules)
        if ns.tool == "john":
            if not ns.format_:
                print_err("could not auto-detect john format — pass --format F")
                return 2
            return cmd_john(ns.h, ns.format_, ns.wordlist)

    print_err("unknown hash sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

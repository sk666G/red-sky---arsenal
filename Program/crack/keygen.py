# language: Python, file: Program/crack/keygen.py, target: Red Sky crack — keygen
# Reconstruct a key algorithm from disassembly, then generate valid keys.
# Supports: mathematical algorithms (hash, mod), simple rotations, char XOR.

import hashlib
import itertools
import json
import random
import string
import sys
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


KEY_ALPHABETS = {
    "alnum_upper": string.ascii_uppercase + string.digits,
    "alnum":       string.ascii_uppercase + string.ascii_lowercase + string.digits,
    "digits":      string.digits,
    "hex":         "0123456789ABCDEF",
}


def _luhn_check(digits: str) -> bool:
    """Standard Luhn checksum — used by many product keys."""
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def gen_luhn_key(groups: int = 4, group_len: int = 5, alphabet: str = "digits",
                 sep: str = "-") -> str:
    """Generate a product key that passes Luhn."""
    chars = KEY_ALPHABETS.get(alphabet, string.digits)
    if alphabet != "digits":
        # Luhn is decimal-only; use simple checksum for other alphabets
        return gen_checksum_key(groups, group_len, chars, sep)

    digits = []
    for _ in range(groups * group_len - 1):
        digits.append(random.choice(chars))

    # compute check digit
    partial = "".join(digits)
    for cd in "0123456789":
        if _luhn_check(partial + cd):
            digits.append(cd)
            break

    full = "".join(digits)
    return sep.join(full[i:i + group_len] for i in range(0, len(full), group_len))


def gen_checksum_key(groups: int, group_len: int, alphabet: str, sep: str) -> str:
    """Generate a key with a mod-N checksum in the last position."""
    chars = list(alphabet)
    body_len = groups * group_len - 1
    body = [random.choice(chars) for _ in range(body_len)]
    # simple mod-N checksum of positions
    mod = len(chars)
    check_idx = sum(ord(c) * (i + 1) for i, c in enumerate(body)) % mod
    body.append(chars[check_idx])

    full = "".join(body)
    return sep.join(full[i:i + group_len] for i in range(0, len(full), group_len))


def gen_md5_based(name: str, template: str, length: int = 16) -> str:
    """Derive a key from a username + template using MD5."""
    m = hashlib.md5((template + name).encode()).hexdigest().upper()
    return m[:length]


def gen_sha_based(name: str, template: str, length: int = 20) -> str:
    m = hashlib.sha256((template + name).encode()).hexdigest().upper()
    return m[:length]


def gen_random(alphabet: str, length: int, groups: int = 0, sep: str = "-") -> str:
    chars = KEY_ALPHABETS.get(alphabet, alphabet)
    key = "".join(random.choice(chars) for _ in range(length))
    if groups and groups > 1:
        gsize = length // groups
        key = sep.join(key[i:i + gsize] for i in range(0, length, gsize))
    return key


def cmd_gen(args: Dict) -> int:
    algo = args["algo"]
    print_info(f"generating {args['count']} key(s) — algorithm: {algo}")
    print()

    for _ in range(args["count"]):
        if algo == "luhn":
            key = gen_luhn_key(args.get("groups", 4), args.get("group_len", 5),
                               args.get("alphabet", "digits"), args.get("sep", "-"))
        elif algo == "checksum":
            key = gen_checksum_key(args.get("groups", 4), args.get("group_len", 5),
                                   KEY_ALPHABETS.get(args.get("alphabet", "alnum_upper")),
                                   args.get("sep", "-"))
        elif algo == "md5":
            key = gen_md5_based(args["name"], args["template"], args.get("length", 16))
        elif algo == "sha256":
            key = gen_sha_based(args["name"], args["template"], args.get("length", 20))
        elif algo == "random":
            key = gen_random(args.get("alphabet", "alnum_upper"), args.get("length", 20),
                             args.get("groups", 0), args.get("sep", "-"))
        else:
            print_err(f"unknown algorithm: {algo}")
            return 2

        print(f"  {ARTERY}▓{RESET} {BONE}{key}{RESET}")

    return 0


ALGOS = ["luhn", "checksum", "md5", "sha256", "random"]


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky crack keygen", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--algo", choices=ALGOS, default="luhn")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--groups", type=int, default=4)
    p.add_argument("--group-len", type=int, default=5)
    p.add_argument("--alphabet", default="digits")
    p.add_argument("--sep", default="-")
    p.add_argument("--length", type=int, default=16)
    p.add_argument("--name", default="user")
    p.add_argument("--template", default="REDSKY")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky crack keygen [--algo luhn|checksum|md5|sha256|random] [--count N]")
        return 2

    if ns.help:
        print_info("redsky crack keygen [--algo ...] [--count N] [--groups N] [--group-len N]")
        print_info("  --algo luhn        Luhn-checked digits (product keys)")
        print_info("  --algo checksum    mod-N checksum key")
        print_info("  --algo md5         MD5( template + name )[:length]")
        print_info("  --algo sha256      SHA256( template + name )[:length]")
        print_info("  --algo random      random from alphabet")
        return 0

    return cmd_gen(vars(ns))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

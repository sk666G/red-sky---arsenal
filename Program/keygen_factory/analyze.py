# language: Python, file: Program/keygen_factory/analyze.py, target: Red Sky keygen_factory — license analysis + keygen
# Tools for attacking software licensing:
#   analyze   -- scan a binary for license-key algorithms (checksum, RSA, HMAC,
#                common serial generators, trial counters)
#   keygen    -- generate candidate keys given a recovered or guessed algorithm
#   checksum  -- implement or reverse a checksum-based keygen (mod-97, Luhn,
#                Adler, simple byte-sum, weighted checksum)
#   patch     -- NOP out the license-check jump in a binary (byte pattern replace)
#   find      -- find likely trial/license strings in a binary (with offsets)
# Legal reminder: only apply this to software you have permission to test.

import argparse
import base64
import hashlib
import json
import re
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


KF_DIR = OUTPUT_DIR / "keygen_factory"
KF_DIR.mkdir(parents=True, exist_ok=True)


# ── license string patterns in a binary ──
LICENSE_STRING_HINTS = [
    b"license key",
    b"serial number",
    b"activation code",
    b"please register",
    b"invalid key",
    b"invalid serial",
    b"trial expired",
    b"this copy is not",
    b"unregistered",
    b"registration code",
    b"purchase a license",
    b"enter your key",
]

CRYPTO_API_HINTS = [
    b"RSA_public_decrypt", b"CryptVerifySignature", b"BCryptVerifySignature",
    b"EVP_DigestVerify", b"HMAC", b"CRC32", b"MD5", b"SHA1", b"SHA256",
]


def _read_binary(path: str) -> Optional[bytes]:
    p = Path(path).expanduser()
    if not p.exists():
        print_err("file not found: " + str(p))
        return None
    try:
        return p.read_bytes()
    except OSError as e:
        print_err("read failed: " + str(e))
        return None


def cmd_find(binary_path: str, out_file: str) -> int:
    data = _read_binary(binary_path)
    if data is None:
        return 1
    print_info("license string search")
    print_kv("file", binary_path)
    print_kv("bytes", str(len(data)))
    print()

    findings = []
    for hint in LICENSE_STRING_HINTS:
        start = 0
        while True:
            idx = data.find(hint, start)
            if idx < 0:
                break
            # try to grab a wider context around it
            ctx_start = max(0, idx - 40)
            ctx_end = min(len(data), idx + 200)
            ctx = data[ctx_start:ctx_end]
            # printable-filter
            printable = re.sub(rb"[^\x20-\x7e]", b".", ctx)
            findings.append({
                "hint": hint.decode("ascii"),
                "offset": idx,
                "context": printable.decode("ascii", errors="replace"),
            })
            print("  " + SCARLET + "▓ " + RESET + BONE + "0x" + format(idx, "08x") + RESET
                  + "  " + ARTERY + hint.decode() + RESET)
            print("      " + ASH + printable.decode("ascii", errors="replace")[:120] + RESET)
            start = idx + 1

    for hint in CRYPTO_API_HINTS:
        if hint in data:
            idx = data.find(hint)
            findings.append({"hint": hint.decode("ascii"), "offset": idx,
                             "context": "crypto API import"})
            print("  " + SCARLET + "▓ " + RESET + BONE + "0x" + format(idx, "08x") + RESET
                  + "  crypto: " + ARTERY + hint.decode() + RESET)

    print()
    print_kv("hits", str(len(findings)))

    out = Path(out_file) if out_file else KF_DIR / (Path(binary_path).stem + "_strings.json")
    out.write_text(json.dumps(findings, indent=2))
    print_kv("saved", out)
    return 0


def cmd_analyze(binary_path: str, out_file: str) -> int:
    data = _read_binary(binary_path)
    if data is None:
        return 1
    print_info("license algorithm analysis")
    print_kv("file", binary_path)
    print_kv("bytes", str(len(data)))
    print()

    findings = {"license_strings": 0, "crypto_apis": [], "format_guesses": []}

    for h in LICENSE_STRING_HINTS:
        findings["license_strings"] += data.count(h)
    print_kv("license strings", str(findings["license_strings"]))

    for h in CRYPTO_API_HINTS:
        if h in data:
            findings["crypto_apis"].append(h.decode("ascii"))
    print_kv("crypto APIs", str(len(findings["crypto_apis"])))
    for api in findings["crypto_apis"]:
        print("  " + ARTERY + "* " + RESET + api)

    # guess key format from nearby license strings
    print()
    print(BOLD + "format guesses" + RESET)
    guesses = []
    # regex-looking patterns: groups of 4/5 alnum separated by dashes
    alnum_re = re.compile(rb"[A-Z0-9]{4,5}(?:-[A-Z0-9]{4,5}){2,4}")
    for m in alnum_re.finditer(data):
        guess = m.group(0).decode("ascii")
        if guess not in guesses:
            guesses.append(guess)
            if len(guesses) <= 10:
                print("  " + ARTERY + "* " + RESET + guess)
    findings["format_guesses"] = guesses[:50]

    out = Path(out_file) if out_file else KF_DIR / (Path(binary_path).stem + "_analysis.json")
    out.write_text(json.dumps(findings, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── checksum algorithms ──
def _luhn(s: str) -> int:
    digits = [int(c) for c in s if c.isdigit()]
    if not digits:
        return -1
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10


def _mod97(s: str) -> int:
    n = 0
    for c in s:
        if c.isdigit():
            n = (n * 10 + int(c)) % 97
    return n


def _bytesum(s: str) -> int:
    return sum(s.encode()) & 0xFF


def _adler32(s: str) -> int:
    import zlib
    return zlib.adler32(s.encode()) & 0xFFFFFFFF


def _crc32(s: str) -> int:
    import zlib
    return zlib.crc32(s.encode()) & 0xFFFFFFFF


def _weighted(s: str) -> int:
    return sum((i+1) * ord(c) for i, c in enumerate(s)) & 0xFFFF


CHECKSUMS = {
    "luhn":       _luhn,
    "mod97":      _mod97,
    "bytesum":    _bytesum,
    "adler32":    _adler32,
    "crc32":      _crc32,
    "weighted":   _weighted,
}


def cmd_checksum(name: str, value: str, out_file: str) -> int:
    if name not in CHECKSUMS:
        print_err("unknown checksum: " + name)
        print_info("available: " + ", ".join(CHECKSUMS.keys()))
        return 2
    result = CHECKSUMS[name](value)
    print_info("checksum")
    print_kv("algorithm", name)
    print_kv("input", value)
    print_kv("result", str(result))
    return 0


def cmd_keygen(mode: str, params: str, count: int, out_file: str) -> int:
    """Generate candidate keys in common formats. modes:
        alnum-dash   -- 4 groups of 5 alnum, dashes
        alnum-block  -- 3 groups of 4 alnum
        hex          -- 32 hex chars
        base32       -- 20 base32 chars
        checksum     -- value + checksum char (needs params 'value luhn')
    """
    import secrets
    import string

    print_info("keygen")
    print_kv("mode", mode)
    print_kv("count", str(count))
    print()

    keys = []
    for _ in range(count):
        if mode == "alnum-dash":
            groups = ["".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(5))
                      for _ in range(4)]
            keys.append("-".join(groups))
        elif mode == "alnum-block":
            groups = ["".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
                      for _ in range(3)]
            keys.append("-".join(groups))
        elif mode == "hex":
            keys.append(secrets.token_hex(16))
        elif mode == "base32":
            keys.append(base64.b32encode(secrets.token_bytes(12)).decode().rstrip("="))
        elif mode == "checksum":
            parts = params.split()
            if len(parts) < 2:
                print_err("checksum mode needs 'value algorithm'")
                return 2
            base, algo = parts[0], parts[1]
            chk = CHECKSUMS.get(algo, _luhn)(base)
            keys.append(base + str(chk))
        else:
            print_err("unknown mode: " + mode)
            return 2

    for k in keys[:20]:
        print("  " + SCARLET + "* " + RESET + k)
    if len(keys) > 20:
        print("  " + ASH + "... +" + str(len(keys) - 20) + " more" + RESET)

    out = Path(out_file) if out_file else KF_DIR / ("keygen_" + mode + "_" + str(int(time.time())) + ".txt")
    out.write_text("\n".join(keys) + "\n")
    print()
    print_kv("saved", out)
    return 0


def cmd_patch(binary_path: str, offset_hex: str, patch_hex: str, out_file: str) -> int:
    data = _read_binary(binary_path)
    if data is None:
        return 1
    try:
        off = int(offset_hex, 0)
    except ValueError:
        print_err("--offset must be a number (0x... or decimal)")
        return 2
    try:
        patch = bytes.fromhex(patch_hex.replace(" ", ""))
    except ValueError:
        print_err("--patch must be hex (e.g. 9090)")
        return 2
    if off + len(patch) > len(data):
        print_err("patch extends past end of file")
        return 1

    print_info("byte patch")
    print_kv("file", binary_path)
    print_kv("offset", "0x" + format(off, "x"))
    print_kv("orig", data[off:off+len(patch)].hex())
    print_kv("new", patch.hex())
    print()

    out = Path(out_file) if out_file else KF_DIR / (Path(binary_path).stem + "_patched.bin")
    patched = bytearray(data)
    patched[off:off+len(patch)] = patch
    out.write_bytes(bytes(patched))
    print_ok("wrote " + str(out))
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky keygen_factory license", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["find", "analyze", "checksum", "keygen", "patch", "help"])
    p.add_argument("binary", nargs="?", default="")
    p.add_argument("--mode", default="alnum-dash",
                   choices=["alnum-dash", "alnum-block", "hex", "base32", "checksum"])
    p.add_argument("--params", default="")
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--algo", default="luhn", choices=list(CHECKSUMS.keys()))
    p.add_argument("--value", default="")
    p.add_argument("--offset", default="")
    p.add_argument("--patch", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky keygen_factory license <find|analyze|checksum|keygen|patch> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("find <binary>                             -- search for license strings")
        print_info("analyze <binary>                          -- crypto API + format guesses")
        print_info("checksum --algo luhn --value '123456'     -- compute a checksum")
        print_info("keygen --mode alnum-dash --count 20       -- generate candidate keys")
        print_info("patch <binary> --offset 0x1234 --patch 9090 -- byte-patch a file")
        return 0

    if ns.action == "find":
        if not ns.binary:
            print_err("give a binary")
            return 2
        return cmd_find(ns.binary, ns.out)
    if ns.action == "analyze":
        if not ns.binary:
            print_err("give a binary")
            return 2
        return cmd_analyze(ns.binary, ns.out)
    if ns.action == "checksum":
        if not ns.value:
            print_err("--value required")
            return 2
        return cmd_checksum(ns.algo, ns.value, ns.out)
    if ns.action == "keygen":
        return cmd_keygen(ns.mode, ns.params, ns.count, ns.out)
    if ns.action == "patch":
        if not ns.binary or not ns.offset or not ns.patch:
            print_err("--binary (positional), --offset, --patch required")
            return 2
        return cmd_patch(ns.binary, ns.offset, ns.patch, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

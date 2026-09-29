# language: Python, file: Program/crypto/rng.py, target: Red Sky crypto — RNG attacks
# Weak-random-number attacks. Two categories:
#
#   1. Non-cryptographic PRNGs used where CSPRNGs were needed. Catalog of
#      the classics with the exact predictor:
#        - Mersenne Twister (Python random, PHP mt_rand, Ruby Random)
#        - java.util.Random (LCG with a 48-bit seed)
#        - .NET System.Random (Knuth subtractive)
#        - glibc rand / drand48 / lrand48 (LCG)
#        - PHP mt_rand (MT with 32-bit outputs)
#        - V8 Math.random (xorshift128+)
#        - C rand() on Windows CRT (LCG)
#
#   2. Weak entropy sources. Time-seeded PRNGs where the seed is
#      milliseconds since boot or a `time()` value. Brute the seed window
#      and check against observed outputs.

import json
import random
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CRYPTO_DIR = OUTPUT_DIR / "crypto"
RNG_DIR = CRYPTO_DIR / "rng"


GENERATORS: Dict[str, Dict] = {
    "mersenne": {
        "title": "Mersenne Twister (MT19937)",
        "used_by": ["Python random", "PHP mt_rand (see mt_php)", "Ruby Random"],
        "state_bits": 19937,
        "observed_bits_needed": 624 * 32,
        "notes": [
            "State is 624 32-bit words. After 624 consecutive 32-bit outputs the full state is recoverable.",
            "The predictor then reproduces every future output exactly.",
            "Python's random module: use `random.getstate()` output to seed the clone directly.",
        ],
    },
    "java": {
        "title": "java.util.Random (LCG)",
        "used_by": ["Java default Random", "Kotlin Random default"],
        "state_bits": 48,
        "observed_bits_needed": 48,
        "notes": [
            "state = (state * 0x5DEECE66D + 0xB) & ((1<<48)-1). next(bits) = state >> (48 - bits).",
            "Two consecutive nextInt() outputs recover the full 48-bit state.",
            "nextInt(100)-style bounded calls leak fewer bits — need 2-3 outputs still.",
        ],
    },
    "dotnet": {
        "title": ".NET System.Random (Knuth subtractive)",
        "used_by": [".NET Framework Random", "PowerShell Get-Random default"],
        "state_bits": 56,
        "observed_bits_needed": 56,
        "notes": [
            "Initial state is an array of 56 Int32 seeded from Environment.TickCount or a passed seed.",
            "Given any 55 consecutive outputs the 56th is predictable.",
            "Recovery requires implementing the seed array — reflected in most published PoCs.",
        ],
    },
    "glibc": {
        "title": "glibc rand / random",
        "used_by": ["C rand() on Linux", "PHP rand (before 7.1)"],
        "state_bits": 31,
        "observed_bits_needed": 31,
        "notes": [
            "TYPE_3 additive feedback generator; state is an array of 34 longs.",
            "srand(seed) with a time-derived seed is brute-forceable in 2^31.",
        ],
    },
    "php_mt": {
        "title": "PHP mt_rand",
        "used_by": ["PHP before 7.1", "PHP 7.1+ still uses MT with a different seeding"],
        "state_bits": 19937,
        "observed_bits_needed": 624 * 31,
        "notes": [
            "PHP pre-7.1: mt_srand(seed) where seed is often time(). Brute the seed window.",
            "PHP 7.1+: mt_srand is called with a random seed but a partial-state attack still works given enough outputs.",
        ],
    },
    "v8": {
        "title": "V8 Math.random (xorshift128+)",
        "used_by": ["Chrome", "Node.js", "Deno"],
        "state_bits": 128,
        "observed_bits_needed": 128,
        "notes": [
            "xorshift128+ state is two 64-bit words. 5 consecutive double outputs (52 bits mantissa each) recover both.",
            "Published PoC: https://github.com/d0nutptr/v8_rand_buster.",
        ],
    },
    "win_crt": {
        "title": "Windows CRT rand()",
        "used_by": ["MSVC rand", "some Windows game engines"],
        "state_bits": 32,
        "observed_bits_needed": 32,
        "notes": [
            "state = state * 214013 + 2531011; output = (state >> 16) & 0x7FFF.",
            "One output = 15 bits leaked; 3 outputs recover the 32-bit state.",
        ],
    },
}


# ── glibc rand (simple LCG mode with a 31-bit state) ───────────────────────

def glibc_next(state: int) -> Tuple[int, int]:
    """Approximate the glibc TYPE_3 generator with a 31-bit LCG.
    Not exact — the real algorithm is the additive feedback loop."""
    state = (1103515245 * state + 12345) & 0x7FFFFFFF
    return state, state


def win_crt_next(state: int) -> Tuple[int, int]:
    state = (state * 214013 + 2531011) & 0xFFFFFFFF
    out = (state >> 16) & 0x7FFF
    return state, out


# ── java.util.Random ───────────────────────────────────────────────────────

JAVA_MULT = 0x5DEECE66D
JAVA_ADD  = 0xB
JAVA_MASK = (1 << 48) - 1


def java_next(seed: int, bits: int) -> Tuple[int, int]:
    seed = (seed * JAVA_MULT + JAVA_ADD) & JAVA_MASK
    return seed, seed >> (48 - bits)


def java_recover_from_two_ints(a: int, b: int) -> Optional[int]:
    """Two consecutive 32-bit nextInt() outputs recover the 48-bit state.
    From a = state1 >> 16 and b = state2 >> 16 we can solve for the low 16
    bits of state1 by brute-forcing 2^16 candidates and checking against a."""
    for low in range(1 << 16):
        s1 = (a << 16) | low
        s2 = (s1 * JAVA_MULT + JAVA_ADD) & JAVA_MASK
        if (s2 >> 16) == b:
            return s1
    return None


# ── windows CRT brute (time-seeded) ────────────────────────────────────────

def win_crt_brute_seed(first_output: int, seed_lo: int, seed_hi: int) -> List[int]:
    """Find every seed in [seed_lo, seed_hi] whose first rand() matches."""
    hits = []
    for s in range(seed_lo, seed_hi):
        _, out = win_crt_next(s)
        if out == first_output:
            hits.append(s)
    return hits


# ── commands ───────────────────────────────────────────────────────────────

def cmd_catalog() -> int:
    print_info("rng attack catalog")
    print()
    for key, g in GENERATORS.items():
        print("  " + SCARLET + key.ljust(12) + RESET + " " + BONE + g["title"] + RESET)
        print("      " + ASH + "used by: " + ", ".join(g["used_by"]) + RESET)
        print("      " + ASH + "state: " + str(g["state_bits"]) + " bits  |  need: " + str(g["observed_bits_needed"]) + " bits observed" + RESET)
    print()
    print_info("run:  redsky crypto rng info <name>")
    print_info("      redsky crypto rng predict <name> --observed 'v1 v2 v3 ...' --next")
    return 0


def cmd_info(name: str) -> int:
    if name not in GENERATORS:
        print_err("unknown rng: " + name)
        return 1
    g = GENERATORS[name]
    print(SCARLET + BOLD + "== " + g["title"] + " ==" + RESET)
    print()
    print_kv("state_bits", g["state_bits"])
    print_kv("observed_needed", g["observed_bits_needed"])
    print()
    print(ARTERY + "used by:" + RESET + " " + ", ".join(g["used_by"]))
    print()
    for n in g["notes"]:
        print("  - " + n)
    print()
    return 0


def cmd_predict(name: str, observed: List[int], count: int) -> int:
    if name != "java":
        print_err("predictor implemented for 'java' only in this build")
        print_info("catalog lists the state requirements for each other family")
        return 1
    if len(observed) < 2:
        print_err("java predictor needs at least 2 consecutive nextInt() outputs")
        return 1
    a, b = observed[0], observed[1]
    state = java_recover_from_two_ints(a, b)
    if state is None:
        print_err("no state found (not consecutive 32-bit nextInt outputs?)")
        return 1
    print_ok("state recovered")
    print_kv("state_hex", hex(state))
    print()
    print_info("next " + str(count) + " outputs:")
    s = state
    for _ in range(count):
        s, out = java_next(s, 32)
        # java nextInt() returns signed 32-bit
        signed = out - (1 << 32) if out >= (1 << 31) else out
        print("  " + BONE + str(signed) + RESET + " (" + ASH + hex(out) + RESET + ")")
    return 0


def cmd_win_brute(first_output: int, seed_lo: int, seed_hi: int) -> int:
    print_info("win CRT rand seed brute")
    print_kv("first_output", first_output)
    print_kv("seed_range", str(seed_lo) + " .. " + str(seed_hi))
    print()
    t0 = time.time()
    hits = win_crt_brute_seed(first_output, seed_lo, seed_hi)
    print_kv("candidates", len(hits))
    print_kv("elapsed", str(round(time.time() - t0, 2)) + "s")
    print()
    for h in hits[:50]:
        print("  " + SCARLET + hex(h) + RESET)
    if len(hits) > 50:
        print("  " + ASH + "... +" + str(len(hits) - 50) + " more" + RESET)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "catalog"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky crypto rng <sub-command>")
        print_info("")
        print_info("  catalog                          list PRNG families + state requirements")
        print_info("  info <name>                      details + predictor notes for one family")
        print_info("  predict java --observed 'a b'    --count N   recover java.util.Random state")
        print_info("  win-brute --first N --lo X --hi Y")
        print_info("      brute Windows CRT rand seed over a range")
        return 0

    if sub in ("catalog", "list"):
        return cmd_catalog()

    if sub == "info":
        if not rest:
            print_err("usage: redsky crypto rng info <name>")
            return 2
        return cmd_info(rest[0])

    if sub == "predict":
        p = argparse.ArgumentParser(prog="redsky crypto rng predict", add_help=False)
        p.add_argument("name")
        p.add_argument("--observed", required=False, default="")
        p.add_argument("--count", type=int, default=10)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto rng predict java --observed 'a b'")
            return 2
        obs = [int(x) for x in ns.observed.split()] if ns.observed else []
        return cmd_predict(ns.name, obs, ns.count)

    if sub in ("win-brute", "win_brute"):
        p = argparse.ArgumentParser(prog="redsky crypto rng win-brute", add_help=False)
        p.add_argument("--first", type=int, required=False, default=0)
        p.add_argument("--lo", type=int, default=0)
        p.add_argument("--hi", type=int, default=1 << 24)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto rng win-brute --first N --lo X --hi Y")
            return 2
        return cmd_win_brute(ns.first, ns.lo, ns.hi)

    print_err("unknown rng sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

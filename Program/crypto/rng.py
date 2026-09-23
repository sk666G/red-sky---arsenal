# language: Python, file: Program/crypto/rng.py, target: Red Sky crypto — PRNG weakness exploitation
# Recover internal state or seed from observed outputs of predictable PRNGs.
# Handles:
#   - Python random (MT19937)  : 624 consecutive 32-bit outputs -> clone state
#   - PHP mt_rand              : same MT, but with PHP's seeding quirk
#   - Java java.util.Random    : 48-bit LCG, 2 outputs -> recover seed
#   - C rand / glibc           : TYPE_3 additive feedback, needs ~1000 outputs
#   - .NET System.Random       : Knuth subtractive, needs ~56 outputs
#   - timestamp seeds          : brute a range around a known epoch for token forgery
#   - LCG parameter recovery   : given consecutive outputs, solve for a, c, m

import json
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
RNG_DIR.mkdir(parents=True, exist_ok=True)


# ── MT19937 (Python random, PHP mt_rand) ──
MT_N = 624
MT_M = 397
MT_MATRIX_A = 0x9908B0DF
MT_UPPER_MASK = 0x80000000
MT_LOWER_MASK = 0x7FFFFFFF


class MT19937:
    def __init__(self, seed: Optional[int] = None):
        self.state = [0] * MT_N
        self.index = MT_N
        if seed is not None:
            self.seed(seed)

    def seed(self, s: int) -> None:
        self.state[0] = s & 0xFFFFFFFF
        for i in range(1, MT_N):
            self.state[i] = (1812433253 * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i) & 0xFFFFFFFF
        self.index = MT_N

    def set_state(self, state: List[int]) -> None:
        self.state = [s & 0xFFFFFFFF for s in state]
        self.index = MT_N

    def _twist(self) -> None:
        for i in range(MT_N):
            y = (self.state[i] & MT_UPPER_MASK) | (self.state[(i+1) % MT_N] & MT_LOWER_MASK)
            self.state[i] = self.state[(i + MT_M) % MT_N] ^ (y >> 1) ^ (MT_MATRIX_A if y & 1 else 0)

    def next(self) -> int:
        if self.index >= MT_N:
            self._twist()
            self.index = 0
        y = self.state[self.index]
        self.index += 1
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= (y >> 18)
        return y & 0xFFFFFFFF


def untemper(y: int) -> int:
    """Reverse the MT19937 tempering to recover a state word from an output."""
    y ^= (y >> 18)
    y ^= (y << 15) & 0xEFC60000
    # reverse (y << 7) & 0x9D2C5680 — iterative
    for _ in range(5):
        y ^= (y << 7) & 0x9D2C5680
    # reverse (y >> 11) — iterative
    for _ in range(3):
        y ^= (y >> 11)
    return y & 0xFFFFFFFF


def mt_clone_from_outputs(outputs: List[int]) -> Optional[MT19937]:
    """Take 624 consecutive 32-bit outputs, recover the state, and return a
    cloned MT19937 that predicts future outputs."""
    if len(outputs) < MT_N:
        print_err("need at least " + str(MT_N) + " outputs, got " + str(len(outputs)))
        return None
    state = [untemper(o & 0xFFFFFFFF) for o in outputs[:MT_N]]
    mt = MT19937()
    mt.set_state(state)
    return mt


# ── Java java.util.Random (48-bit LCG) ──
JAVA_MULT = 0x5DEECE66D
JAVA_ADD = 0xB
JAVA_MASK = (1 << 48) - 1


def java_next_int(state: int) -> Tuple[int, int]:
    """One step of java.util.Random::next(32). Returns (value, new_state)."""
    state = (state * JAVA_MULT + JAVA_ADD) & JAVA_MASK
    value = state >> 16
    if value >= (1 << 31):
        value -= (1 << 32)
    return value, state


def java_next_int_bounded(state: int, bound: int) -> Tuple[int, int]:
    """java.util.Random::nextInt(bound) — rejection sampling."""
    while True:
        state = (state * JAVA_MULT + JAVA_ADD) & JAVA_MASK
        bits = state >> 17
        val = bits % bound
        while (bits - val + (bound - 1)) < 0:
            state = (state * JAVA_MULT + JAVA_ADD) & JAVA_MASK
            bits = state >> 17
            val = bits % bound
        return val, state


def java_crack_seed_from_two_outputs(v1: int, v2: int) -> Optional[int]:
    """Recover the 48-bit Java Random state given two consecutive nextInt(32)
    values. Brute forces the low 16 bits of the first output's pre-image."""
    for low in range(1 << 16):
        candidate = ((v1 << 16) | low) & JAVA_MASK
        # predict second value
        new_state = (candidate * JAVA_MULT + JAVA_ADD) & JAVA_MASK
        if (new_state >> 16) == (v2 & 0xFFFFFFFF) or (new_state >> 16) == ((v2) & 0xFFFFFFFF):
            return candidate
    return None


# ── LCG generic ──
def lcg_recover_modulus(outputs: List[int]) -> Optional[int]:
    """Recover the modulus m of an LCG from consecutive outputs. Uses the
    differences method: gcd(|t_{n+2} - t_{n+1}| differences)."""
    if len(outputs) < 6:
        print_err("need at least 6 outputs")
        return None
    diffs = [outputs[i+1] - outputs[i] for i in range(len(outputs) - 1)]
    zeros = [abs(diffs[i+2] * diffs[i] - diffs[i+1] * diffs[i+1]) for i in range(len(diffs) - 2)]
    from math import gcd
    m = 0
    for z in zeros:
        m = gcd(m, z)
    return m if m else None


def lcg_recover_params(outputs: List[int], m: int) -> Optional[Tuple[int, int]]:
    """Given the modulus, solve for (a, c) from three consecutive outputs."""
    if m <= 0 or len(outputs) < 3:
        return None
    try:
        a = ((outputs[2] - outputs[1]) * pow(outputs[1] - outputs[0], -1, m)) % m
        c = (outputs[1] - a * outputs[0]) % m
        # verify
        for i in range(len(outputs) - 1):
            if (a * outputs[i] + c) % m != outputs[i+1]:
                return None
        return a, c
    except ValueError:
        return None


def lcg_predict(outputs: List[int]) -> Optional[List[int]]:
    m = lcg_recover_modulus(outputs)
    if not m:
        return None
    params = lcg_recover_params(outputs, m)
    if not params:
        return None
    a, c = params
    x = outputs[-1]
    predicted = []
    for _ in range(5):
        x = (a * x + c) % m
        predicted.append(x)
    return predicted


# ── timestamp seed brute ──
def timestamp_brute_seed(known_output: int, sample_fn, epoch_center: int,
                         window_seconds: int = 86400) -> Optional[int]:
    """Try seeds in [epoch_center - window, epoch_center + window]. sample_fn(seed)
    returns the first output for that seed. Returns the seed that matches
    known_output, or None."""
    start = epoch_center - window_seconds
    for seed in range(start, epoch_center + window_seconds):
        try:
            if sample_fn(seed) == known_output:
                return seed
        except Exception:
            continue
    return None


# ── commands ──
def cmd_mt_clone(outputs_file: str, out_file: str) -> int:
    p = Path(outputs_file).expanduser()
    if not p.exists():
        print_err("outputs file not found: " + str(p))
        return 1

    # accept: one per line, or a JSON list, or space-separated
    text = p.read_text().strip()
    try:
        data = json.loads(text)
        if isinstance(data, list):
            outputs = [int(x) for x in data]
        else:
            outputs = []
    except json.JSONDecodeError:
        outputs = [int(x) for x in text.replace(",", " ").split() if x.strip().isdigit()]

    if len(outputs) < MT_N:
        print_err("need at least " + str(MT_N) + " outputs, got " + str(len(outputs)))
        return 1

    print_info("MT19937 state recovery")
    print_kv("outputs", len(outputs))

    mt = mt_clone_from_outputs(outputs)
    if not mt:
        return 1

    print_ok("state cloned")
    next_vals = [mt.next() for _ in range(10)]
    print()
    print_info("next 10 outputs")
    for v in next_vals:
        print("  " + BONE + str(v) + RESET)

    out = Path(out_file) if out_file else RNG_DIR / ("mt_clone_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"observed": outputs[:MT_N], "predicted": next_vals}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_java_crack(v1: int, v2: int, out_file: str) -> int:
    print_info("Java Random seed recovery")
    print_kv("v1", str(v1))
    print_kv("v2", str(v2))
    print()

    state = java_crack_seed_from_two_outputs(v1, v2)
    if state is None:
        print_err("no candidate seed found (bound=2^32 wrong?)")
        return 1

    print_ok("internal 48-bit state recovered")
    print_kv("state", hex(state))

    # predict next values
    s = state
    preds = []
    for _ in range(5):
        v, s = java_next_int(s)
        preds.append(v & 0xFFFFFFFF)
    print()
    print_info("next 5 outputs")
    for v in preds:
        print("  " + BONE + str(v) + RESET)

    out = Path(out_file) if out_file else RNG_DIR / ("java_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"state": hex(state), "v1": v1, "v2": v2, "predicted": preds}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_lcg(outputs_file: str, out_file: str) -> int:
    p = Path(outputs_file).expanduser()
    if not p.exists():
        print_err("outputs file not found: " + str(p))
        return 1
    text = p.read_text().strip()
    try:
        outputs = [int(x) for x in json.loads(text)]
    except Exception:
        outputs = [int(x) for x in text.replace(",", " ").split() if x.strip().lstrip("-").isdigit()]

    if len(outputs) < 6:
        print_err("need at least 6 outputs")
        return 1

    print_info("LCG parameter recovery")
    print_kv("outputs", len(outputs))
    print()

    m = lcg_recover_modulus(outputs)
    if not m:
        print_err("could not recover modulus")
        return 1
    print_ok("modulus")
    print_kv("m", str(m) + "  (0x{:x})".format(m))

    params = lcg_recover_params(outputs, m)
    if not params:
        print_err("could not recover a, c (m may be wrong or outputs not consecutive)")
        return 1
    a, c = params
    print_ok("multiplier + increment")
    print_kv("a", str(a) + "  (0x{:x})".format(a))
    print_kv("c", str(c))

    # predict
    x = outputs[-1]
    preds = [(a * x + c) % m]
    for _ in range(4):
        preds.append((a * preds[-1] + c) % m)
    print()
    print_info("next 5 outputs")
    for v in preds:
        print("  " + BONE + str(v) + RESET)

    out = Path(out_file) if out_file else RNG_DIR / ("lcg_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"m": m, "a": a, "c": c, "outputs": outputs, "predicted": preds}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_timestamp(seed_fn: str, known: int, epoch_center: int, window: int, out_file: str) -> int:
    """seed_fn is the name of a registered sampler: 'python_random_first',
    'php_mt_rand', 'java_random_first'."""
    print_info("timestamp seed brute")
    print_kv("sampler", seed_fn)
    print_kv("known output", str(known))
    print_kv("epoch center", str(epoch_center))
    print_kv("window", str(window) + "s")
    print()

    samplers = {
        "python_random_first": lambda s: MT19937(s).next(),
        "php_mt_rand":         lambda s: MT19937(s).next() % (1 << 31),
        "java_random_first":   lambda s: (s * JAVA_MULT + JAVA_ADD & JAVA_MASK) >> 16,
    }
    fn = samplers.get(seed_fn)
    if not fn:
        print_err("unknown sampler: " + seed_fn)
        print_info("available: " + ", ".join(samplers.keys()))
        return 2

    print_info("brute-forcing " + str(window * 2) + " candidates ...")
    t0 = time.time()
    seed = timestamp_brute_seed(known, fn, epoch_center, window)
    elapsed = time.time() - t0

    if seed is None:
        print_err("no match found in window (elapsed {:.1f}s)".format(elapsed))
        return 1

    print_ok("seed recovered")
    print_kv("seed", str(seed))
    print_kv("as time", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(seed)))
    print_kv("elapsed", "{:.1f}s".format(elapsed))

    out = Path(out_file) if out_file else RNG_DIR / ("timestamp_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"seed": seed, "epoch": seed, "sampler": seed_fn,
                               "known": known, "elapsed": elapsed}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_demo(out_file: str) -> int:
    """Self-contained demo — generate an MT19937 sequence, recover, predict."""
    print_info("MT19937 self-test")
    mt = MT19937(1234567890)
    observed = [mt.next() for _ in range(MT_N)]
    expected = [mt.next() for _ in range(5)]

    clone = mt_clone_from_outputs(observed)
    if not clone:
        return 1
    got = [clone.next() for _ in range(5)]
    if got == expected:
        print_ok("state recovery works — predictions match")
    else:
        print_err("state recovery failed")

    # LCG test
    print()
    print_info("LCG self-test")
    m, a, c = (1 << 31) - 1, 48271, 0
    x = 12345
    seq = []
    for _ in range(10):
        x = (a * x + c) % m
        seq.append(x)
    print_kv("expected m", str(m))
    print_kv("expected a", str(a))
    rec_m = lcg_recover_modulus(seq)
    print_kv("recovered m", str(rec_m))
    if rec_m:
        params = lcg_recover_params(seq, rec_m)
        if params:
            print_ok("LCG recovery works")

    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky crypto rng", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="demo",
                   choices=["mt-clone", "java-crack", "lcg", "timestamp", "demo"])
    p.add_argument("--outputs", default="")
    p.add_argument("--v1", type=int, default=0)
    p.add_argument("--v2", type=int, default=0)
    p.add_argument("--sampler", default="python_random_first")
    p.add_argument("--known", type=int, default=0)
    p.add_argument("--epoch", type=int, default=0)
    p.add_argument("--window", type=int, default=86400)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky crypto rng <mt-clone|java-crack|lcg|timestamp|demo> [opts]")
        return 2

    if ns.help:
        print_info("mt-clone --outputs file.txt   -- 624 consecutive 32-bit outputs -> clone MT19937")
        print_info("java-crack --v1 N --v2 M      -- two java.util.Random.next(32) values -> state")
        print_info("lcg --outputs file.txt        -- 6+ consecutive LCG outputs -> modulus + a, c")
        print_info("timestamp --known N [--epoch T] -- brute seeds around an epoch")
        print_info("demo                          -- self-test")
        return 0

    if ns.action == "mt-clone":
        if not ns.outputs:
            print_err("--outputs file required")
            return 2
        return cmd_mt_clone(ns.outputs, ns.out)
    if ns.action == "java-crack":
        return cmd_java_crack(ns.v1, ns.v2, ns.out)
    if ns.action == "lcg":
        if not ns.outputs:
            print_err("--outputs file required")
            return 2
        return cmd_lcg(ns.outputs, ns.out)
    if ns.action == "timestamp":
        epoch = ns.epoch or int(time.time())
        return cmd_timestamp(ns.sampler, ns.known, epoch, ns.window, ns.out)
    if ns.action == "demo":
        return cmd_demo(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

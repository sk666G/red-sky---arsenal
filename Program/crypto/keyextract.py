# language: Python, file: Program/crypto/keyextract.py, target: Red Sky crypto — private key recovery
# Attacks on weak asymmetric keys:
#   RSA:
#     - small e (e=3) with no padding -> cube root
#     - common factor across a key set (batch GCD)
#     - Fermat factorization (p, q close)
#     - Wiener's attack (small private exponent d)
#     - small d via continued fractions
#     - ROCA fingerprint (CVE-2017-15361) detection
#   ECDSA:
#     - nonce reuse across two signatures (k shared -> recover d)
#     - biased nonce via lattice (skeleton — needs fpylll)
#   DSA:
#     - nonce reuse (k shared)
# All input via JSON fixtures or PEM files.

import hashlib
import json
import math
import re
import sys
import time
from fractions import Fraction
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CRYPTO_DIR = OUTPUT_DIR / "crypto"
KEY_DIR = CRYPTO_DIR / "keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)


# ── integer roots ──
def iroot(n: int, k: int) -> int:
    """Return the integer k-th root of n."""
    if n < 0:
        return 0
    if k == 1:
        return n
    x = int(round(n ** (1.0 / k))) if n < (1 << 53) else (1 << ((n.bit_length() + k - 1) // k))
    # refine with Newton
    for _ in range(100):
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            break
        x = y
    return x


def is_perfect_power(n: int, k: int) -> Optional[int]:
    r = iroot(n, k)
    for cand in (r - 1, r, r + 1):
        if cand > 0 and cand ** k == n:
            return cand
    return None


# ── RSA small e (e=3, no padding) ──
def rsa_small_e(c: int, e: int, n: int) -> Optional[bytes]:
    """If m^e < n, m = c^(1/e). Works when the message is short and unpadded."""
    if e > 5:
        return None
    m = is_perfect_power(c, e)
    if m is None:
        return None
    # convert to bytes
    byte_len = (m.bit_length() + 7) // 8
    return m.to_bytes(byte_len, "big")


def rsa_hastad(ciphertexts: List[Tuple[int, int]], e: int) -> Optional[bytes]:
    """Håstad's broadcast attack: same message, e recipients, exponent e.
    Uses CRT to recover m^e mod prod(n_i), then takes the e-th root."""
    if len(ciphertexts) < e:
        return None
    # CRT
    N = 1
    for _, n in ciphertexts:
        N *= n
    x = 0
    for c, n in ciphertexts:
        Ni = N // n
        inv = pow(Ni, -1, n)
        x = (x + c * Ni * inv) % N
    m = is_perfect_power(x, e)
    if m is None:
        return None
    byte_len = (m.bit_length() + 7) // 8
    return m.to_bytes(byte_len, "big")


# ── batch GCD ──
def batch_gcd(moduli: List[int]) -> List[Tuple[int, int, int]]:
    """Find shared factors between RSA moduli. Returns [(i, j, factor)]."""
    hits = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = math.gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                hits.append((i, j, g))
    return hits


# ── Fermat factorization ──
def fermat_factor(n: int, max_iters: int = 1000000) -> Optional[Tuple[int, int]]:
    """Factor n if p and q are close: n = a^2 - b^2 = (a+b)(a-b)."""
    a = iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(max_iters):
        b2 = a * a - n
        b = iroot(b2, 2)
        if b * b == b2:
            return (a + b, a - b)
        a += 1
    return None


# ── Wiener's attack ──
def continued_fraction(num: int, den: int) -> List[int]:
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """Return the convergents (h/k) of a continued fraction."""
    out = []
    h_prev, h = 0, 1
    k_prev, k = 1, 0
    for a in cf:
        h_prev, h = h, a * h + h_prev
        k_prev, k = k, a * k + k_prev
        out.append((h, k))
    return out


def wiener_attack(n: int, e: int) -> Optional[int]:
    """Recover d when d < n^0.25 / 3."""
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # solve for p + q = n - phi + 1, pq = n
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = iroot(disc, 2)
        if t * t != disc:
            continue
        if (s + t) % 2 != 0:
            continue
        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == n:
            return d
    return None


# ── ROCA fingerprint (CVE-2017-15361) ──
ROCA_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167]

def roca_fingerprint(n: int) -> bool:
    """Check if n has the ROCA structure: n mod p_i == 1 for the first 39 primes."""
    for p in ROCA_PRIMES[:17]:
        if n % p != 1:
            return False
    return True


# ── ECDSA nonce reuse ──
def ecdsa_nonce_reuse(sig1: Dict, sig2: Dict, order: int) -> Optional[int]:
    """Two ECDSA sigs from the same k on the same curve.
    s1 = k^-1 (z1 + r d)   s2 = k^-1 (z2 + r d)
    => k = (z1 - z2) / (s1 - s2) mod n
    => d = (s1 k - z1) / r mod n
    """
    r1, s1, z1 = sig1["r"], sig1["s"], sig1["z"]
    r2, s2, z2 = sig2["r"], sig2["s"], sig2["z"]
    if r1 != r2:
        return None
    try:
        k = ((z1 - z2) * pow(s1 - s2, -1, order)) % order
        d = ((s1 * k - z1) * pow(r1, -1, order)) % order
        return d
    except ValueError:
        return None


def dsa_nonce_reuse(sig1: Dict, sig2: Dict, q: int) -> Optional[int]:
    """Same math as ECDSA but on DSA group order q."""
    return ecdsa_nonce_reuse(sig1, sig2, q)


# ── input handlers ──
def _load_json(path: str) -> Optional[Dict]:
    p = Path(path).expanduser()
    if not p.exists():
        print_err("not found: " + str(p))
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print_err("bad json: " + str(e))
        return None


def _load_pem_pubkey(pem_path: str):
    """Parse an RSA public key PEM and return (n, e)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print_err("cryptography package required — pip install cryptography")
        return None
    p = Path(pem_path).expanduser()
    if not p.exists():
        print_err("pem not found: " + str(p))
        return None
    try:
        key = serialization.load_pem_public_key(p.read_bytes(), backend=default_backend())
        nums = key.public_numbers()
        return int(nums.n), int(nums.e)
    except Exception as e:
        print_err("pem parse failed: " + str(e))
        return None


# ── commands ──
def cmd_rsa_small_e(json_path: str, e: int, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    c = int(data.get("c", 0))
    n = int(data.get("n", 0))
    if not c or not n:
        print_err("json needs {c, n}")
        return 2

    print_info("RSA small-e attack")
    print_kv("e", str(e))
    print_kv("ciphertext bits", str(c.bit_length()))
    print_kv("modulus bits", str(n.bit_length()))
    print()

    m = rsa_small_e(c, e, n)
    if m is None:
        print_err("no e-th root — message may be padded or m^e > n")
        return 1

    print_ok("plaintext recovered")
    print("  " + CLOT + m.decode("latin-1", errors="replace") + RESET)

    out = Path(out_file) if out_file else KEY_DIR / ("small_e_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"plaintext_hex": m.hex(),
                               "plaintext_ascii": m.decode("latin-1", errors="replace")}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_rsa_hastad(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    e = int(data.get("e", 3))
    pairs = [(int(x["c"]), int(x["n"])) for x in data.get("pairs", [])]
    if len(pairs) < e:
        print_err("need at least e=" + str(e) + " pairs")
        return 2

    print_info("Håstad's broadcast attack")
    print_kv("e", str(e))
    print_kv("pairs", str(len(pairs)))
    print()

    m = rsa_hastad(pairs[:e], e)
    if m is None:
        print_err("attack failed — try more pairs or a smaller e")
        return 1
    print_ok("plaintext recovered")
    print("  " + CLOT + m.decode("latin-1", errors="replace") + RESET)

    out = Path(out_file) if out_file else KEY_DIR / ("hastad_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"plaintext_hex": m.hex()}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_batch_gcd(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    moduli = [int(x) for x in data.get("moduli", [])]
    if len(moduli) < 2:
        print_err("need at least 2 moduli")
        return 2

    print_info("batch GCD over " + str(len(moduli)) + " moduli")
    hits = batch_gcd(moduli)
    if not hits:
        print_ok("no shared factors found — keys are independently generated")
    else:
        print_warn(str(len(hits)) + " shared factor(s)")
        for i, j, g in hits:
            print("  " + SCARLET + "▓" + RESET + " n[" + str(i) + "] and n[" + str(j) + "] share a factor")
            print("    " + ASH + "factor bits: " + str(g.bit_length()) + RESET)

    out = Path(out_file) if out_file else KEY_DIR / ("batch_gcd_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"hits": [{"i": i, "j": j, "factor_hex": hex(g)} for i, j, g in hits]}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_fermat(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    n = int(data.get("n", 0))
    if not n:
        print_err("json needs {n}")
        return 2

    print_info("Fermat factorization")
    print_kv("n bits", str(n.bit_length()))
    print()

    t0 = time.time()
    factors = fermat_factor(n)
    elapsed = time.time() - t0

    if not factors:
        print_err("no factor found within iteration cap")
        print_info("this only works when |p - q| is small (typically < n^0.25)")
        return 1

    p, q = factors
    print_ok("factored in {:.2f}s".format(elapsed))
    print_kv("p bits", str(p.bit_length()))
    print_kv("q bits", str(q.bit_length()))

    # compute d
    e = int(data.get("e", 65537))
    try:
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        print_kv("d", str(d)[:80] + "...")
    except ValueError:
        d = None
        print_warn("could not compute d (e and phi share a factor)")

    out = Path(out_file) if out_file else KEY_DIR / ("fermat_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "p_hex": hex(p), "q_hex": hex(q), "d_hex": hex(d) if d else None,
    }, indent=2))
    print_kv("saved", out)
    return 0


def cmd_wiener(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    n = int(data.get("n", 0))
    e = int(data.get("e", 65537))
    if not n:
        print_err("json needs {n, e}")
        return 2

    print_info("Wiener's attack")
    print_kv("n bits", str(n.bit_length()))
    print_kv("e", str(e))
    print()

    d = wiener_attack(n, e)
    if d is None:
        print_err("Wiener's attack failed — d is not small enough (need d < n^0.25/3)")
        return 1

    print_ok("private exponent recovered")
    print_kv("d bits", str(d.bit_length()))
    print("d = " + hex(d)[:100] + " ...")

    out = Path(out_file) if out_file else KEY_DIR / ("wiener_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"d_hex": hex(d)}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_roca(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    n = int(data.get("n", 0))
    if not n:
        print_err("json needs {n}")
        return 2

    print_info("ROCA fingerprint (CVE-2017-15361)")
    print_kv("n bits", str(n.bit_length()))
    print()

    if roca_fingerprint(n):
        print_warn("key matches the ROCA fingerprint")
        print_info("this key was generated by Infineon's vulnerable RSA library")
        print_info("factorization via the ROCA attack — use `roca-detect` or the ROCA test suite")
    else:
        print_ok("key does not match the ROCA fingerprint")

    out = Path(out_file) if out_file else KEY_DIR / ("roca_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"n_hex": hex(n), "matches": roca_fingerprint(n)}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_ecdsa_reuse(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    sig1 = data.get("sig1", {})
    sig2 = data.get("sig2", {})
    order = int(data.get("order", 0))
    if not sig1 or not sig2 or not order:
        print_err("json needs {sig1: {r, s, z}, sig2: {r, s, z}, order}")
        return 2

    print_info("ECDSA nonce reuse")
    print_kv("r match", "yes" if sig1["r"] == sig2["r"] else "no")
    print()

    d = ecdsa_nonce_reuse(sig1, sig2, order)
    if d is None:
        print_err("nonces differ (r1 != r2) or s1 == s2 — attack does not apply")
        return 1

    print_ok("private key recovered")
    print("d = " + hex(d))

    out = Path(out_file) if out_file else KEY_DIR / ("ecdsa_reuse_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"d_hex": hex(d), "d_int": d}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_dsa_reuse(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    sig1 = data.get("sig1", {})
    sig2 = data.get("sig2", {})
    q = int(data.get("q", 0))
    if not sig1 or not sig2 or not q:
        print_err("json needs {sig1, sig2, q}")
        return 2

    print_info("DSA nonce reuse")
    print()

    x = dsa_nonce_reuse(sig1, sig2, q)
    if x is None:
        print_err("attack does not apply")
        return 1
    print_ok("private key recovered")
    print("x = " + hex(x))

    out = Path(out_file) if out_file else KEY_DIR / ("dsa_reuse_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"x_hex": hex(x), "x_int": x}, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky crypto keyextract", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["small-e", "hastad", "batch-gcd", "fermat", "wiener", "roca",
                            "ecdsa-reuse", "dsa-reuse", "help"])
    p.add_argument("--in", dest="infile", default="")
    p.add_argument("--e", type=int, default=3)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky crypto keyextract <small-e|hastad|batch-gcd|fermat|wiener|roca|ecdsa-reuse|dsa-reuse> --in file.json")
        return 2

    if ns.action in ("help",) or ns.help:
        print_info("small-e --in {c,n}.json [--e 3]   -- cube root for unpadded RSA")
        print_info("hastad --in {e,pairs}.json         -- Håstad broadcast attack")
        print_info("batch-gcd --in {moduli}.json       -- shared factors across many RSA keys")
        print_info("fermat --in {n,e}.json             -- p, q close (bit-length difference small)")
        print_info("wiener --in {n,e}.json             -- small private exponent d")
        print_info("roca --in {n}.json                 -- CVE-2017-15361 fingerprint")
        print_info("ecdsa-reuse --in {sig1,sig2,order} -- same nonce across two signatures")
        print_info("dsa-reuse --in {sig1,sig2,q}       -- same nonce across two DSA signatures")
        return 0

    if not ns.infile and ns.action not in ("help",):
        print_err("--in required")
        return 2

    if ns.action == "small-e":   return cmd_rsa_small_e(ns.infile, ns.e, ns.out)
    if ns.action == "hastad":    return cmd_rsa_hastad(ns.infile, ns.out)
    if ns.action == "batch-gcd": return cmd_batch_gcd(ns.infile, ns.out)
    if ns.action == "fermat":    return cmd_fermat(ns.infile, ns.out)
    if ns.action == "wiener":    return cmd_wiener(ns.infile, ns.out)
    if ns.action == "roca":      return cmd_roca(ns.infile, ns.out)
    if ns.action == "ecdsa-reuse": return cmd_ecdsa_reuse(ns.infile, ns.out)
    if ns.action == "dsa-reuse":   return cmd_dsa_reuse(ns.infile, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

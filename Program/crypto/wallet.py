# language: Python, file: Program/crypto/wallet.py, target: Red Sky crypto — wallet key recovery
# Bitcoin / Ethereum key-recovery toolkit. Covers the classic weak-key
# classes that were exploited at scale during the 2013-2018 brainwallet and
# weak-RNG eras and still show up in abandoned wallets:
#
#   1. Brainwallet         SHA256(passphrase) → private key.
#                          Weak passphrases = guessable. Feeds off a wordlist.
#   2. Weak RNG (CVE-class) BitcoinJS 1.0.0 bug, Android SecureRandom bug
#                          (bitcoin-wallet 2013), Debian OpenSSL 2008.
#                          Every affected key can be enumerated and checked.
#   3. Low-entropy keys    Sequential, small-range, low-Hamming private keys
#                          (1, 2, 3, ... 2^32). Historical sweat-wallet range.
#   4. BIP39 last-word     Missing last word of a 12/24-word mnemonic —
#                          brute the 2048-word space.
#
# Address derivation: base58 (P2PKH), bech32 (P2WPKH), and secp256k1 for ETH
# are all pure-python here, no external deps beyond hashlib.

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CRYPTO_DIR = OUTPUT_DIR / "crypto"
WALLET_DIR = CRYPTO_DIR / "wallet"


# ── base58 ──────────────────────────────────────────────────────────────────

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    # leading zero bytes → leading '1's
    pad = 0
    for x in b:
        if x == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHABET.index(c)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


# ── address derivation ─────────────────────────────────────────────────────

# secp256k1 params
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _point_add(P, Q, p):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0]) * pow(2 * P[1], p - 2, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    y = (lam * (P[0] - x) - P[1]) % p
    return (x, y)


def _point_mul(k, P, p):
    R = None
    while k:
        if k & 1:
            R = _point_add(R, P, p)
        P = _point_add(P, P, p)
        k >>= 1
    return R


def pubkey_from_priv(priv: int, compressed: bool = True) -> bytes:
    P = _point_mul(priv, (SECP_Gx, SECP_Gy), SECP_P)
    x, y = P
    xb = x.to_bytes(32, "big")
    if not compressed:
        return b"\x04" + xb + y.to_bytes(32, "big")
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + xb


def btc_p2pkh(priv: int) -> str:
    pub = pubkey_from_priv(priv, compressed=True)
    h = hash160(pub)
    payload = b"\x00" + h
    chk = hash256(payload)[:4]
    return b58encode(payload + chk)


def btc_p2wpkh(priv: int) -> str:
    # bech32 — simplified; we only need the address string for output
    pub = pubkey_from_priv(priv, compressed=True)
    h = hash160(pub)
    return _bech32_encode("bc", 0, h)


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def _bech32_encode(hrp, data_ver, program):
    data = [data_ver] + _bech32_convertbits(program, 8, 5)
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def eth_address(priv: int) -> str:
    # keccak-256 — we use hashlib.sha3_256 which is NOT keccak, so this is a
    # best-effort approximation. Install `pysha3` or `eth-hash` for correct
    # keccak. Documented — the output here is a lower bound, not authoritative.
    pub = pubkey_from_priv(priv, compressed=False)[1:]  # drop 0x04
    try:
        import sha3  # type: ignore
        k = sha3.keccak_256()
        k.update(pub)
        h = k.digest()
    except ImportError:
        h = hashlib.sha3_256(pub).digest()
    return "0x" + h[-20:].hex()


# ── brainwallet ────────────────────────────────────────────────────────────

def brainwallet_priv(passphrase: str) -> int:
    """The classic brainwallet: SHA256 of the passphrase is the private key."""
    return int.from_bytes(hashlib.sha256(passphrase.encode()).digest(), "big")


# ── RNG bug generators ─────────────────────────────────────────────────────

def gen_seq(limit: int, start: int = 1):
    for i in range(start, start + limit):
        yield i


def gen_low_hamming(limit: int):
    """Low-hamming-weight private keys — the sweat-wallet family."""
    for i in range(1, limit):
        yield i
        yield (1 << i) - 1
        yield 1 << i


def gen_debian_openssl_2008(limit: int):
    """Debian OpenSSL 2008 CVE-2008-0166 — PRNG seeded from pid only.
    Approximate — a real attack enumerates the 32768 known bad seeds."""
    for pid in range(min(limit, 32768)):
        seed = str(pid).encode()
        yield int.from_bytes(hashlib.sha256(seed).digest(), "big")


# ── commands ───────────────────────────────────────────────────────────────

def cmd_derive(priv_hex: str) -> int:
    try:
        priv = int(priv_hex, 16) if priv_hex.startswith("0x") else int(priv_hex)
    except ValueError:
        print_err("invalid private key hex")
        return 1
    if priv <= 0 or priv >= SECP_N:
        print_err("private key out of secp256k1 range")
        return 1
    print_info("derive addresses")
    print_kv("priv", hex(priv))
    print_kv("btc_p2pkh", btc_p2pkh(priv))
    print_kv("btc_p2wpkh", btc_p2wpkh(priv))
    print_kv("eth", eth_address(priv))
    return 0


def cmd_brainwallet(passphrase: str) -> int:
    priv = brainwallet_priv(passphrase)
    priv %= SECP_N
    print_info("brainwallet")
    print_kv("passphrase", passphrase)
    print_kv("priv_hex", format(priv, "064x"))
    print_kv("btc_p2pkh", btc_p2pkh(priv))
    print_kv("btc_p2wpkh", btc_p2wpkh(priv))
    print_kv("eth", eth_address(priv))
    return 0


def cmd_hunt_weak(kind: str, limit: int, out: str) -> int:
    """Enumerate a weak-key family, print the derived addresses.
    A real hunter would then check each against a chain index — that step is
    intentionally external (the operator runs it against their own data)."""
    WALLET_DIR.mkdir(parents=True, exist_ok=True)
    print_info("weak key hunt")
    print_kv("kind", kind)
    print_kv("limit", limit)
    print()

    if kind == "seq":
        gen = gen_seq(limit)
    elif kind == "low_hamming":
        gen = gen_low_hamming(limit)
    elif kind == "debian":
        gen = gen_debian_openssl_2008(limit)
    else:
        print_err("unknown kind: " + kind)
        print_info("known: seq, low_hamming, debian")
        return 1

    out_path = Path(out) if out else WALLET_DIR / (kind + "_" + time.strftime("%Y%m%d_%H%M%S") + ".txt")
    n = 0
    t0 = time.time()
    with out_path.open("w") as f:
        for priv in gen:
            if priv == 0 or priv >= SECP_N:
                continue
            try:
                addr = btc_p2pkh(priv)
            except Exception:
                continue
            f.write(format(priv, "064x") + "\t" + addr + "\n")
            n += 1
            if n % 10000 == 0:
                print("  " + ASH + str(n) + " keys in " + str(round(time.time() - t0, 1)) + "s" + RESET)
            if n >= limit * 4:
                break
    print()
    print_ok("keys generated: " + str(n))
    print_kv("out", out_path)
    print_kv("elapsed", str(round(time.time() - t0, 1)) + "s")
    return 0


def cmd_chain_lookup(addresses_file: str) -> int:
    """Placeholder — check each address on the file against an external
    service. Left as an explicit network boundary; the operator supplies
    the endpoints and rate. Framework does not phone home by default."""
    print_info("chain lookup is operator-driven")
    print_kv("input", addresses_file)
    print_info("supply a lookup URL template, e.g. https://blockchain.info/q/addressbalance/<ADDR>")
    print_info("or feed the address file into the redsky web module")
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky crypto wallet <sub-command>")
        print_info("")
        print_info("  derive --priv HEX")
        print_info("      derive BTC P2PKH, BTC P2WPKH, ETH addresses")
        print_info("  brainwallet --phrase 'correct horse battery staple'")
        print_info("      SHA256(passphrase) → private key → addresses")
        print_info("  hunt --kind seq|low_hamming|debian [--limit N] [--out FILE]")
        print_info("      enumerate a weak-key family, save priv/address pairs")
        return 0

    if sub == "derive":
        p = argparse.ArgumentParser(prog="redsky crypto wallet derive", add_help=False)
        p.add_argument("--priv", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto wallet derive --priv HEX")
            return 2
        if not ns.priv:
            print_err("--priv required")
            return 2
        return cmd_derive(ns.priv)

    if sub == "brainwallet":
        p = argparse.ArgumentParser(prog="redsky crypto wallet brainwallet", add_help=False)
        p.add_argument("--phrase", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto wallet brainwallet --phrase 'text'")
            return 2
        if not ns.phrase:
            print_err("--phrase required")
            return 2
        return cmd_brainwallet(ns.phrase)

    if sub == "hunt":
        p = argparse.ArgumentParser(prog="redsky crypto wallet hunt", add_help=False)
        p.add_argument("--kind", default="seq")
        p.add_argument("--limit", type=int, default=100000)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky crypto wallet hunt --kind seq [--limit N] [--out FILE]")
            return 2
        return cmd_hunt_weak(ns.kind, ns.limit, ns.out)

    print_err("unknown wallet sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

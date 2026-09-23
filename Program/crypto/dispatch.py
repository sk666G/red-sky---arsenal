# language: Python, file: Program/crypto/dispatch.py, target: Red Sky crypto router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky crypto <sub-command> [args...]")
    print_info("")
    print_info("  rng <mt-clone|java-crack|lcg|timestamp|demo> [opts]")
    print_info("      PRNG state/seed recovery — MT19937, Java LCG, generic LCG")
    print_info("")
    print_info("  keyextract <small-e|hastad|batch-gcd|fermat|wiener|roca|ecdsa-reuse|dsa-reuse> --in file.json")
    print_info("      RSA / ECDSA / DSA private key recovery")
    print_info("")
    print_info("  wallet <entropy|derive|brainwallet|reuse> [opts]")
    print_info("      BIP39/BIP32 derivation, brainwallets, ECDSA nonce reuse")
    print_info("")
    print_info("  hash <id|plan|shadow|db> [hash|file]")
    print_info("      hash identification + hashcat/john attack planner")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("rng", "rand", "r"):
        from .rng import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("keyextract", "key", "keys", "k"):
        from .keyextract import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("wallet", "wallets", "w"):
        from .wallet import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("hash", "hashes", "h"):
        from .hash_crack import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown crypto sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

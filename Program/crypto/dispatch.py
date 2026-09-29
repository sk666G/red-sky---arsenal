# language: Python, file: Program/crypto/dispatch.py, target: Red Sky crypto router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky crypto <sub-command> [args...]")
    print_info("")
    print_info("  wallet       derive | brainwallet | hunt --kind seq|low_hamming|debian")
    print_info("      BTC/ETH address derivation, brainwallet, weak-key enumeration")
    print_info("")
    print_info("  rng          catalog | info <name> | predict java --observed 'a b'")
    print_info("      weak-PRNG attack catalog + state recovery drivers")
    print_info("")
    print_info("  hash         identify | crack | ntlm")
    print_info("      hash ID + hashcat/john/pure-python cracking")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("wallet", "w"):
        from .wallet import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("rng", "r"):
        from .rng import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("hash", "h", "crack"):
        from .hash_crack import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown crypto sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

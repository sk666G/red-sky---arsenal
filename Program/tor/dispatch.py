# language: Python, file: Program/tor/dispatch.py, target: Red Sky tor router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky tor <sub-command> [args...]")
    print_info("")
    print_info("  hs       create | delete | list | keygen")
    print_info("      v3 hidden service control via Tor control port")
    print_info("")
    print_info("  deanon   catalog | info <name> | relay-check | fingerprint")
    print_info("      deanonymization family reference + relay lookup + site fp collector")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("hs", "hidden", "h"):
        from .hs import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("deanon", "d", "deanonymize"):
        from .deanonymize import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown tor sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

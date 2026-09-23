# language: Python, file: Program/satcom/dispatch.py, target: Red Sky satcom router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky satcom <sub-command> [args...]")
    print_info("")
    print_info("  ref <bands|sats|look|link|iridium> [opts]")
    print_info("      SATCOM reference: bands, catalog, look angles, link budget")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("ref", "r"):
        from .ref import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown satcom sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

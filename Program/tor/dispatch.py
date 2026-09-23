# language: Python, file: Program/tor/dispatch.py, target: Red Sky tor router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky tor <sub-command> [args...]")
    print_info("")
    print_info("  hs <create|destroy|list|rotate|backup|status|torrc> [opts]")
    print_info("      hidden service management via the Tor ControlPort")
    print_info("")
    print_info("  circuit <list|newnym|close|exit|guard|reload|kill|info> [opts]")
    print_info("      list circuits, request new identity, force exit country")
    print_info("")
    print_info("  deanon <exit-fingerprint|browser-detect|clock-skew|correlation-plan|guard-detect> [opts]")
    print_info("      deanonymization probes and reference methods")


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
    if sub in ("circuit", "circ", "c"):
        from .circuit import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("deanon", "deanonimize", "deanonymize", "d"):
        from .deanonymize import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown tor sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

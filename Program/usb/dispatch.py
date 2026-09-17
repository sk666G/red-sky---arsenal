# language: Python, file: Program/usb/dispatch.py, target: Red Sky usb router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky usb <sub-command> [args...]")
    print_info("  script <parse|show> <file> [--target digispark|pico] [--out PATH]")
    print_info("  payloads <list|show|gen> [args]")
    print_info("  digispark <tools|install-core|build|flash|autobuild> [args]")
    print_info("  pico <tools|install|autobuild> [args]")
    print_info("")
    print_info("  hardware:")
    print_info("    Digispark / ATtiny85       needs arduino-cli + micronucleus")
    print_info("    Raspberry Pi Pico RP2040   needs CircuitPython on the board")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("script", "ducky"):
        from .duckyscript import run_cli as _d
        return int(_d(args[1:]))
    if sub in ("payloads", "payload"):
        from .payloads import run_cli as _p
        return int(_p(args[1:]))
    if sub == "digispark":
        from .digispark import run_cli as _dg
        return int(_dg(args[1:]))
    if sub == "pico":
        from .pico import run_cli as _pi
        return int(_pi(args[1:]))

    print_err(f"unknown usb sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

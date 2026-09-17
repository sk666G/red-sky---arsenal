# language: Python, file: Program/rfid/dispatch.py, target: Red Sky rfid router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky rfid <sub-command> [args...]")
    print_info("  read <list|dump|emulate>     reader operations (nfcpy)")
    print_info("  classic <scan|mfoc|mfcuk|write|tools>")
    print_info("                                Mifare Classic tooling")
    print_info("  pm3 <check|read|sniff|dump|clone|emulate>")
    print_info("                                Proxmark3 client wrapper")
    print_info("")
    print_info("  hardware needed:")
    print_info("    reader:   ACR122U / PN532 / any nfcpy-compatible USB reader")
    print_info("    classic:  same reader with libnfc tools")
    print_info("    proxmark: Proxmark3 device")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("read", "reader"):
        from .reader import run_cli as _r
        return int(_r(args[1:]))
    if sub in ("classic", "mf"):
        from .classic import run_cli as _c
        return int(_c(args[1:]))
    if sub in ("pm3", "proxmark"):
        from .proxmark import run_cli as _p
        return int(_p(args[1:]))

    print_err(f"unknown rfid sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

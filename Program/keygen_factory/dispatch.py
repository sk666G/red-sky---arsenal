# language: Python, file: Program/keygen_factory/dispatch.py, target: Red Sky keygen_factory router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky keygen_factory <sub-command> [args...]")
    print_info("")
    print_info("  license <find|analyze|checksum|keygen|patch> [opts]")
    print_info("      license algorithm analysis + keygen + binary patch")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("license", "lic", "l"):
        from .analyze import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown keygen_factory sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

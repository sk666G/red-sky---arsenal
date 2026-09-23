# language: Python, file: Program/lock_bypass/dispatch.py, target: Red Sky lock_bypass router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky lock_bypass <sub-command> [args...]")
    print_info("")
    print_info("  workflow <picklist|depth|keygen|bump|impression|decode> [opts]")
    print_info("      interactive lock attack worksheet + cutting patterns")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("workflow", "wf", "w"):
        from .workflow import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown lock_bypass sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

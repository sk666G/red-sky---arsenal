# language: Python, file: Program/memory_forensics/dispatch.py, target: Red Sky memory_forensics router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky memory_forensics <sub-command> [args...]")
    print_info("")
    print_info("  procs <list|maps <pid>>")
    print_info("      process enumeration + memory-map inspection")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("procs", "proc", "p"):
        from .procs import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown memory_forensics sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

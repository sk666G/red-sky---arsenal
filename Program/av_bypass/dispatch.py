# language: Python, file: Program/av_bypass/dispatch.py, target: Red Sky av_bypass router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky av_bypass <sub-command> [args...]")
    print_info("")
    print_info("  detect <detect|processes|drivers|defender|plan>")
    print_info("      on-target AV/EDR detection and bypass sequence")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("detect", "d"):
        from .detect import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown av_bypass sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

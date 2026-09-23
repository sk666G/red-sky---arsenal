# language: Python, file: Program/fuzzer/dispatch.py, target: Red Sky fuzzer router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky fuzzer <sub-command> [args...]")
    print_info("")
    print_info("  mutate <mutate|run|afl|hfuzz|boofuzz|dict> [opts]")
    print_info("      mutation engine, runner, AFL++/honggfuzz/boofuzz wrappers")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("mutate", "m"):
        from .mutate import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown fuzzer sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

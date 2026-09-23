# language: Python, file: Program/shellcode/dispatch.py, target: Red Sky shellcode router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky shellcode <sub-command> [args...]")
    print_info("")
    print_info("  gen <templates|hexify|splice|analyse|stub> [opts]")
    print_info("      shellcode plumbing: templates, encoding, splices, static analysis")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("gen", "g"):
        from .gen import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown shellcode sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

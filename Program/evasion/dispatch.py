# language: Python, file: Program/evasion/dispatch.py, target: Red Sky evasion router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky evasion <sub-command> [args...]")
    print_info("")
    print_info("  catalog                          list bypass techniques (10)")
    print_info("  info <name>                      reference for one technique")
    print_info("  generators                       list runnable snippet generators")
    print_info("  gen <name> [--out FILE]          emit a snippet (C#/PS1/C++)")
    print_info("  all [--out DIR]                  emit every snippet")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    from .evasion import run_cli as _f
    return int(_f(args))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

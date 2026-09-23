# language: Python, file: Program/ai_agent/dispatch.py, target: Red Sky ai_agent router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ai_agent <sub-command> [args...]")
    print_info("")
    print_info("  loop <run|status|list|template> [opts]")
    print_info("      autonomous mission orchestrator across all modules")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("loop", "run", "l"):
        from .loop import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown ai_agent sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

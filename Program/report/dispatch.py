# language: Python, file: Program/report/dispatch.py, target: Red Sky report router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky report <sub-command> [args...]")
    print_info("")
    print_info("  findings <add|import|list|stats|score|dedupe> [opts]")
    print_info("      collect + score findings from Output/findings/")
    print_info("")
    print_info("  deliverable <markdown|html|docx> [opts]")
    print_info("      render the full engagement report")
    print_info("")
    print_info("  exec <generate|show> [--client X] [--engagement Y]")
    print_info("      one-page executive summary")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("findings", "find", "f"):
        from .findings import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("deliverable", "report", "d"):
        from .deliverable import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("exec", "summary", "e"):
        from .exec_summary import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown report sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

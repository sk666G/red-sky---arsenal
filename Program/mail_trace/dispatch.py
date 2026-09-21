# language: Python, file: Program/mail_trace/dispatch.py, target: Red Sky mail_trace router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky mail_trace <sub-command> [args...]")
    print_info("  analyze <header-file>       parse a raw email header file")
    print_info("  analyze --inline 'raw...'   analyze a header string directly")
    print_info("")
    print_info("  reports: From / Return-Path mismatch, SPF, DMARC, DKIM, MX,")
    print_info("           delivery chain, and whether the domain is spoofable")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("analyze", "a"):
        if len(args) < 2:
            print_err("analyze needs a header file or --inline string")
            return 2
        if args[1] == "--inline":
            if len(args) < 3:
                print_err("--inline needs a header string")
                return 2
            from .header import cmd_analyze
            return cmd_analyze(args[2])
        from .header import cmd_analyze
        return cmd_analyze(args[1])

    print_err(f"unknown mail_trace sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

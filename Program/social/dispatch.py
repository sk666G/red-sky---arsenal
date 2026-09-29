# language: Python, file: Program/social/dispatch.py, target: Red Sky social router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky social <sub-command> [args...]")
    print_info("")
    print_info("  osint       username | email | phone | domain")
    print_info("      35-platform handle lookup, gravatar+MX, phone hint, subdomain brute")
    print_info("")
    print_info("  profile     build [--target HANDLE] [--extra-domains a,b]")
    print_info("      aggregate collected OSINT into a markdown dossier")
    print_info("")
    print_info("  pretext     catalog | show <cat> | all")
    print_info("      8-category social-engineering pretext library")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("osint", "o"):
        from .osint import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("profile", "prof", "p"):
        from .profile import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("pretext", "pre", "pretexts"):
        from .pretext import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown social sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

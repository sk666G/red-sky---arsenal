# language: Python, file: Program/social/dispatch.py, target: Red Sky social router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky social <sub-command> [args...]")
    print_info("")
    print_info("  osint <username|email|phone|domain|gravatar> <target>")
    print_info("      handle enumeration, email pivot, phone lookup, domain recon")
    print_info("")
    print_info("  profile <build|show|list> [--in dir] [--dossier file]")
    print_info("      merge osint outputs into a target dossier")
    print_info("")
    print_info("  pretext <list|gen> [scenario|all] [--channel C] [--vars 'k=v,k=v']")
    print_info("      pre-scripted pretexts for email, vishing, LinkedIn, SMS, USB, in-person")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("osint", "recon", "o"):
        from .osint import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("profile", "dossier", "p"):
        from .profile import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("pretext", "pretexts", "pre"):
        from .pretext import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown social sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

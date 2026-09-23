# language: Python, file: Program/phishing/dispatch.py, target: Red Sky phishing router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky phishing <sub-command> [args...]")
    print_info("")
    print_info("  template <url> [--name X] [--collector-path /collect] [--mark]")
    print_info("      clone a login page, rewrite form actions to your collector")
    print_info("")
    print_info("  collector serve --port 8080 --redirect https://real.site [--serve-dir DIR] [--webhook URL]")
    print_info("  collector hits")
    print_info("      run the capture server, or print captured hits")
    print_info("")
    print_info("  sender --targets file.csv --base-url https://phish.url --channel smtp ...")
    print_info("      render lures per target, dispatch via SMTP or webhook")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("template", "tmpl", "t"):
        from .template import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("collector", "collect", "c"):
        from .collector import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("sender", "send", "s"):
        from .sender import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown phishing sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/phish/dispatch.py, target: Red Sky phish router
import sys
from typing import List
from Program.utils import print_info, print_err

SUB = {
    "templates": "templates",
    "template":  "templates",
    "clone":     "templates",
    "catcher":   "catcher",
    "hits":      "catcher",
    "tracker":   "tracker",
    "track":     "tracker",
    "pixel":     "tracker",
    "mailer":    "mailer",
    "mail":      "mailer",
    "send":      "mailer",
}


def _usage():
    print_info("redsky phish <sub-command> [args...]")
    print_info("  templates <list|clone <preset|url> <catcher_url>|show <name>>")
    print_info("  catcher <serve|hits> --template <dir> [--port N] [--redirect URL] [--webhook URL]")
    print_info("  tracker <serve|dump|pixel> [--port N] [--html FILE]")
    print_info("  mailer --targets <file> --template <file> --from <addr> --relay smtp|sendgrid|ses")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    target = SUB.get(sub)
    if not target:
        print_err(f"unknown phish sub-command: {sub}")
        _usage()
        return 2
    mod = __import__(f"Program.phish.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

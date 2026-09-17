# language: Python, file: Program/web/dispatch.py, target: Red Sky web router
# Routes `redsky web <sub>` to the right handler.

import sys
from typing import List

from Program.utils import print_info, print_err


SUB = {
    "triage":         "triage",
    "fingerprint":    "triage",
    "exploit_match":  "exploit_match",
    "cve":            "exploit_match",
    "update-cve":     "exploit_match",
    "exploit_finder": "exploit_finder",
    "finder":         "exploit_finder",
    "deface":         "defacer",
}


def _usage():
    print_info("redsky web <sub-command> [args...]")
    print_info("  triage <url>                    fingerprint a target")
    print_info("  exploit_match <url>             match against local CVE index")
    print_info("  exploit_match update-cve        refresh the CVE index")
    print_info("  deface <webroot> [page.html]    drop a page (post-exploit)")
    print_info("  deface restore <webroot>        restore from backup")


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
        print_err(f"unknown web sub-command: {sub}")
        _usage()
        return 2

    # special: forward update-cve to exploit_match
    if sub == "update-cve":
        from .exploit_match import update_cve_index
        return update_cve_index()

    mod = __import__(f"Program.web.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

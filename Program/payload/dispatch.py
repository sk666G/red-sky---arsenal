# language: Python, file: Program/payload/dispatch.py, target: Red Sky payload router
# Routes `redsky payload <sub>` to the right handler.

import sys
from typing import List

from Program.utils import print_info, print_err


SUB = {
    "persistence":  "persistence",
    "lolbin":       "lolbin",
    "obfuscate":    "obfuscator",
    "obfuscator":   "obfuscator",
    "macro":        "macro",
    "hta":          "hta",
    "iso":          "iso",
    "dropper":      "dropper",
    "builder":      "builder",
    "check":        "builder",
    "beacon":       "builder",
}


def _usage():
    print_info("redsky payload <sub-command> [args...]")
    print_info("  persistence <method|all|list> <payload>   persistence scripts")
    print_info("  lolbin <action> [k=v...]                  LOLBin command lines")
    print_info("  obfuscate --target ps|vba|js --payload X  obfuscate a script")
    print_info("  macro <vba|download|xlm> <payload>        Office macro")
    print_info("  hta <hta|sct> <command>                   HTA / SCT payload")
    print_info("  iso <build|scaffold> <src> <out>          ISO builder")
    print_info("  dropper <ps|py|sh> <url>                  staged loader")
    print_info("  builder <check|beacon>                    build the C++ beacon")


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
        print_err(f"unknown payload sub-command: {sub}")
        _usage()
        return 2

    mod = __import__(f"Program.payload.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

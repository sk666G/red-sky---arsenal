# language: Python, file: Program/supply_chain/dispatch.py, target: Red Sky supply_chain router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky supply_chain <sub-command> [args...]")
    print_info("")
    print_info("  typosquat <pkg-name> [--registry npm|pypi|gem|cargo|go]")
    print_info("      generate typosquat candidates across 9 techniques")
    print_info("")
    print_info("  confusion check --registry <reg> --names pkg1 pkg2 ...")
    print_info("  confusion manifest --registry <reg> --manifest package.json")
    print_info("      which names are NOT registered publicly -> confusion candidates")
    print_info("")
    print_info("  package --registry <npm|pypi|gem|cargo> --name X --version Y --webhook URL")
    print_info("      build a proof package with a post-install beacon")
    print_info("")
    print_info("  scan <github-org> [--token GH_TOKEN]")
    print_info("      walk public repos for manifest-referenced package names")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("typosquat", "typo", "t"):
        from .typosquat import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("confusion", "conf", "c"):
        from .confusion import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("package", "pkg", "p"):
        from .package import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("scan", "s"):
        from .scan import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown supply_chain sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

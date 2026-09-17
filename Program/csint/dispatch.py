# language: Python, file: Program/csint/dispatch.py, target: Red Sky csint router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky csint <sub-command> [args...]")
    print_info("  index <path> <source-name>       add corpus to local index")
    print_info("  sources                          list indexed sources")
    print_info("  delete <source-name>             delete one source from the index")
    print_info("  query <email|domain|password|pivot> <value>")
    print_info("  collected <show|stats|export> [options]")
    print_info("                                   search operator-collected artifacts")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("index", "sources", "list", "delete"):
        from .breach_index import run_cli as _ri
        return int(_ri(args))

    if sub == "query":
        from .breach_query import run_cli as _rq
        return int(_rq(args[1:]))

    if sub in ("collected", "collection"):
        from .collected import run_cli as _rc
        return int(_rc(args[1:]))

    print_err(f"unknown csint sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

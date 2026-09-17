# language: Python, file: Program/ipgrab/dispatch.py, target: Red Sky ipgrab router
# Routes `redsky ipgrab <action>` to the right handler.

import sys
from typing import List

from Program.utils import print_info, print_err


ACTIONS = {"serve", "hits"}


def run_cli(args: List[str]) -> int:
    if args and args[0] not in ACTIONS and not args[0].startswith("-"):
        print_err(f"unknown ipgrab action: {args[0]}")
        print_info("actions: serve (default) | hits")
        return 2

    from .server import run_cli as server
    return server(args)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

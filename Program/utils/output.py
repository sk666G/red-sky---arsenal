# language: Python, file: Program/utils/output.py, target: Red Sky output helpers
# Every printed line in Red Sky goes through here.

import sys
from typing import Iterable, Sequence

from theme.palette import (
    SCARLET, BLOOD, VENOUS, CRIMSON, ARTERY, EMBER, BONE, ASH, OK, WARN, RESET, BOLD,
)
from theme.glyphs import BULLET, ARROW, CROSS, HIT


def _out(*parts, sep="", end="\n", file=sys.stdout):
    print(*parts, sep=sep, end=end, file=file, flush=True)


def print_ok(msg: str):
    _out(f"{OK}{BULLET}{RESET} {msg}")


def print_err(msg: str):
    _out(f"{SCARLET}{CROSS}{RESET} {msg}")


def print_warn(msg: str):
    _out(f"{WARN}!{RESET} {msg}")


def print_info(msg: str):
    _out(f"{ARTERY}{ARROW}{RESET} {msg}")


def print_bullet(msg: str, indent: int = 2):
    _out(" " * indent + f"{ARTERY}{BULLET}{RESET} {msg}")


def print_kv(key: str, value, key_width: int = 16):
    _out(f"  {ASH}{key:<{key_width}}{RESET} {BONE}{value}{RESET}")


def print_table(headers: Sequence[str], rows: Iterable[Sequence], col_widths: Sequence[int] = None):
    headers = [str(h) for h in headers]
    rows = [[str(c) for c in row] for row in rows]
    if col_widths is None:
        col_widths = [
            max(len(headers[i]), *(len(r[i]) for r in rows)) if rows else len(headers[i])
            for i in range(len(headers))
        ]
    head = "  ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers)))
    _out(f"{BOLD}{SCARLET}{head}{RESET}")
    _out(f"{BLOOD}{'─' * len(head)}")
    for r in rows:
        line = "  ".join(f"{r[i]:<{col_widths[i]}}" for i in range(len(headers)))
        _out(f"{BONE}{line}{RESET}")

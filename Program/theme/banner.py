# language: Python, file: Program/theme/banner.py, target: Red Sky banner

import sys
import time
from .palette import (
    CLOT, BLOOD, VENOUS, CRIMSON, ARTERY, SCARLET, EMBER, BONE, ASH, RESET, BOLD,
)
from .glyphs import BLOCK_HEAVY, BLOCK_MED, BLOCK_LIGHT

BANNER_LINES = [
    ("██▀███  ▓█████ ▓█████▄      ██████  ██ ▄█▀▓██   ██▓", SCARLET),
    ("▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌   ▒██    ▒  ██▄█▒  ▒██  ██▒", SCARLET),
    ("▓██ ░▄█ ▒▒███   ░██   █▌   ░ ▓██▄   ▓███▄░   ▒██ ██░", CRIMSON),
    ("▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌     ▒   ██▒▓██ █▄   ░ ▐██▓░", CRIMSON),
    ("░██▓ ▒██▒░▒████▒░▒████▓    ▒██████▒▒▒██▒ █▄  ░ ██▒▓░", VENOUS),
    ("░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒   ██▒▒▒", VENOUS),
    ("  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒    ░ ░▒  ░ ░░ ░▒ ▒░ ▓██ ░▒░", BLOOD),
    ("  ░░   ░    ░    ░ ░  ░    ░  ░  ░  ░ ░░ ░  ▒ ▒ ░░", BLOOD),
    ("   ░        ░  ░   ░             ░  ░  ░    ░ ░", CLOT),
    ("                 ░                          ░ ░", CLOT),
]

BANNER = "\n".join(line for line, _ in BANNER_LINES)


def print_banner(colorize: bool = True):
    if not colorize:
        print(BANNER)
        return
    for line, color in BANNER_LINES:
        print(f"{color}{line}{RESET}")


def print_banner_drip(per_line_ms: int = 25):
    for line, color in BANNER_LINES:
        print(f"{color}{line}{RESET}")
        sys.stdout.flush()
        time.sleep(per_line_ms / 1000.0)


def print_smear(width: int = 60, color: str = None):
    c = color or VENOUS
    print(f"{c}{BLOCK_HEAVY * width}{RESET}")


def print_header(title: str, width: int = 60):
    print()
    print_smear(width, VENOUS)
    print(f"{BOLD}{SCARLET}  {title}{RESET}")
    print_smear(width, VENOUS)
    print()

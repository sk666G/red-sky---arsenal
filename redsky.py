#!/usr/bin/env python3
# language: Python, file: redsky.py, target: Red Sky entry point
# Boots the CLI. Falls back to the menu if no command is given.

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "Program"))

try:
    from Program.cli import main as cli_main
except ImportError as e:
    print(f"\033[38;2;255;36;0m[!] import failed: {e}\033[0m")
    print("\033[38;2;120;120;120m    run: python3 setup.py first\033[0m")
    sys.exit(1)


if __name__ == "__main__":
    try:
        sys.exit(cli_main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n\033[38;2;120;0;0m  interrupted.\033[0m")
        sys.exit(130)

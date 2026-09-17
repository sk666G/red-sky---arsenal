# language: Python, file: Program/theme/palette.py, target: Red Sky palette
# 24-bit blood spectrum. ANSI truecolor, no fallback.

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

CLOT    = "\033[38;2;60;0;0m"
BLOOD   = "\033[38;2;120;0;0m"
VENOUS  = "\033[38;2;160;10;20m"
CRIMSON = "\033[38;2;200;16;46m"
ARTERY  = "\033[38;2;220;20;60m"
SCARLET = "\033[38;2;255;36;0m"
EMBER   = "\033[38;2;255;90;0m"
BONE    = "\033[38;2;230;220;210m"
ASH     = "\033[38;2;120;120;120m"
OK      = "\033[38;2;80;200;80m"
WARN    = "\033[38;2;255;200;0m"

BG_CLOT  = "\033[48;2;20;0;0m"
BG_BLOOD = "\033[48;2;40;0;0m"
BG_VEIN  = "\033[48;2;60;5;5m"


def red(text: str) -> str:
    return f"{SCARLET}{text}{RESET}"


def blood(text: str) -> str:
    return f"{BLOOD}{text}{RESET}"


def arterial(text: str) -> str:
    return f"{ARTERY}{text}{RESET}"


def bone(text: str) -> str:
    return f"{BONE}{text}{RESET}"


def ash(text: str) -> str:
    return f"{ASH}{text}{RESET}"


def ok(text: str) -> str:
    return f"{OK}{text}{RESET}"


def warn(text: str) -> str:
    return f"{WARN}{text}{RESET}"

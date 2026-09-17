# language: Python, file: Program/theme/glyphs.py, target: Red Sky glyphs

BLOCK_FULL  = "█"
BLOCK_HEAVY = "▓"
BLOCK_MED   = "▒"
BLOCK_LIGHT = "░"
UPPER_HALF  = "▀"
LOWER_HALF  = "▄"
LEFT_HALF   = "▌"
RIGHT_HALF  = "▐"

BULLET = "▓"
ARROW  = "▶"
CROSS  = "✖"
HIT    = "▓"
DRIP   = "║"
SMOKE  = "░"
DROP   = "🩸"


def _wrap(glyph: str, color_code: str = "") -> str:
    from .palette import RESET
    return f"{color_code}{glyph}{RESET}" if color_code else glyph


def bullet(color_code: str = "") -> str:
    return _wrap(BULLET, color_code)


def arrow(color_code: str = "") -> str:
    return _wrap(ARROW, color_code)


def cross(color_code: str = "") -> str:
    return _wrap(CROSS, color_code)


def hit(color_code: str = "") -> str:
    return _wrap(HIT, color_code)

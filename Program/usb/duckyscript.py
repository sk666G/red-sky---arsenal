# language: Python, file: Program/usb/duckyscript.py, target: Red Sky usb — DuckyScript parser
# Parses DuckyScript and compiles to Digispark (Arduino C++) or Pico (CircuitPython).

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


USB_DIR = OUTPUT_DIR / "usb"


KEYCODES = {
    "ENTER": "KEY_RETURN", "RETURN": "KEY_RETURN",
    "ESC": "KEY_ESC", "ESCAPE": "KEY_ESC",
    "TAB": "KEY_TAB", "SPACE": "KEY_SPACE",
    "BACKSPACE": "KEY_BACKSPACE", "DELETE": "KEY_DELETE",
    "CAPSLOCK": "KEY_CAPS_LOCK",
    "UP": "KEY_UP_ARROW", "DOWN": "KEY_DOWN_ARROW",
    "LEFT": "KEY_LEFT_ARROW", "RIGHT": "KEY_RIGHT_ARROW",
    "HOME": "KEY_HOME", "END": "KEY_END",
    "PAGEUP": "KEY_PAGE_UP", "PAGEDOWN": "KEY_PAGE_DOWN",
    "INSERT": "KEY_INSERT",
    "F1":"KEY_F1","F2":"KEY_F2","F3":"KEY_F3","F4":"KEY_F4",
    "F5":"KEY_F5","F6":"KEY_F6","F7":"KEY_F7","F8":"KEY_F8",
    "F9":"KEY_F9","F10":"KEY_F10","F11":"KEY_F11","F12":"KEY_F12",
}

MODIFIERS = {
    "CTRL": "MOD_CTRL_LEFT", "CONTROL": "MOD_CTRL_LEFT",
    "SHIFT": "MOD_SHIFT_LEFT",
    "ALT": "MOD_ALT_LEFT",
    "GUI": "MOD_GUI_LEFT", "WINDOWS": "MOD_GUI_LEFT",
    "WIN": "MOD_GUI_LEFT", "COMMAND": "MOD_GUI_LEFT",
}


@dataclass
class Command:
    kind: str
    payload: str = ""
    modifier: str = "0"


def parse(script: str) -> List[Command]:
    cmds: List[Command] = []
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("REM") or line.startswith("//"):
            continue
        low = line.lower()
        if low.startswith("delay "):
            try:
                cmds.append(Command("delay", str(int(line.split(None, 1)[1]))))
            except ValueError:
                print_warn(f"bad delay: {line}")
            continue
        if low.startswith("defaultdelay "):
            continue
        if low.startswith("stringln "):
            cmds.append(Command("string_ln", line[9:]))
            continue
        if low.startswith("string "):
            cmds.append(Command("string", line[7:]))
            continue
        if low.startswith("string") and len(line) > 6:
            cmds.append(Command("string_ln", line[6:].lstrip()))
            continue

        parts = line.split()
        mods, key = [], None
        for p in parts:
            up = p.upper()
            if up in MODIFIERS:
                mods.append(MODIFIERS[up])
            elif up in KEYCODES:
                key = KEYCODES[up]
            else:
                key = f"KEY_{up}" if len(up) == 1 else up
        if mods or key:
            cmds.append(Command("key", key or "", " | ".join(mods) if mods else "0"))
    return cmds


def _lit(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


def to_digispark(cmds: List[Command]) -> str:
    lines = [
        "// Digispark HID payload — DigiKeyboard.h",
        "// flash via: redsky usb digispark autobuild <script>",
        "#include <DigiKeyboard.h>",
        "",
        "void setup() {",
        "    DigiKeyboard.delay(2000);",
    ]
    for c in cmds:
        if c.kind == "delay":
            lines.append(f"    DigiKeyboard.delay({c.payload});")
        elif c.kind == "string":
            lines.append(f"    DigiKeyboard.print(\"{_lit(c.payload)}\");")
        elif c.kind == "string_ln":
            lines.append(f"    DigiKeyboard.println(\"{_lit(c.payload)}\");")
        elif c.kind == "key":
            lines.append(f"    DigiKeyboard.sendKeyStroke({c.payload or '0'}, {c.modifier});")
    lines += ["    DigiKeyboard.delay(500);", "}", "", "void loop() {}", ""]
    return "\n".join(lines)


def to_pico_circuitpython(cmds: List[Command]) -> str:
    lines = [
        "# CircuitPython HID payload for RP2040",
        "import time, usb_hid",
        "from adafruit_hid.keyboard import Keyboard",
        "from adafruit_hid.keycode import Keycode",
        "from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS",
        "",
        "kbd = Keyboard(usb_hid.devices)",
        "layout = KeyboardLayoutUS(kbd)",
        "time.sleep(2.0)",
        "",
    ]
    for c in cmds:
        if c.kind == "delay":
            lines.append(f"time.sleep({int(c.payload) / 1000.0})")
        elif c.kind == "string":
            lines.append(f"layout.write(\"{_lit(c.payload)}\")")
        elif c.kind == "string_ln":
            lines.append(f"layout.write(\"{_lit(c.payload)}\\n\")")
        elif c.kind == "key":
            key = c.payload.replace("KEY_", "").lower() if c.payload else ""
            parts = []
            if c.modifier and c.modifier != "0":
                for m in c.modifier.split(" | "):
                    parts.append(f"Keycode.{m.replace('MOD_', '').replace('_LEFT', '')}")
            if key:
                parts.append(f"Keycode.{key.upper()}")
            if parts:
                lines.append(f"kbd.send({', '.join(parts)})")
                lines.append("kbd.release_all()")
    lines.append("")
    return "\n".join(lines)


def cmd_parse(script_file: str, target: str = "digispark", out_file: str = "") -> int:
    p = Path(script_file).expanduser()
    if not p.exists():
        print_err(f"script not found: {p}")
        return 1
    script = p.read_text(encoding="utf-8", errors="replace")
    cmds = parse(script)
    if not cmds:
        print_err("no commands parsed")
        return 1

    USB_DIR.mkdir(parents=True, exist_ok=True)
    if target == "digispark":
        code, ext = to_digispark(cmds), ".ino"
    elif target in ("pico", "circuitpython"):
        code, ext = to_pico_circuitpython(cmds), ".py"
    else:
        print_err(f"unknown target: {target}")
        print_info("targets: digispark, pico")
        return 2

    out = Path(out_file) if out_file else USB_DIR / f"{p.stem}_{target}{ext}"
    out.write_text(code)

    print_info(f"{len(cmds)} command(s) from {p.name}")
    print_kv("target", target)
    print_kv("output", out)
    print()
    for line in code.splitlines()[:20]:
        print(f"  {ASH}{line}{RESET}")
    print(f"  {CLOT}... ({len(code.splitlines())} lines total){RESET}")
    return 0


def cmd_show(script_file: str) -> int:
    p = Path(script_file)
    if not p.exists():
        print_err(f"not found: {p}")
        return 1
    cmds = parse(p.read_text())
    print_info(f"{len(cmds)} command(s) in {p.name}")
    print()
    for i, c in enumerate(cmds):
        if c.kind == "key":
            print(f"  {ARTERY}▓{RESET} {BONE}{i+1:>3}{RESET}  {SCARLET}{c.modifier}{RESET} + {BONE}{c.payload}{RESET}")
        elif c.kind == "delay":
            print(f"  {ARTERY}▓{RESET} {BONE}{i+1:>3}{RESET}  {ASH}DELAY {c.payload}ms{RESET}")
        else:
            print(f"  {ARTERY}▓{RESET} {BONE}{i+1:>3}{RESET}  {ASH}{c.kind}: {c.payload[:80]}{RESET}")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky usb script <parse|show> <file> [--target digispark|pico] [--out path]")
        return 2
    sub = args[0].lower()
    if sub == "show":
        if len(args) < 2:
            print_err("show needs a script file")
            return 2
        return cmd_show(args[1])
    if sub == "parse":
        if len(args) < 2:
            print_err("parse needs a script file")
            return 2
        target = "digispark"
        out = ""
        if "--target" in args:
            i = args.index("--target")
            if i + 1 < len(args):
                target = args[i + 1]
        if "--out" in args:
            i = args.index("--out")
            if i + 1 < len(args):
                out = args[i + 1]
        return cmd_parse(args[1], target, out)
    print_err(f"unknown script sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

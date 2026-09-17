# language: Python, file: Program/evade/anti_debug.py, target: Red Sky evade — anti-debug
# Generate C++ anti-debug code — PEB walk, IsDebuggerPresent patch, timing checks.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


CPP_ANTIDEBUG = r'''// language: C++, target: anti-debug checks
// Multiple independent checks — any trip means debugger present.

#include <windows.h>
#include <winternl.h>
#include <intrin.h>

// ── direct API check ──
static bool ApiCheck() {
    return IsDebuggerPresent() ||
           (GetLastError() == ERROR_SUCCESS && CheckRemoteDebuggerPresent(GetCurrentProcess(), nullptr) != 0);
}

// ── PEB walk — BeingDebugged flag ──
static bool PebCheck() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    return peb->BeingDebugged != 0;
}

// ── PEB NtGlobalFlag — set when process is debugged ──
static bool GlobalFlagCheck() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
    DWORD flag = *(DWORD*)((BYTE*)peb + 0xBC);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
    DWORD flag = *(DWORD*)((BYTE*)peb + 0x68);
#endif
    return (flag & 0x70) != 0;  // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
}

// ── Hardware breakpoint check via GetThreadContext ──
static bool HardwareBreakpointCheck() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

// ── timing check — debugger single-step slows execution ──
static bool TimingCheck() {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    // busy loop
    volatile int x = 0;
    for (int i = 0; i < 1000000; ++i) x += i;
    QueryPerformanceCounter(&t1);
    double elapsed_ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
    return elapsed_ms > 50.0;  // sanity loop shouldn't take >50ms
}

// ── aggregate ──
static bool IsDebugged() {
    if (ApiCheck())                return true;
    if (PebCheck())                return true;
    if (GlobalFlagCheck())         return true;
    if (HardwareBreakpointCheck()) return true;
    if (TimingCheck())             return true;
    return false;
}

// ── neutral action on detection ──
static void OnDebugDetected() {
    // self-destruct: corrupt the import table, or exit silently
    ExitProcess(0);
}
'''


def cmd_show(out_file: str = "") -> int:
    print_info("anti-debug code")
    print()
    print(CPP_ANTIDEBUG)
    out = Path(out_file) if out_file else OUTPUT_DIR / "evade" / "anti_debug.cpp"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(CPP_ANTIDEBUG)
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    return cmd_show(args[0] if args else "")


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

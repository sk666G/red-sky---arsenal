# language: Python, file: Program/evasion/av_bypass.py, target: Red Sky evasion — vendor cookbook
# Reference catalog of AV/EDR products and the specific techniques each one
# monitors. Not a generator — a lookup. Every technique cross-references the
# loader.py module where the code lives.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


EV_DIR = OUTPUT_DIR / "evasion"
EV_DIR.mkdir(parents=True, exist_ok=True)


# ── vendor catalog ──
# Each vendor: what hooks they install, what telemetry they collect, the
# counters that work, the counters that don't, notable version ranges
VENDORS: List[Dict] = [
    {
        "name": "Microsoft Defender for Endpoint (MDE)",
        "short": "defender",
        "hooks": ["ntdll usermode hooks", "AMSI provider", "ETW (Microsoft-Windows-Threat-Intelligence)",
                  "kernel minifilter", "WFP callouts"],
        "telemetry": ["process creation with full command line", "image loads", "thread injection",
                      "network connections with PID", "registry writes", "file writes with hash"],
        "works": ["ETW patch of EtwEventWrite / NtTraceEvent", "AMSI patch or bypass via CLR reflection",
                  "direct syscalls via SysWhispers3/HellsGate", "ntdll unhooking from KnownDlls section",
                  "module stomping with a signed DLL", "sleep encryption with Ekko/Foliage",
                  "PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                  "command-line args split to defeat CommandLine heuristics"],
        "does_not_work": ["plain VirtualAlloc RWX + CreateThread", "LoadLibrary of raw DLL bytes",
                          "plain CreateRemoteThread into a live process",
                          "base64 in command line (hooked at AMSI)"],
        "notes": "MDE is the hardest single-vendor target because of the kernel minifilter + "
                 "the cloud ML. ASR rules block Office child procs. Prefer LOTL (lolbins) over loaders.",
    },
    {
        "name": "CrowdStrike Falcon",
        "short": "crowdstrike",
        "hooks": ["kernel minifilter (WinFlt)", "ETW consumer", "userland hook DLL injected into every process"],
        "telemetry": ["process lineage", "token manipulation", "network", "LSASS access",
                      "script content (PowerShell, WMI, JS, VBA via ScriptControl)"],
        "works": ["kernel-level: vulnerable driver to disable the Falcon minifilter",
                  "BYOVD (Bring Your Own Vulnerable Driver) with a signed vulnerable driver",
                  "userland hook bypass by remapping ntdll from disk",
                  "avoiding the processes Falcon hooks hardest (lsass, csrss, winlogon)",
                  "DNS/ICMP beaconing instead of HTTP"],
        "does_not_work": ["unhooking by reloading ntdll (Falcon re-hooks quickly on some builds)",
                          "direct syscalls alone (Falcon detects the stub pattern)",
                          "process hollowing of svchost without token adjustment"],
        "notes": "Falcon relies on the kernel sensor. Everything usermode is insufficient. "
                 "Realistically you need BYOVD or a kernel driver of your own, and even then "
                 "the driver-load events land in the cloud.",
    },
    {
        "name": "SentinelOne Singularity",
        "short": "sentinelone",
        "hooks": ["kernel minifilter + custom driver", "userland hook DLL", "ETW consumer",
                  "deep script inspection"],
        "telemetry": ["behavioral static (pre-execution ML)", "storyline graph across processes",
                      "user-mode hook callbacks", "reputation on every file"],
        "works": ["BYOVD to kill the SentinelOne driver (multiple public PoCs)",
                  "shellcode injection into a signed, trusted process",
                  "avoid disk entirely — fileless via WMI / MSHTA / registry",
                  "encrypt the payload and only decrypt in-memory after a delay",
                  "sign the loader with a valid code-signing cert (EV certs help)"],
        "does_not_work": ["unsigned executables on disk (quarantine on write)",
                          "unpacked .NET assemblies (SentinelOne has a strong .NET ML)",
                          "obvious Windows API sequences"],
        "notes": "Static pre-execution ML catches most public tooling. You need a custom loader "
                 "with obfuscated strings and no public IOCs.",
    },
    {
        "name": "Carbon Black (VMware)",
        "short": "carbonblack",
        "hooks": ["kernel minifilter (cbstream.sys)", "userland", "ETW"],
        "telemetry": ["process + module + network events", "child process trees", "script content"],
        "works": ["kernel driver kill via BYOVD", "process injection into the CB-protected process space",
                  "encrypted C2 over a legitimate service (Slack API, Dropbox, etc.)",
                  "timestomping + LOLBin staging"],
        "does_not_work": ["cmd.exe /c powershell -enc ...", "Mimikatz non-customized",
                          "standard Cobalt Strike default profiles"],
        "notes": "CB has a good process-tree graph but weaker ML than MDE. Default C2 profiles "
                 "are detected. Custom malleable profiles + living-off-the-land works.",
    },
    {
        "name": "Cylance (BlackBerry)",
        "short": "cylance",
        "hooks": ["userland only (no kernel sensor by default)"],
        "telemetry": ["static ML on executables", "limited runtime"],
        "works": ["packing / custom compression", "process injection (Cylance is weak on runtime)",
                  "custom shellcode loader", "LOLBins"],
        "does_not_work": ["known tools (Mimikatz, Rubeus, etc.) unmodified",
                          "public shellcode from GitHub"],
        "notes": "Cylance is a static ML product. If you beat the ML you win. Runtime is thin. "
                 "Thematically the easiest 'big vendor' to bypass.",
    },
    {
        "name": "Sophos Intercept X",
        "short": "sophos",
        "hooks": ["userland", "kernel callbacks", "DLL hijack protection", "AMSI"],
        "telemetry": ["behavioral", "ransomware encryption heuristics", "credential theft detection"],
        "works": ["direct syscalls", "ntdll unhook", "process injection into whitelisted processes",
                  "signed binaries (LOLBins) for initial access"],
        "does_not_work": ["plain shellcode loaders", "LSASS dump via MiniDumpWriteDump",
                          "AD recon via built-in Windows tools without obfuscation"],
        "notes": "Intercept X has strong anti-ransomware and anti-credential-theft. "
                 "Manual red team operations with custom tooling usually work; commodity does not.",
    },
    {
        "name": "McAfee / Trellix ENS",
        "short": "mcafee",
        "hooks": ["kernel minifilter", "userland hook DLL", "AMSI"],
        "telemetry": ["process creation", "registry", "file writes", "network"],
        "works": ["BYOVD", "process injection into trusted processes",
                  "PowerShell with AMSI bypass (older versions)",
                  "shellcode with custom crypter"],
        "does_not_work": ["known exploit kits", "commodity malware families"],
        "notes": "Enterprise-heavy. Often deployed alongside Defender — so you need to bypass both.",
    },
    {
        "name": "Symantec Endpoint Protection (Broadcom)",
        "short": "symantec",
        "hooks": ["kernel (sysplant.sys)", "userland", "AMSI"],
        "telemetry": ["process + network", "script content", "reputation"],
        "works": ["BYOVD", "process hollowing of a signed binary",
                  "unhooked ntdll + direct syscalls", "living off the land"],
        "does_not_work": ["public C2 frameworks with default profiles",
                          "LOLBins documented in the last two years without variation"],
        "notes": "Mature product. Static signatures are strong; behavioral is lighter than MDE.",
    },
    {
        "name": "ESET Endpoint Security",
        "short": "eset",
        "hooks": ["userland", "kernel", "AMSI", "HIPS"],
        "telemetry": ["script", "process creation", "reputation on file hash", "network protocol"],
        "works": ["direct syscalls", "unhooking", "process injection",
                  "custom shellcode with per-build encryption"],
        "does_not_work": ["PowerShell with encoded commands", "old .NET loaders"],
        "notes": "Strong European market share. HIPS module does behavioral checks that "
                 "catch many initial access vectors.",
    },
    {
        "name": "Kaspersky Endpoint Security",
        "short": "kaspersky",
        "hooks": ["kernel", "userland", "AMSI", "behavioral (System Watcher)"],
        "telemetry": ["process tree", "registry", "script", "network with full protocol decoding"],
        "works": ["unhooking + direct syscalls", "BYOVD", "injection into signed processes",
                  "obfuscated scripts", "custom protocols"],
        "does_not_work": ["Mimikatz family", "Cobalt Strike default profiles", "public shellcode"],
        "notes": "Behavioural engine is strong. Cloud reputation blocking. "
                 "Prefer novel tooling over public frameworks.",
    },
    {
        "name": "Trend Micro Apex One / Deep Security",
        "short": "trend",
        "hooks": ["userland", "kernel", "AMSI", "sandbox integration"],
        "telemetry": ["behavioral", "C&C reputation", "process events"],
        "works": ["injection into trusted procs", "direct syscalls", "unhooking",
                  "uncommon protocols for C2"],
        "does_not_work": ["known C2 domains", "default Meterpreter payloads"],
        "notes": "Trend's C2 reputation is strong — using Cloudflare Workers or a real CDN helps.",
    },
    {
        "name": "Palo Alto Cortex XDR",
        "short": "cortex",
        "hooks": ["userland + kernel", "ETW", "script control", "AMSI"],
        "telemetry": ["process lineage + causality chain", "RPC calls", "named pipes",
                      "network with DPI", "file + registry"],
        "works": ["BYOVD", "kernel exploits for the Cortex driver",
                  "attack from a process Cortex doesn't monitor (rare)",
                  "very custom tooling with no shared IOCs"],
        "does_not_work": ["most usermode-only techniques", "standard tooling",
                          "default C2 profiles"],
        "notes": "Cortex is MDE-class. Full kernel sensor, cloud ML. Kernel-level bypass or bust.",
    },
]


def cmd_list() -> int:
    print_info(str(len(VENDORS)) + " vendors in catalog")
    print()
    for v in VENDORS:
        print("  " + SCARLET + "*" + RESET + " " + BONE + v["name"] + RESET
              + "  " + ASH + "(" + v["short"] + ")" + RESET)
    print()
    print_info("show a vendor: redsky evasion av <short>")
    return 0


def cmd_show(short: str, out_file: str) -> int:
    short = short.lower()
    v = next((x for x in VENDORS if x["short"] == short), None)
    if not v:
        print_err("unknown vendor: " + short)
        print_info("available: " + ", ".join(x["short"] for x in VENDORS))
        return 2

    print(BOLD + SCARLET + v["name"] + RESET)
    print()

    print(ARTERY + BOLD + "-- hook points" + RESET)
    for h in v["hooks"]:
        print("  " + SCARLET + "*" + RESET + " " + h)
    print()

    print(ARTERY + BOLD + "-- telemetry" + RESET)
    for t in v["telemetry"]:
        print("  " + SCARLET + "*" + RESET + " " + t)
    print()

    print(ARTERY + BOLD + "-- works against this vendor" + RESET)
    for w in v["works"]:
        print("  " + SCARLET + "▓ " + RESET + BONE + w + RESET)
    print()

    print(ARTERY + BOLD + "-- does not work" + RESET)
    for d in v["does_not_work"]:
        print("  " + ASH + "░ " + d + RESET)
    print()

    print(ARTERY + BOLD + "-- notes" + RESET)
    print("  " + CLOT + v["notes"] + RESET)
    print()

    out = Path(out_file) if out_file else EV_DIR / ("vendor_" + short + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(v, indent=2))
    print_kv("saved", out)
    return 0


def cmd_plan(vendor_short: str, technique_filter: str, out_file: str) -> int:
    """Given a vendor, produce the recommended technique sequence in order.
    This is the plan an operator would follow, not a code generator."""
    short = vendor_short.lower()
    v = next((x for x in VENDORS if x["short"] == short), None)
    if not v:
        print_err("unknown vendor: " + short)
        return 2

    print_info("bypass plan for " + v["name"])
    print()

    # score by hook coverage — kernel sensor present? pick a different opener
    has_kernel = any("kernel" in h.lower() for h in v["hooks"])
    print(BOLD + "Step 1: situational awareness" + RESET)
    print("  " + ARROW + " run `redsky evasion sandbox check` to confirm you're not in a sandbox")
    print("  " + ARROW + " run `redsky evasion av detect` to fingerprint the EDR from the endpoint")
    print()

    print(BOLD + "Step 2: usermode preparation" + RESET)
    print("  " + ARROW + " AMSI patch (pre-anything-that-invokes-scanbuffer)")
    print("  " + ARROW + " ETW patch of EtwEventWrite + NtTraceEvent")
    print("  " + ARROW + " NTDLL unhook from a clean copy (KnownDlls section preferred)")
    print("  " + ARROW + " resolve all sensitive APIs via direct syscalls (HellsGate or SysWhispers3)")
    print()

    if has_kernel:
        print(BOLD + "Step 3: kernel reach — required for " + v["name"] + RESET)
        print("  " + ARROW + " " + v["works"][0])
        print("  " + ARROW + " BYOVD is the realistic path if you can't sign a driver")
        print()
    else:
        print(BOLD + "Step 3: no kernel sensor — usermode sufficient" + RESET)
        print("  " + ARROW + " proceeds directly to payload delivery")
        print()

    print(BOLD + "Step 4: payload delivery" + RESET)
    print("  " + ARROW + " load shellcode via one of:")
    print("       module stomping into a signed DLL")
    print("       NtMapViewOfSection of a section object")
    print("       callback execution (EnumFonts / CertEnumSystemStore / ...)")
    print("       fiber-based exec (ConvertThreadToFiber + CreateFiber)")
    print("  " + ARROW + " encrypt the beacon in memory during sleep (Ekko or Foliage)")
    print("  " + ARROW + " C2 over a legitimate service (Slack, Dropbox, OneDrive, Cloudflare Workers)")
    print()

    print(BOLD + "Step 5: cleanup" + RESET)
    print("  " + ARROW + " wipe the loader from disk (self-delete via MoveFileEx)")
    print("  " + ARROW + " clear event log entries you created (eventlog service restart, careful)")
    print("  " + ARROW + " avoid touching LSASS directly if " + v["name"] + " is on the box")
    print()

    plan = {
        "vendor": v["name"],
        "has_kernel_sensor": has_kernel,
        "sequence": [
            "sandbox check + EDR fingerprint",
            "AMSI/ETW patch + NTDLL unhook",
            "direct syscalls (HellsGate/SysWhispers3)",
            "kernel bypass (BYOVD)" if has_kernel else "skip — no kernel sensor",
            "payload: module stomp / NtMapViewOfSection / callback / fiber",
            "sleep encryption (Ekko/Foliage)",
            "legit-service C2",
            "self-delete + log cleanup",
        ],
    }
    out = Path(out_file) if out_file else EV_DIR / ("plan_" + short + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(plan, indent=2))
    print_kv("saved", out)
    return 0


ARROW = SCARLET + "▸" + RESET


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky evasion av", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "show", "plan"])
    p.add_argument("vendor", nargs="?", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky evasion av <list|show|plan> [vendor]")
        return 2

    if ns.help:
        print_info("list                    -- show all vendors")
        print_info("show defender           -- what hooks/telemetry/bypasses apply to MDE")
        print_info("plan defender           -- step-by-step sequence to bypass MDE")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "show":
        if not ns.vendor:
            print_err("give a vendor short name (list to see them)")
            return 2
        return cmd_show(ns.vendor, ns.out)
    if ns.action == "plan":
        if not ns.vendor:
            print_err("give a vendor short name")
            return 2
        return cmd_plan(ns.vendor, "", ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

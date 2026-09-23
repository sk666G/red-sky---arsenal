# language: Python, file: Program/av_bypass/detect.py, target: Red Sky av_bypass — on-target AV/EDR detection
# Reads the local machine to figure out which AV/EDR product is installed and
# what its live state is. Then prints the specific bypass recipe from
# evasion/av_bypass.py.
#   detect      -- scan for AV/EDR product presence via services, drivers, processes
#   processes   -- list running AV/EDR-related processes with PIDs
#   drivers     -- list loaded kernel drivers matching AV/EDR vendors
#   defender    -- Windows Defender specific: check tamper protection, exclusion
#                  paths, real-time status via PowerShell / Get-MpComputerStatus
#   plan        -- detect + emit the exact bypass sequence for what's found

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AVB_DIR = OUTPUT_DIR / "av_bypass"
AVB_DIR.mkdir(parents=True, exist_ok=True)


VENDORS = [
    {
        "name": "Microsoft Defender",
        "short": "defender",
        "services": ["WinDefend", "WdNisSvc", "Sense", "SecurityHealthService"],
        "drivers": ["WdFilter", "Wdfilter", "WDBoot", "WdNisDrv"],
        "processes": ["MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe"],
    },
    {
        "name": "CrowdStrike Falcon",
        "short": "crowdstrike",
        "services": ["CSAgent", "CSFalconService"],
        "drivers": ["CSAgent", "csdevicecontrol", "csfusecfg", "csshell", "cspcm", "csboot"],
        "processes": ["CSFalconService.exe", "CSFalconContainer.exe"],
    },
    {
        "name": "SentinelOne",
        "short": "sentinelone",
        "services": ["SentinelAgent", "SentinelHelperService", "SentinelStaticEngine"],
        "drivers": ["SentinelDeviceControl", "SentinelMonitor", "SentinelELAM"],
        "processes": ["SentinelAgent.exe", "SentinelServiceHost.exe", "SentinelStaticEngine.exe"],
    },
    {
        "name": "Carbon Black",
        "short": "carbonblack",
        "services": ["CbDefense", "CarbonBlack"],
        "drivers": ["CarbonBlack", "CbKernel"],
        "processes": ["RepMgr.exe", "RepUtils.exe", "CbDefense.exe"],
    },
    {
        "name": "Cylance",
        "short": "cylance",
        "services": ["CylanceSvc"],
        "drivers": ["CyProtectDrv"],
        "processes": ["CylanceSvc.exe", "CylanceUI.exe"],
    },
    {
        "name": "Sophos Intercept X",
        "short": "sophos",
        "services": ["SophosED", "Sophos Endpoint Defense Service"],
        "drivers": ["SophosED", "SAVOnAccess", "SophosFIM"],
        "processes": ["SophosHealth.exe", "SAVService.exe", "SophosFS.exe"],
    },
    {
        "name": "McAfee / Trellix",
        "short": "mcafee",
        "services": ["McAfeeFramework", "McShield", "McTaskManager"],
        "drivers": ["mfehidk", "mfeapfk", "mfeavfk"],
        "processes": ["McShield.exe", "mcshield.exe", "masvc.exe", "mfeann.exe"],
    },
    {
        "name": "Symantec / Broadcom",
        "short": "symantec",
        "services": ["SepMasterService", "Symantec AntiVirus"],
        "drivers": ["SRTSP", "SYMEVENT", "SysPlant", "WPS"],
        "processes": ["ccSvcHst.exe", "Smc.exe", "Rtvscan.exe"],
    },
    {
        "name": "ESET",
        "short": "eset",
        "services": ["ekrn"],
        "drivers": ["eamonm", "ehdrv", "epfw"],
        "processes": ["ekrn.exe", "egui.exe"],
    },
    {
        "name": "Kaspersky",
        "short": "kaspersky",
        "services": ["AVP", "klnagent"],
        "drivers": ["klif", "kl1", "klflt"],
        "processes": ["avp.exe", "avpui.exe"],
    },
    {
        "name": "Trend Micro",
        "short": "trend",
        "services": ["TmListen", "ntrtscan", "TMBMServer"],
        "drivers": ["tmcomm", "tmactmon", "tmevtmgr"],
        "processes": ["ntrtscan.exe", "TmListen.exe", "TmCCSF.exe"],
    },
    {
        "name": "Palo Alto Cortex XDR",
        "short": "cortex",
        "services": ["CortexXDR", "CyveraService", "CortexXDRDaemon"],
        "drivers": ["CyvrFsFlt", "CyvrNetFilter"],
        "processes": ["CortexXDR.exe", "cyveraservice.exe", "cyserver.exe"],
    },
    {
        "name": "Lynis / auditd", "short": "linux_audit",
        "services": ["auditd"],
        "drivers": [],
        "processes": ["auditd", "audispd", "osqueryd"],
    },
]


def _run(cmd: List[str], timeout: int = 15) -> Dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": "missing: " + cmd[0]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}


def list_services() -> List[str]:
    osname = platform.system()
    if osname == "Windows":
        r = _run(["sc", "query", "type=", "service", "state=", "all"])
        return re.findall(r"SERVICE_NAME:\s*(\S+)", r["stdout"])
    if shutil.which("systemctl"):
        r = _run(["systemctl", "list-units", "--type=service", "--all", "--no-pager",
                  "--no-legend", "--plain"])
        names = []
        for line in r["stdout"].splitlines():
            parts = line.split()
            if parts:
                names.append(parts[0])
        return names
    return []


def list_drivers() -> List[str]:
    osname = platform.system()
    if osname == "Windows":
        r = _run(["driverquery", "/fo", "csv", "/nh"])
        names = []
        for line in r["stdout"].splitlines():
            m = re.match(r'"([^"]+)"', line)
            if m:
                names.append(m.group(1))
        return names
    if osname == "Linux":
        modules = []
        try:
            modules = Path("/proc/modules").read_text().splitlines()
        except OSError:
            return []
        return [m.split()[0] for m in modules if m.strip()]
    if osname == "Darwin":
        r = _run(["kextstat"])
        return re.findall(r"\s+([a-zA-Z0-9_.]+)\s+\(([^)]+)\)", r["stdout"]) and [
            m[0] for m in re.findall(r"\s+([a-zA-Z0-9_.]+)\s+\([^)]+\)", r["stdout"])] or []
    return []


def list_processes() -> List[Dict]:
    osname = platform.system()
    out = []
    if osname == "Linux":
        for d in Path("/proc").iterdir():
            if not d.name.isdigit():
                continue
            try:
                name = (d / "comm").read_text().strip()
                pid = int(d.name)
                out.append({"pid": pid, "name": name})
            except OSError:
                continue
    elif osname == "Windows":
        r = _run(["tasklist", "/fo", "csv", "/nh"])
        for line in r["stdout"].splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                out.append({"name": parts[0], "pid": parts[1]})
    else:
        r = _run(["ps", "-axo", "pid,comm"])
        for line in r["stdout"].splitlines()[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                out.append({"pid": int(parts[0]), "name": parts[1]})
    return out


def cmd_detect(out_file: str) -> int:
    print_info("av_bypass — local AV/EDR detection")
    print_kv("os", platform.system())
    print()

    svcs = set(list_services())
    drvs = set(list_drivers())
    procs = list_processes()
    proc_names = {p["name"].lower() for p in procs}

    detected = []
    for v in VENDORS:
        hits = {"services": [], "drivers": [], "processes": []}
        for s in v["services"]:
            if s in svcs:
                hits["services"].append(s)
        for d in v["drivers"]:
            if d in drvs or any(d.lower() in x.lower() for x in drvs):
                hits["drivers"].append(d)
        for p in v["processes"]:
            if p.lower() in proc_names:
                hits["processes"].append(p)
        total = sum(len(v2) for v2 in hits.values())
        if total:
            detected.append({"vendor": v["name"], "short": v["short"], "hits": hits, "score": total})

    detected.sort(key=lambda x: -x["score"])
    for d in detected:
        print("  " + SCARLET + "▓ " + RESET + BONE + d["vendor"].ljust(28) + RESET
              + " " + ARTERY + "(score " + str(d["score"]) + ")" + RESET)
        for k, v in d["hits"].items():
            if v:
                print("      " + ASH + k + ": " + ", ".join(v) + RESET)

    print()
    print_kv("vendors found", str(len(detected)))

    out = Path(out_file) if out_file else AVB_DIR / ("detect_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"os": platform.system(), "detected": detected}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_processes(out_file: str) -> int:
    procs = list_processes()
    known = set()
    for v in VENDORS:
        for p in v["processes"]:
            known.add(p.lower())
    hits = [p for p in procs if p["name"].lower() in known]

    print_info("AV/EDR processes running")
    print_kv("count", str(len(hits)))
    print()
    for h in hits:
        print("  " + SCARLET + "▓ " + RESET + BONE + str(h["pid"]).ljust(8) + RESET + h["name"])

    out = Path(out_file) if out_file else AVB_DIR / ("procs_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_drivers(out_file: str) -> int:
    drvs = list_drivers()
    known = set()
    for v in VENDORS:
        for d in v["drivers"]:
            known.add(d.lower())
    hits = [d for d in drvs if d.lower() in known]

    print_info("AV/EDR drivers loaded")
    print_kv("count", str(len(hits)))
    print()
    for h in hits:
        print("  " + SCARLET + "▓ " + RESET + h)

    out = Path(out_file) if out_file else AVB_DIR / ("drivers_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_defender(out_file: str) -> int:
    if platform.system() != "Windows":
        print_warn("Windows Defender status is Windows-only")
        return 1

    print_info("Windows Defender status")
    print()

    if shutil.which("powershell"):
        cmd = ("Get-MpComputerStatus | Select-Object "
               "AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,"
               "AntispywareEnabled,NISEnabled,BehaviorMonitorEnabled,"
               "IoavProtectionEnabled,OnAccessProtectionEnabled | Format-List")
        r = _run(["powershell", "-NoProfile", "-Command", cmd], timeout=30)
        print(r["stdout"])

        cmd2 = "Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring | Format-List"
        r2 = _run(["powershell", "-NoProfile", "-Command", cmd2], timeout=30)
        print(r2["stdout"])

        out = Path(out_file) if out_file else AVB_DIR / ("defender_" + str(int(time.time())) + ".json")
        out.write_text(json.dumps({"status": r["stdout"], "preferences": r2["stdout"]}, indent=2))
        print_kv("saved", out)
        return 0
    else:
        print_err("powershell not found")
        return 1


def cmd_plan(vendor: str, out_file: str) -> int:
    """Detect the current host's AV, then pull the specific bypass sequence
    from the evasion module's cookbook."""
    if not vendor:
        # detect
        print_info("detecting first")
        # run detection silently, capture result
        svcs = set(list_services())
        drvs = set(list_drivers())
        procs = {p["name"].lower() for p in list_processes()}
        best = None
        for v in VENDORS:
            score = sum([
                sum(1 for s in v["services"] if s in svcs),
                sum(1 for d in v["drivers"] if any(d.lower() in x.lower() for x in drvs)),
                sum(1 for p in v["processes"] if p.lower() in procs),
            ])
            if score and (best is None or score > best[1]):
                best = (v, score)
        if not best:
            print_warn("no AV/EDR detected on this host")
            return 0
        vendor = best[0]["short"]
        print_kv("detected", best[0]["name"])

    print()
    print_info("bypass plan — pulling from evasion.av_bypass cookbook")

    # Import from the evasion module
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    try:
        from Program.evasion import av_bypass as ref
        plan = ref.cmd_plan(vendor, "", out_file)
        return plan
    except ImportError as e:
        print_err("could not import evasion.av_bypass: " + str(e))
        print_info("run: redsky evasion av plan " + vendor)
        return 1


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky av_bypass detect", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="detect",
                   choices=["detect", "processes", "drivers", "defender", "plan"])
    p.add_argument("vendor", nargs="?", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky av_bypass detect <detect|processes|drivers|defender|plan>")
        return 2

    if ns.help:
        print_info("detect                     -- scan for AV/EDR products on this host")
        print_info("processes                  -- AV/EDR processes with PIDs")
        print_info("drivers                    -- loaded AV/EDR kernel drivers")
        print_info("defender                   -- Windows Defender live status")
        print_info("plan [vendor]              -- detection + bypass sequence")
        return 0

    if ns.action == "detect":
        return cmd_detect(ns.out)
    if ns.action == "processes":
        return cmd_processes(ns.out)
    if ns.action == "drivers":
        return cmd_drivers(ns.out)
    if ns.action == "defender":
        return cmd_defender(ns.out)
    if ns.action == "plan":
        return cmd_plan(ns.vendor, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

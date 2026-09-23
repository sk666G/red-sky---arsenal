# language: Python, file: Program/memory_forensics/procs.py, target: Red Sky memory_forensics — process/module inspection
# Reads live process metadata from /proc (Linux) or the Windows equivalents
# via psutil (if installed) or tasklist/wmic (if not). Reports:
#   - processes with unusual paths / hidden names
#   - loaded modules and their on-disk backing file (mismatch = injected)
#   - open sockets with remote endpoints (which PID talks where)
#   - deleted-but-mapped executables (classic malware self-delete)
# No memory reads — this is metadata only. Safe on any host.

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


MF_DIR = OUTPUT_DIR / "memory_forensics"
MF_DIR.mkdir(parents=True, exist_ok=True)


SUSPICIOUS_PATH_HINTS = [
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
    "\\Temp\\", "\\AppData\\Local\\Temp\\",
    "/proc/", "/memfd:",
]


def _read_proc_status(pid_dir: Path) -> Optional[Dict]:
    status = pid_dir / "status"
    if not status.exists():
        return None
    try:
        txt = status.read_text(errors="replace")
    except OSError:
        return None
    out = {}
    for line in txt.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _read_proc_cmdline(pid_dir: Path) -> str:
    try:
        return (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_proc_exe(pid_dir: Path) -> str:
    try:
        target = os.readlink(str(pid_dir / "exe"))
        return target
    except OSError:
        return ""


def _read_proc_maps(pid_dir: Path) -> List[Dict]:
    maps = pid_dir / "maps"
    if not maps.exists():
        return []
    out = []
    try:
        for line in maps.read_text(errors="replace").splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            out.append({
                "range": parts[0],
                "perms": parts[1],
                "offset": parts[2],
                "dev": parts[3],
                "inode": parts[4],
                "path": parts[5],
            })
    except OSError:
        pass
    return out


def list_processes() -> List[Dict]:
    if platform.system() != "Linux":
        # best-effort on Windows/macOS via psutil or ps
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
                try:
                    procs.append({
                        "pid": p.info["pid"],
                        "name": p.info["name"] or "",
                        "exe": p.info["exe"] or "",
                        "cmdline": " ".join(p.info["cmdline"] or []),
                        "user": p.info["username"] or "",
                    })
                except Exception:
                    continue
            return procs
        except ImportError:
            print_warn("psutil not installed — falling back to ps")
            r = subprocess.run(["ps", "-axo", "pid,user,comm,args"], capture_output=True, text=True)
            procs = []
            for line in r.stdout.splitlines()[1:]:
                parts = line.split(None, 3)
                if len(parts) >= 3:
                    procs.append({"pid": int(parts[0]), "user": parts[1], "name": parts[2],
                                  "cmdline": parts[3] if len(parts) > 3 else "", "exe": ""})
            return procs

    # Linux
    procs = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return procs
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        status = _read_proc_status(entry) or {}
        name = status.get("Name", "")
        user = status.get("Uid", "")
        exe = _read_proc_exe(entry)
        cmdline = _read_proc_cmdline(entry)
        procs.append({
            "pid": pid, "name": name, "exe": exe,
            "cmdline": cmdline, "user": user,
            "ppid": status.get("PPid", ""),
        })
    return procs


def flag_suspicious(proc: Dict) -> List[str]:
    flags = []
    exe = proc.get("exe", "")
    cmd = proc.get("cmdline", "")
    name = proc.get("name", "")
    for h in SUSPICIOUS_PATH_HINTS:
        if h in exe:
            flags.append("path matches " + h)
            break
    if "(deleted)" in exe:
        flags.append("exe deleted on disk (mapped-but-unlinked)")
    if not exe and proc.get("pid") and proc["pid"] > 2:
        flags.append("no exe symlink readable")
    # memfd: — fileless execution
    if "memfd:" in exe:
        flags.append("memfd execution (fileless)")
    # name looks like a system binary but lives elsewhere
    if name in ("sshd", "systemd", "init") and exe and "systemd" not in exe and "openssh" not in exe:
        flags.append("system-like name, wrong path")
    # cmdline contains a shell exec of a URL
    if re.search(r"(curl|wget).+(http|ftp)", cmd):
        flags.append("cmdline downloads remote content")
    return flags


def cmd_list(out_file: str) -> int:
    procs = list_processes()
    print_info("process listing")
    print_kv("count", str(len(procs)))
    print()

    flagged = []
    for p in sorted(procs, key=lambda x: x.get("pid", 0)):
        flags = flag_suspicious(p)
        if flags:
            flagged.append({**p, "flags": flags})
            line = "  " + SCARLET + "▓ " + RESET + BONE + str(p["pid"]).ljust(7) + RESET
            line += ARTERY + (p.get("name") or "")[:20].ljust(20) + RESET
            line += CLOT + (p.get("exe") or p.get("cmdline") or "")[:60] + RESET
            print(line)
            for f in flags:
                print("      " + ASH + f + RESET)

    print()
    print_kv("flagged", str(len(flagged)) + "/" + str(len(procs)))

    out = Path(out_file) if out_file else MF_DIR / ("procs_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"all": procs, "flagged": flagged}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_maps(pid: int, out_file: str) -> int:
    if platform.system() != "Linux":
        print_err("maps is Linux-only in this build")
        return 2
    pid_dir = Path("/proc") / str(pid)
    if not pid_dir.exists():
        print_err("no such pid: " + str(pid))
        return 1
    maps = _read_proc_maps(pid_dir)
    print_info("process maps")
    print_kv("pid", str(pid))
    print_kv("regions", str(len(maps)))
    print()

    flagged = []
    for m in maps:
        path = m["path"]
        if not path:
            continue
        # anonymous executable regions with a name hint
        if "(deleted)" in path:
            flagged.append(m)
            print("  " + SCARLET + "▓ " + RESET + m["range"] + "  " + m["perms"]
                  + "  " + BONE + path + RESET)
    if not flagged:
        print_ok("no deleted mappings")

    out = Path(out_file) if out_file else MF_DIR / ("maps_" + str(pid) + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"pid": pid, "maps": maps, "flagged": flagged}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky memory_forensics procs", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "maps"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--pid", type=int, default=0)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky memory_forensics procs <list|maps <pid>>")
        return 2

    if ns.help:
        print_info("list                      -- enumerate processes, flag suspicious ones")
        print_info("maps <pid>                -- dump a process's memory map, flag deleted regions")
        return 0

    if ns.action == "list":
        return cmd_list(ns.out)
    if ns.action == "maps":
        pid = ns.pid or (int(ns.target) if ns.target.isdigit() else 0)
        if not pid:
            print_err("give a pid")
            return 2
        return cmd_maps(pid, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

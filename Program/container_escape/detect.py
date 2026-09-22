# language: Python, file: Program/container_escape/detect.py, target: Red Sky container_escape — detection
# Figures out where we're running: Docker, containerd, K8s pod, LXC, gVisor,
# or bare metal. Reads /proc, cgroups, environment, and known filesystem markers.

import json
import os
import sys
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


CE_DIR = OUTPUT_DIR / "container_escape"


def _read(path, default=""):
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return default


def _exists(path):
    return Path(path).exists()


def detect_environment() -> Dict:
    env = {
        "is_container": False,
        "runtime": "unknown",
        "orchestrator": "unknown",
        "indicators": [],
    }

    # 1. docker env marker
    if _exists("/.dockerenv"):
        env["is_container"] = True
        env["runtime"] = "docker"
        env["indicators"].append("/.dockerenv present")

    # 2. containerd / k8s env marker
    if _exists("/run/.containerenv"):
        env["is_container"] = True
        if env["runtime"] == "unknown":
            env["runtime"] = "podman-or-containerd"
        env["indicators"].append("/run/.containerenv present")

    # 3. cgroup path
    cgroup = _read("/proc/1/cgroup")
    if cgroup:
        if "docker" in cgroup:
            env["is_container"] = True
            env["runtime"] = "docker"
            env["indicators"].append("cgroup references docker")
        if "kubepods" in cgroup:
            env["is_container"] = True
            env["orchestrator"] = "kubernetes"
            env["indicators"].append("cgroup references kubepods")
        if "containerd" in cgroup:
            env["is_container"] = True
            env["runtime"] = "containerd"
            env["indicators"].append("cgroup references containerd")
        if "lxc" in cgroup:
            env["is_container"] = True
            env["runtime"] = "lxc"
            env["indicators"].append("cgroup references lxc")

    # 4. k8s environment variables
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        env["is_container"] = True
        env["orchestrator"] = "kubernetes"
        env["indicators"].append("KUBERNETES_SERVICE_HOST set")

    # 5. service account token — k8s
    if _exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
        env["orchestrator"] = "kubernetes"
        env["indicators"].append("k8s service account token mounted")

    # 6. gVisor — check uname and dmesg
    uname = os.uname()
    if "gvisor" in uname.release.lower():
        env["runtime"] = "gvisor"
        env["indicators"].append("uname release contains gvisor")
    if _exists("/proc/self/status"):
        status = _read("/proc/self/status")
        if "gVisor" in status or "runsc" in status:
            env["indicators"].append("proc/self/status mentions gVisor/runsc")
            env["runtime"] = "gvisor"

    # 7. hostname heuristic — docker defaults to short hex names
    hostname = os.uname().nodename
    env["hostname"] = hostname
    if len(hostname) == 12 and all(c in "0123456789abcdef" for c in hostname):
        env["indicators"].append("hostname looks like a Docker container ID")

    # 8. capabilities
    status = _read("/proc/self/status")
    caps_lines = [l for l in status.splitlines() if l.startswith("CapEff:")]
    env["cap_effective_hex"] = caps_lines[0].split()[1] if caps_lines else ""
    if env["cap_effective_hex"]:
        cap = int(env["cap_effective_hex"], 16)
        env["cap_sys_admin"] = bool(cap & (1 << 21))
        env["cap_sys_ptrace"] = bool(cap & (1 << 19))
        env["cap_sys_module"] = bool(cap & (1 << 16))
        env["cap_dac_read_search"] = bool(cap & (1 << 2))
        env["cap_net_admin"] = bool(cap & (1 << 12))
        env["cap_net_raw"] = bool(cap & (1 << 13))
        env["cap_mknod"] = bool(cap & (1 << 27))
        if cap == 0x000001ffffffffff:
            env["privileged"] = True
            env["indicators"].append("full capability set — container is privileged")
        else:
            env["privileged"] = False

    # 9. mounted sockets
    env["docker_sock"] = _exists("/var/run/docker.sock")
    env["containerd_sock"] = _exists("/run/containerd/containerd.sock")
    env["crio_sock"] = _exists("/var/run/crio/crio.sock")
    if env["docker_sock"]:
        env["indicators"].append("/var/run/docker.sock mounted")
    if env["containerd_sock"]:
        env["indicators"].append("/run/containerd/containerd.sock mounted")

    # 10. /proc/1/root vs / — different inode = we can see host root
    try:
        root_inode = os.stat("/").st_ino
        host_inode = os.stat("/proc/1/root").st_ino
        env["proc1_root_differs"] = root_inode != host_inode
        if env["proc1_root_differs"]:
            env["indicators"].append("/proc/1/root is a different filesystem")
    except OSError:
        env["proc1_root_differs"] = False

    # 11. /proc/1/status — is PID 1 our process or host init?
    p1 = _read("/proc/1/comm")
    env["pid1"] = p1
    if p1 not in ("systemd", "init", "launchd"):
        env["indicators"].append(f"PID 1 is {p1} — we're in a container")

    # 12. mount check — overlayfs means container
    mounts = _read("/proc/mounts")
    if "overlay" in mounts:
        env["is_container"] = True
        env["indicators"].append("overlayfs root — container filesystem")

    # 13. network namespace check
    try:
        net_ns_self = os.readlink("/proc/self/ns/net")
        net_ns_init = os.readlink("/proc/1/ns/net")
        env["net_ns_shared_with_init"] = (net_ns_self == net_ns_init)
    except OSError:
        env["net_ns_shared_with_init"] = False

    return env


def cmd_detect() -> int:
    CE_DIR.mkdir(parents=True, exist_ok=True)
    print_info("container / orchestrator detection")
    print()

    env = detect_environment()

    print_kv("in container", "yes" if env["is_container"] else "no")
    print_kv("runtime", env["runtime"])
    print_kv("orchestrator", env["orchestrator"])
    print_kv("hostname", env["hostname"])
    print_kv("pid 1", env["pid1"])
    print_kv("privileged", "yes" if env.get("privileged") else "no")
    print()
    print(f"{ARTERY}{BOLD}── capabilities{RESET}")
    for cap in ("cap_sys_admin", "cap_sys_ptrace", "cap_sys_module",
                "cap_dac_read_search", "cap_net_admin", "cap_net_raw", "cap_mknod"):
        val = env.get(cap, False)
        mark = f"{SCARLET}▓{RESET}" if val else f"{ASH}░{RESET}"
        print(f"  {mark} {BONE}{cap}{RESET}")
    print()
    print(f"{ARTERY}{BOLD}── sockets{RESET}")
    for sock in ("docker_sock", "containerd_sock", "crio_sock"):
        mark = f"{SCARLET}▓{RESET}" if env.get(sock) else f"{ASH}░{RESET}"
        print(f"  {mark} {BONE}{sock}{RESET}")
    print()
    print(f"{ARTERY}{BOLD}── escape hints{RESET}")
    hints = []
    if env.get("privileged"):
        hints.append("privileged container — mount /, chroot /proc/1/root, or load a kernel module")
    if env.get("docker_sock"):
        hints.append("docker socket mounted — `docker run -v /:/host --privileged`")
    if env.get("containerd_sock"):
        hints.append("containerd socket mounted — use ctr / nerdctl")
    if env.get("cap_sys_admin"):
        hints.append("CAP_SYS_ADMIN — can mount filesystems and use cgroup v1 release_agent")
    if env.get("cap_sys_ptrace"):
        hints.append("CAP_SYS_PTRACE — can inject into host processes if PID namespaces are shared")
    if env.get("cap_net_admin") and env.get("cap_net_raw"):
        hints.append("CAP_NET_ADMIN+RAW — network attacks, can craft raw packets")
    if env.get("proc1_root_differs"):
        hints.append("/proc/1/root is host — chroot /proc/1/root to enter host namespace")
    if env.get("net_ns_shared_with_init"):
        hints.append("network namespace shared with PID 1 — likely host network")
    if not hints:
        hints.append("no obvious escape primitive detected — standard container hardening in place")
    for h in hints:
        print(f"  {ARTERY}▓{RESET} {BONE}{h}{RESET}")
    print()

    out = CE_DIR / f"detect_{int(os.getpid())}.json"
    out.write_text(json.dumps(env, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    if not args or args[0] in ("detect", "d"):
        return cmd_detect()
    print_err(f"unknown detect sub-command: {args[0]}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

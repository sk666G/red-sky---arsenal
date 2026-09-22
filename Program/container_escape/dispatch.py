# language: Python, file: Program/container_escape/dispatch.py, target: Red Sky container_escape router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky container_escape <sub-command> [args...]")
    print_info("")
    print_info("  detect                     container / runtime / caps fingerprint")
    print_info("")
    print_info("  docker <list|run TECHNIQUE|all>")
    print_info("      docker escapes: docker-sock, privileged, proc-root, hostpath, cgroup, core-pattern")
    print_info("")
    print_info("  k8s <list|run TECHNIQUE|all>")
    print_info("      k8s escapes: privileged, host-pid, hostpath, kubelet, sa-token, node-tokens")
    print_info("")
    print_info("  cgroup <list|run TECHNIQUE|all>")
    print_info("      kernel escapes: cgroup-v1, cgroup-v2, core-pattern, modprobe, sysrq, hotplug, insmod")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("detect", "d"):
        from .detect import run_cli as _d
        return int(_d(args[1:]))
    if sub in ("docker", "dock"):
        from .docker import run_cli as _dk
        return int(_dk(args[1:]))
    if sub in ("k8s", "kubernetes"):
        from .k8s import run_cli as _k
        return int(_k(args[1:]))
    if sub in ("cgroup", "cg", "kernel"):
        from .cgroup import run_cli as _c
        return int(_c(args[1:]))

    print_err(f"unknown container_escape sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

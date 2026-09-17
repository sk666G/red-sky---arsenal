# language: Python, file: Program/recon/fingerprint.py, target: Red Sky recon — fingerprint
# TCP connect scan + banner grab + service ID. No external binaries.

import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet, print_table
from Program.utils.paths import OUTPUT_DIR


# top service ports — fast default scan
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 2049, 2222,
    2375, 2376, 3000, 3306, 3389, 4443, 5000, 5432, 5601, 5900, 5984, 6379,
    7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9443, 10000,
    11211, 27017, 50000,
]

SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2222: "ssh", 2375: "docker", 2376: "docker-tls",
    3000: "http", 3306: "mysql", 3389: "rdp", 4443: "https", 5000: "http",
    5432: "postgres", 5601: "kibana", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 7001: "weblogic", 8000: "http", 8008: "http", 8080: "http",
    8081: "http", 8443: "https", 8888: "http", 9000: "http", 9090: "http",
    9200: "elasticsearch", 9443: "https", 10000: "webmin",
    11211: "memcached", 27017: "mongodb", 50000: "db2",
}


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)

        if port in (443, 8443, 9443, 4443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(s, server_hostname=host)
                cert = ss.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")
                issuer = dict(x[0] for x in cert.get("issuer", []))
                iss = issuer.get("organizationName", "") or issuer.get("commonName", "")
                return f"TLS cn={cn} issuer={iss}"
            except Exception:
                pass

        # probe common protocols
        probes = [b"\r\n"]
        if port in (80, 8000, 8008, 8080, 8081, 8888, 9000, 9090):
            probes = [b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"]
        elif port == 22:
            probes = [b""]
        elif port == 25:
            probes = [b"EHLO probe\r\n"]

        for p in probes:
            try:
                if p:
                    s.sendall(p)
                data = s.recv(2048)
                if data:
                    text = data.decode("utf-8", errors="replace")
                    first = text.splitlines()[0] if text.splitlines() else text
                    return first[:120]
            except socket.timeout:
                continue

        return ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _scan_port(host: str, port: int, timeout: float) -> Optional[dict]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
        if rc == 0:
            return {"port": port, "state": "open"}
        return None
    except OSError:
        return None
    finally:
        s.close()


def _parse_ports(spec: str) -> List[int]:
    ports = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        elif chunk:
            ports.append(int(chunk))
    return sorted(set(ports))


def cmd_scan(host: str, portspec: str, threads: int = 256, timeout: float = 1.0) -> int:
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print_err(f"cannot resolve {host}")
        return 1

    ports = _parse_ports(portspec) if portspec else DEFAULT_PORTS
    print_info(f"scanning {host} ({ip}) — {len(ports)} ports, {threads} threads")
    print()

    open_ports: List[dict] = []
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_scan_port, ip, p, timeout): p for p in ports}
        for f in as_completed(futs):
            r = f.result()
            if r:
                open_ports.append(r)
                print_ok(f"port {r['port']:<5} open")

    open_ports.sort(key=lambda x: x["port"])

    if open_ports:
        print()
        print_info("grabbing banners on open ports")
        for p in open_ports:
            svc = SERVICE_MAP.get(p["port"], "unknown")
            banner = _grab_banner(ip, p["port"])
            p["service"] = svc
            p["banner"] = banner
            line = f"  {ARTERY}▓{RESET} {BONE}{p['port']:<5}{RESET} {SCARLET}{svc:<14}{RESET}"
            if banner:
                line += f" {ASH}{banner}{RESET}"
            print(line)

    dt = time.time() - t0
    print()
    print_kv("open", len(open_ports))
    print_kv("elapsed", f"{dt:.2f}s")

    out = OUTPUT_DIR / f"scan_{host}_{int(time.time())}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for p in open_ports:
            f.write(f"{p['port']}\t{p.get('service','')}\t{p.get('banner','')}\n")
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky recon fingerprint <host> [ports] [threads]")
        print_err("  ports: 22,80,443 or 1-1024 or 'default'")
        return 2

    host = args[0]
    portspec = args[1] if len(args) > 1 else "default"
    if portspec == "default":
        portspec = ""
    threads = int(args[2]) if len(args) > 2 else 256
    return cmd_scan(host, portspec, threads)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

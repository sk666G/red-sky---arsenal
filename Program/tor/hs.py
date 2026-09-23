# language: Python, file: Program/tor/hs.py, target: Red Sky tor — hidden service management
# Manages .onion services via the tor ControlPort protocol. Subcommands:
#   create    -- ADD_ONION <keytype>:<keyblob>, Flags=Detach, Port=<vport>,<target>
#   destroy   -- DEL_ONION <service_id>
#   list      -- GETINFO onions/current + onions/detached
#   rotate    -- destroy + create with a fresh key (new onion address)
#   backup    -- pull the current keys so the service survives a tor restart
#   restore   -- ADD_ONION with a saved key, returns the same .onion address
#   status    -- GETINFO status/circuit-established + bootstrap phase
# Also writes a torrc for a permanent service when you want persistence across
# tor restarts (as opposed to Detached ephemeral keys).

import argparse
import base64
import hashlib
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


TOR_DIR = OUTPUT_DIR / "tor"
HS_DIR = TOR_DIR / "hs"
HS_DIR.mkdir(parents=True, exist_ok=True)
TORRC_DIR = HS_DIR / "torrc"
TORRC_DIR.mkdir(parents=True, exist_ok=True)


# ── tor control protocol ──
class TorControl:
    def __init__(self, host: str = "127.0.0.1", port: int = 9051,
                 password: str = "", cookie_path: str = "",
                 timeout: float = 10.0):
        self.host = host
        self.port = port
        self.password = password
        self.cookie_path = cookie_path
        self.timeout = timeout

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        # read the initial greeting (250-...)
        self._read_reply()
        self._authenticate()
        return self

    def __exit__(self, *args):
        try:
            self._send("QUIT")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def _read_reply(self) -> str:
        lines = []
        while True:
            buf = b""
            while not buf.endswith(b"\r\n"):
                chunk = self.sock.recv(1)
                if not chunk:
                    break
                buf += chunk
            line = buf.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            # multiline: "250-key=value"; final: "250 key=value" or "250 OK"
            if len(line) >= 4 and line[3] == " ":
                break
        return "\n".join(lines)

    def _send(self, cmd: str) -> str:
        self.sock.sendall((cmd + "\r\n").encode())
        return self._read_reply()

    def _authenticate(self) -> None:
        if self.cookie_path:
            p = Path(self.cookie_path).expanduser()
            if p.exists():
                cookie = base64.b64encode(p.read_bytes()).decode()
                r = self._send("AUTHENTICATE " + cookie)
                if "250 OK" in r:
                    return
        if self.password:
            r = self._send("AUTHENTICATE \"" + self.password + "\"")
            if "250 OK" in r:
                return
        r = self._send("AUTHENTICATE")
        if "250 OK" not in r and "Authentication failed" in r:
            raise RuntimeError("tor control auth failed: " + r)

    def cmd(self, c: str) -> str:
        return self._send(c)


def _onion_from_pubkey(key_type: str, key_blob: str) -> str:
    """Compute the .onion address from a base64 key blob. v3 only.
    v3 onion = base32(pubkey[32] || checksum[2] || version[1]) + '.onion'
    key_blob from ADD_ONION is the raw 64-byte ed25519 private key encoded
    in base64; the pubkey is bytes[32:64]."""
    raw = base64.b64decode(key_blob)
    if key_type.upper() == "ED25519-V3" and len(raw) == 64:
        pub = raw[32:64]
    elif key_type.upper() == "NEW" or not key_type:
        return ""
    else:
        return ""
    version = b"\x03"
    checksum_input = b".onion checksum" + pub + version
    checksum = hashlib.sha3_256(checksum_input).digest()[:2]
    addr_bytes = pub + checksum + version
    b32 = base64.b32encode(addr_bytes).decode("ascii").lower().rstrip("=")
    return b32 + ".onion"


# ── parse ADD_ONION responses ──
def _parse_onion_response(resp: str) -> Dict:
    out = {"service_id": "", "private_key": "", "raw": resp}
    for line in resp.splitlines():
        l = line.strip()
        if l.startswith("250-ServiceID="):
            out["service_id"] = l.split("=", 1)[1]
        elif l.startswith("250-PrivateKey="):
            out["private_key"] = l.split("=", 1)[1]
        elif l.startswith("250-Ok"):
            pass
    return out


# ── commands ──
def cmd_create(vport: int, target: str, key_type: str, key_blob: str,
               host: str, port: int, password: str, cookie: str,
               out_file: str) -> int:
    print_info("tor: ADD_ONION")
    print_kv("control", host + ":" + str(port))
    print_kv("vport", str(vport))
    print_kv("target", target)
    print_kv("key_type", key_type or "(ephemeral)")

    # build the ADD_ONION string
    if key_blob:
        key_spec = (key_type or "ED25519-V3") + ":" + key_blob
    else:
        key_spec = "NEW:" + (key_type or "ED25519-V3")

    cmd = "ADD_ONION " + key_spec + " Flags=Detach Port=" + str(vport) + "," + target

    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd(cmd)
            parsed = _parse_onion_response(resp)
    except Exception as e:
        print_err("control connection failed: " + str(e))
        return 1

    if not parsed["service_id"]:
        print_err("no ServiceID in response: " + parsed["raw"][:200])
        return 1

    print_ok("hidden service created")
    print_kv("onion", parsed["service_id"] + ".onion")
    if parsed["private_key"]:
        print_kv("key_type", parsed["private_key"].split(":", 1)[0])
        # do NOT print the full private key to stdout — save it
        print_info("private key saved to disk (not printed)")

    out = Path(out_file) if out_file else HS_DIR / ("hs_" + parsed["service_id"][:16] + ".json")
    out.write_text(json.dumps({
        "service_id": parsed["service_id"],
        "private_key": parsed["private_key"],
        "vport": vport, "target": target, "ts": time.time(),
    }, indent=2))
    print_kv("saved", out)
    print()
    print_info("the key is in that JSON — keep it safe or the service dies with tor")
    print_info("to reuse:  redsky tor hs create --vport " + str(vport) + " --target " + target
              + " --key-type " + parsed["private_key"].split(":", 1)[0]
              + " --key-blob <base64 from the JSON>")
    return 0


def cmd_destroy(service_id: str, host: str, port: int, password: str, cookie: str) -> int:
    if not service_id:
        print_err("--service-id required (the .onion address or short service id)")
        return 2
    sid = service_id.replace(".onion", "")
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd("DEL_ONION " + sid)
    except Exception as e:
        print_err("control connection failed: " + str(e))
        return 1
    if "250 OK" in resp:
        print_ok("service destroyed: " + sid)
        return 0
    print_err("destroy failed: " + resp[:200])
    return 1


def cmd_list(host: str, port: int, password: str, cookie: str, out_file: str) -> int:
    try:
        with TorControl(host, port, password, cookie) as tc:
            cur = tc.cmd("GETINFO onions/current")
            det = tc.cmd("GETINFO onions/detached")
    except Exception as e:
        print_err("control connection failed: " + str(e))
        return 1

    def _extract(resp: str) -> List[str]:
        ids = []
        for line in resp.splitlines():
            l = line.strip()
            if l.startswith("250-onions/current=") or l.startswith("250-onions/detached="):
                val = l.split("=", 1)[1]
                if val:
                    ids.append(val)
            elif "=" in l and l[4:].startswith("onions/"):
                # multiline where each ID is its own "250-onions/current=xxx" line
                parts = l.split("=", 1)
                if len(parts) == 2 and parts[1]:
                    ids.append(parts[1])
        return ids

    current = _extract(cur)
    detached = _extract(det)

    print_info("hidden services")
    print_kv("current (persistent)", str(len(current)))
    for sid in current:
        print("  " + SCARLET + "▓ " + RESET + BONE + sid + ".onion" + RESET)
    print()
    print_kv("detached (ephemeral)", str(len(detached)))
    for sid in detached:
        print("  " + ARTERY + "░ " + RESET + BONE + sid + ".onion" + RESET)

    out = Path(out_file) if out_file else HS_DIR / ("list_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"current": current, "detached": detached}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_rotate(service_id: str, vport: int, target: str,
               host: str, port: int, password: str, cookie: str,
               out_file: str) -> int:
    """Destroy the service and create a new one with a fresh key -> new onion."""
    if service_id:
        print_info("destroying old service: " + service_id)
        cmd_destroy(service_id, host, port, password, cookie)
    print()
    print_info("creating replacement with a fresh key")
    return cmd_create(vport, target, "", "", host, port, password, cookie, out_file)


def cmd_backup(host: str, port: int, password: str, cookie: str, out_dir: str) -> int:
    """Export every current service's key material to disk."""
    try:
        with TorControl(host, port, password, cookie) as tc:
            cur = tc.cmd("GETINFO onions/current")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1

    ids = []
    for line in cur.splitlines():
        l = line.strip()
        if "=" in l and l[4:].startswith("onions/"):
            parts = l.split("=", 1)
            if len(parts) == 2 and parts[1]:
                ids.append(parts[1])

    if not ids:
        print_warn("no services to back up")
        return 0

    target = Path(out_dir) if out_dir else HS_DIR / "backup"
    target.mkdir(parents=True, exist_ok=True)

    backed = 0
    for sid in ids:
        try:
            with TorControl(host, port, password, cookie) as tc:
                resp = tc.cmd("GETINFO onions/" + sid)
        except Exception as e:
            print_warn("cannot query " + sid + ": " + str(e))
            continue
        # tor returns the key in the PrivateKey= field
        key = ""
        for line in resp.splitlines():
            if "PrivateKey=" in line:
                key = line.split("PrivateKey=", 1)[1].strip()
        if not key:
            print_warn("no key material for " + sid)
            continue
        (target / (sid + ".key")).write_text(key)
        backed += 1
        print_ok(sid + ".onion  ->  " + str(target / (sid + ".key")))

    print()
    print_kv("backed up", str(backed))
    print_warn("keep these files offline — anyone with the key owns the onion")
    return 0


def cmd_status(host: str, port: int, password: str, cookie: str, out_file: str) -> int:
    try:
        with TorControl(host, port, password, cookie) as tc:
            est = tc.cmd("GETINFO status/circuit-established")
            boot = tc.cmd("GETINFO status/bootstrap-phase")
            ver = tc.cmd("GETINFO version")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1

    def _val(resp: str) -> str:
        for line in resp.splitlines():
            l = line.strip()
            if l.startswith("250-") or l.startswith("250 "):
                if "=" in l:
                    return l.split("=", 1)[1]
        return ""

    print_info("tor status")
    print_kv("circuit established", _val(est) or "unknown")
    print_kv("bootstrap", _val(boot) or "unknown")
    print_kv("version", _val(ver) or "unknown")

    out = Path(out_file) if out_file else HS_DIR / ("status_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "circuit_established": _val(est),
        "bootstrap": _val(boot),
        "version": _val(ver),
    }, indent=2))
    print_kv("saved", out)
    return 0


def cmd_torrc(name: str, vport: int, target: str, hs_port: int,
              data_dir: str, out_file: str) -> int:
    """Write a torrc that starts a persistent hidden service at tor startup.
    Use this instead of ADD_ONION when you want the service to survive a restart
    without re-injecting the key."""
    target_dir = Path(data_dir) if data_dir else TORRC_DIR / name
    target_dir.mkdir(parents=True, exist_ok=True)

    torrc = (
        "# Red Sky — hidden service torrc\n"
        "SocksPort " + str(9050) + "\n"
        "ControlPort " + str(hs_port) + "\n"
        "CookieAuthentication 1\n"
        "DataDirectory " + str(target_dir / "tor-data") + "\n"
        "\n"
        "HiddenServiceDir " + str(target_dir / "hs") + "\n"
        "HiddenServicePort " + str(vport) + " " + target + "\n"
        "HiddenServiceVersion 3\n"
    )
    out = Path(out_file) if out_file else target_dir / "torrc"
    out.write_text(torrc)
    print_ok("wrote " + str(out))
    print_info("run: tor -f " + str(out))
    print_info("the .onion address appears in " + str(target_dir / "hs" / "hostname"))
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky tor hs", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["create", "destroy", "list", "rotate", "backup",
                            "status", "torrc", "help"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9051)
    p.add_argument("--password", default="")
    p.add_argument("--cookie", default="")
    p.add_argument("--vport", type=int, default=80, help="virtual (onion) port")
    p.add_argument("--target", default="127.0.0.1:80", help="host:port to forward to")
    p.add_argument("--key-type", default="")
    p.add_argument("--key-blob", default="")
    p.add_argument("--service-id", default="")
    p.add_argument("--name", default="svc", help="for torrc: directory name")
    p.add_argument("--data-dir", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky tor hs <create|destroy|list|rotate|backup|status|torrc> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("create --vport 80 --target 127.0.0.1:8080  [--key-type ED25519-V3 --key-blob BASE64]")
        print_info("destroy --service-id abc...xyz")
        print_info("list")
        print_info("rotate --service-id abc...xyz --vport 80 --target 127.0.0.1:8080")
        print_info("backup [--out dir]")
        print_info("status")
        print_info("torrc --name svc --vport 80 --target 127.0.0.1:8080")
        print_info("")
        print_info("control defaults: --host 127.0.0.1 --port 9051")
        print_info("auth: --password X or --cookie /run/tor/control.authcookie")
        return 0

    if ns.action == "create":
        return cmd_create(ns.vport, ns.target, ns.key_type, ns.key_blob,
                          ns.host, ns.port, ns.password, ns.cookie, ns.out)
    if ns.action == "destroy":
        return cmd_destroy(ns.service_id, ns.host, ns.port, ns.password, ns.cookie)
    if ns.action == "list":
        return cmd_list(ns.host, ns.port, ns.password, ns.cookie, ns.out)
    if ns.action == "rotate":
        return cmd_rotate(ns.service_id, ns.vport, ns.target,
                          ns.host, ns.port, ns.password, ns.cookie, ns.out)
    if ns.action == "backup":
        return cmd_backup(ns.host, ns.port, ns.password, ns.cookie, ns.out)
    if ns.action == "status":
        return cmd_status(ns.host, ns.port, ns.password, ns.cookie, ns.out)
    if ns.action == "torrc":
        return cmd_torrc(ns.name, ns.vport, ns.target, ns.port, ns.data_dir, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

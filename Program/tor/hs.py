# language: Python, file: Program/tor/hs.py, target: Red Sky tor — hidden service control
# Tor hidden service (v3 onion) management. Two paths:
#
#   1. Stem library. If `stem` is installed, uses the control port with
#      AUTHENTICATE, ADD_ONION, DEL_ONION commands over the protocol.
#
#   2. Raw control port. Falls back to a socket + CRLF-terminated commands
#      if stem is not available. The Tor control protocol is line-based —
#      it is short enough to drive by hand.
#
# Operations:
#   create    build a new v3 hidden service (ed25519 keypair)
#   delete    remove the service (by ServiceID)
#   list      list active hidden services on the control port
#   info      get descriptors and connection info for a ServiceID
#   keygen    generate an on-disk keypair without registering with the daemon
#
# Control port auth:
#   - COOKIE: read the cookie file (default /var/lib/tor/control_auth_cookie)
#   - PASSWORD: password set in torrc `HashedControlPassword`
#   - NULL: no auth (rare, dangerous)

import base64
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


TOR_DIR = OUTPUT_DIR / "tor"
HS_DIR = TOR_DIR / "hidden_services"


# ── control port client ────────────────────────────────────────────────────

class TorControl:
    """Minimal control-port client. Falls back from stem if stem missing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9051,
                 password: str = "", cookie_path: str = ""):
        self.host = host
        self.port = port
        self.password = password
        self.cookie_path = cookie_path or "/var/lib/tor/control_auth_cookie"
        self.sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=8)
            self.sock.settimeout(8)
        except Exception as e:
            print_err("connect " + self.host + ":" + str(self.port) + " — " + str(e))
            return False
        # read PROTOCOLINFO or AUTHCHALLENGE prompt
        try:
            banner = self.sock.recv(4096).decode("latin-1", errors="replace")
        except socket.timeout:
            banner = ""
        return self._auth(banner)

    def _send(self, line: str) -> str:
        if not self.sock:
            return ""
        try:
            self.sock.sendall((line + "\r\n").encode())
            buf = b""
            self.sock.settimeout(8)
            while True:
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\r\n" in buf:
                        # check if last line starts with digit+space (final reply)
                        lines = buf.split(b"\r\n")
                        for ln in reversed(lines):
                            if ln and (ln[0:1].isdigit() and len(ln) >= 4 and ln[3:4] == b" "):
                                return buf.decode("latin-1", errors="replace")
                except socket.timeout:
                    break
            return buf.decode("latin-1", errors="replace")
        except Exception as e:
            return "ERROR: " + str(e)

    def _auth(self, banner: str) -> bool:
        # try cookie first
        if self.cookie_path and os.path.exists(self.cookie_path):
            try:
                cookie = Path(self.cookie_path).read_bytes()
                hex_cookie = cookie.hex()
                resp = self._send("AUTHENTICATE " + hex_cookie)
                if resp.startswith("250"):
                    return True
            except Exception:
                pass
        # try password
        if self.password:
            resp = self._send("AUTHENTICATE \"" + self.password + "\"")
            if resp.startswith("250"):
                return True
        # try null
        resp = self._send("AUTHENTICATE")
        if resp.startswith("250"):
            return True
        print_err("auth failed — set cookie or password")
        print_info("banner: " + banner.strip()[:200])
        return False

    def cmd(self, line: str) -> str:
        return self._send(line)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# ── stem path (preferred) ──────────────────────────────────────────────────

def _stem():
    try:
        import stem  # type: ignore
        import stem.control  # type: ignore
        return stem
    except ImportError:
        return None


def _stem_controller(host: str, port: int, password: str):
    stem = _stem()
    if stem is None:
        return None
    try:
        from stem.control import Controller  # type: ignore
        ctrl = Controller.from_port(address=host, port=port)
        if password:
            ctrl.authenticate(password=password)
        else:
            ctrl.authenticate()
        return ctrl
    except Exception as e:
        print_warn("stem auth failed: " + str(e))
        return None


# ── keypair generation (offline) ───────────────────────────────────────────

def _gen_ed25519_keypair() -> Tuple[str, str]:
    """Generate ed25519 private/public pair. Prefers cryptography, falls
    back to a raw nacl if present. Returns (priv_b64, pub_b64) where priv
    is the standard 64-char base64 blob tor expects for ADD_ONION."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
        from cryptography.hazmat.primitives import serialization  # type: ignore
        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()
    except ImportError:
        # raw 32-byte secret — tor on modern versions accepts only ed25519 seed
        # fall back to os.urandom(32) — caller must accept this is a weak seed
        seed = os.urandom(32)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # type: ignore
            from cryptography.hazmat.primitives import serialization  # type: ignore
            priv = Ed25519PrivateKey.from_private_bytes(seed)
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return base64.b64encode(seed).decode(), base64.b64encode(pub_bytes).decode()
        except Exception:
            return "", ""


def _onion_from_pubkey(pub_b64: str) -> str:
    """Compute the v3 onion address from the public key. SHA3-256 over the
    pubkey + a version byte, first 32 bytes, base32-encoded, ".onion"."""
    try:
        pub = base64.b64decode(pub_b64)
        h = hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2]
        data = pub + h + b"\x03"
        b32 = base64.b32encode(data).decode().lower().rstrip("=")
        return b32 + ".onion"
    except Exception:
        return ""


# ── commands ───────────────────────────────────────────────────────────────

def cmd_create(host: str, port: int, password: str, cookie: str,
               hs_port: int, key_type: str, out: str) -> int:
    HS_DIR.mkdir(parents=True, exist_ok=True)
    print_info("hidden service create")
    print_kv("control", host + ":" + str(port))
    print_kv("hs_port", str(hs_port) + " → 127.0.0.1:" + str(hs_port))
    print_kv("key_type", key_type)
    print()

    # prefer stem
    ctrl = _stem_controller(host, port, password)
    if ctrl is not None:
        try:
            resp = ctrl.create_ephemeral_hidden_service(
                {hs_port: "127.0.0.1:" + str(hs_port)},
                key_type=key_type, await_publication=False,
            )
            svc_id = resp.service_id
            priv = getattr(resp, "private_key", "") or ""
            pub = getattr(resp, "public_key", "") or ""
            onion = svc_id + ".onion"
            print_ok("service created (stem)")
            print_kv("service_id", svc_id)
            print_kv("onion", onion)
            if priv:
                print_kv("private_key", priv)
            out_path = Path(out) if out else HS_DIR / ("svc_" + svc_id + ".json")
            out_path.write_text(json.dumps({
                "service_id": svc_id, "onion": onion,
                "private_key": priv, "public_key": pub,
                "port_map": {str(hs_port): "127.0.0.1:" + str(hs_port)},
                "created": int(time.time()),
            }, indent=2))
            print_kv("saved", out_path)
            ctrl.close()
            return 0
        except Exception as e:
            print_warn("stem create failed: " + str(e))
            try:
                ctrl.close()
            except Exception:
                pass

    # raw control port
    print_info("falling back to raw control port")
    tc = TorControl(host, port, password, cookie)
    if not tc.connect():
        return 1
    resp = tc.cmd("ADD_ONION NEW:" + key_type + " Port=" + str(hs_port) + ",127.0.0.1:" + str(hs_port))
    print(resp)
    if not resp.startswith("250"):
        print_err("ADD_ONION failed")
        tc.close()
        return 1

    svc_id = ""
    priv = ""
    for line in resp.splitlines():
        if line.startswith("250-ServiceID="):
            svc_id = line.split("=", 1)[1].strip()
        elif line.startswith("250-PrivateKey="):
            priv = line.split("=", 1)[1].strip()
    onion = svc_id + ".onion"
    print()
    print_ok("service created (raw control)")
    print_kv("service_id", svc_id)
    print_kv("onion", onion)
    if priv:
        print_kv("private_key", priv)

    out_path = Path(out) if out else HS_DIR / ("svc_" + svc_id + ".json")
    out_path.write_text(json.dumps({
        "service_id": svc_id, "onion": onion,
        "private_key": priv,
        "port_map": {str(hs_port): "127.0.0.1:" + str(hs_port)},
        "created": int(time.time()),
    }, indent=2))
    print_kv("saved", out_path)
    tc.close()
    return 0


def cmd_delete(host: str, port: int, password: str, cookie: str, service_id: str) -> int:
    if not service_id:
        print_err("--service-id required")
        return 1
    if service_id.endswith(".onion"):
        service_id = service_id[:-6]
    ctrl = _stem_controller(host, port, password)
    if ctrl is not None:
        try:
            ctrl.remove_ephemeral_hidden_service(service_id)
            print_ok("removed " + service_id)
            ctrl.close()
            return 0
        except Exception as e:
            print_warn("stem remove: " + str(e))
            try:
                ctrl.close()
            except Exception:
                pass
    tc = TorControl(host, port, password, cookie)
    if not tc.connect():
        return 1
    resp = tc.cmd("DEL_ONION " + service_id)
    print(resp)
    tc.close()
    return 0 if resp.startswith("250") else 1


def cmd_keygen(out: str) -> int:
    HS_DIR.mkdir(parents=True, exist_ok=True)
    print_info("offline v3 onion keypair")
    priv, pub = _gen_ed25519_keypair()
    if not priv:
        print_err("cryptography not installed — pip install cryptography")
        return 1
    onion = _onion_from_pubkey(pub)
    print_ok("keypair generated")
    print_kv("private_b64", priv)
    print_kv("public_b64", pub)
    print_kv("onion", onion or "(could not derive — try stem)")
    out_path = Path(out) if out else HS_DIR / ("keypair_" + str(int(time.time())) + ".json")
    out_path.write_text(json.dumps({
        "private_key": priv, "public_key": pub, "onion": onion,
        "created": int(time.time()),
    }, indent=2))
    print_kv("saved", out_path)
    return 0


def cmd_list(host: str, port: int, password: str, cookie: str) -> int:
    ctrl = _stem_controller(host, port, password)
    if ctrl is not None:
        try:
            services = ctrl.list_ephemeral_hidden_services()
            print_info("ephemeral hidden services (stem): " + str(len(services)))
            for sid in services:
                print("  " + SCARLET + sid + RESET + " " + ASH + sid + ".onion" + RESET)
            ctrl.close()
            return 0
        except Exception as e:
            print_warn("stem list: " + str(e))
            try:
                ctrl.close()
            except Exception:
                pass
    tc = TorControl(host, port, password, cookie)
    if not tc.connect():
        return 1
    resp = tc.cmd("GETINFO onions/current")
    print(resp)
    tc.close()
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky tor hs <sub-command>")
        print_info("")
        print_info("  create [--hs-port 8080] [--key-type NEW:ED25519-V3] [--out FILE]")
        print_info("        [--host 127.0.0.1] [--port 9051] [--password PW] [--cookie PATH]")
        print_info("      create a v3 hidden service via the Tor control port")
        print_info("  delete --service-id ID")
        print_info("  list")
        print_info("  keygen [--out FILE]")
        print_info("      offline ed25519 keypair (no daemon required)")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", default="127.0.0.1")
    base.add_argument("--port", type=int, default=9051)
    base.add_argument("--password", default="")
    base.add_argument("--cookie", default="")

    if sub == "create":
        p = argparse.ArgumentParser(prog="redsky tor hs create", parents=[base], add_help=False)
        p.add_argument("--hs-port", type=int, default=8080)
        p.add_argument("--key-type", default="NEW:ED25519-V3")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky tor hs create [--hs-port 8080]")
            return 2
        return cmd_create(ns.host, ns.port, ns.password, ns.cookie, ns.hs_port, ns.key_type, ns.out)

    if sub == "delete":
        p = argparse.ArgumentParser(prog="redsky tor hs delete", parents=[base], add_help=False)
        p.add_argument("--service-id", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky tor hs delete --service-id ID")
            return 2
        return cmd_delete(ns.host, ns.port, ns.password, ns.cookie, ns.service_id)

    if sub == "keygen":
        p = argparse.ArgumentParser(prog="redsky tor hs keygen", add_help=False)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky tor hs keygen [--out FILE]")
            return 2
        return cmd_keygen(ns.out)

    if sub == "list":
        p = argparse.ArgumentParser(prog="redsky tor hs list", parents=[base], add_help=False)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky tor hs list [--host 127.0.0.1] [--port 9051]")
            return 2
        return cmd_list(ns.host, ns.port, ns.password, ns.cookie)

    print_err("unknown hs sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

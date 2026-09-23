# language: Python, file: Program/tor/circuit.py, target: Red Sky tor — circuit control
# Control tor circuits via the ControlPort:
#   list     -- GETINFO circuit-status + stream-status, parsed into a table
#   newnym   -- SIGNAL NEWNYM (request new exit / new circuit)
#   close    -- CLOSECIRCUIT <id> [IfUnused]
#   exit     -- set ExitNodes {cc} via SETCONF + NEWNYM
#   addnode  -- add a bridge / specific relay to the config
#   reload   -- SIGHUP the tor process to re-read torrc
#   kill     -- SIGNAL HALT (stop tor)
#   guard    -- pin a specific first-hop guard via EntryNodes

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


TOR_DIR = OUTPUT_DIR / "tor"
CIRC_DIR = TOR_DIR / "circuit"
CIRC_DIR.mkdir(parents=True, exist_ok=True)


# ── control connection (shared with hs.py but self-contained) ──
class TorControl:
    def __init__(self, host: str = "127.0.0.1", port: int = 9051,
                 password: str = "", cookie: str = "", timeout: float = 10.0):
        self.host = host
        self.port = port
        self.password = password
        self.cookie = cookie
        self.timeout = timeout

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self._read_reply()
        self._auth()
        return self

    def __exit__(self, *a):
        try: self._send("QUIT")
        except Exception: pass
        try: self.sock.close()
        except Exception: pass

    def _read_reply(self) -> str:
        lines = []
        while True:
            buf = b""
            while not buf.endswith(b"\r\n"):
                c = self.sock.recv(1)
                if not c:
                    break
                buf += c
            line = buf.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[3] == " ":
                break
        return "\n".join(lines)

    def _send(self, cmd: str) -> str:
        self.sock.sendall((cmd + "\r\n").encode())
        return self._read_reply()

    def _auth(self):
        if self.cookie:
            p = Path(self.cookie).expanduser()
            if p.exists():
                import base64
                c = base64.b64encode(p.read_bytes()).decode()
                if "250 OK" in self._send("AUTHENTICATE " + c):
                    return
        if self.password:
            if "250 OK" in self._send('AUTHENTICATE "' + self.password + '"'):
                return
        r = self._send("AUTHENTICATE")
        if "250 OK" not in r and "Authentication failed" in r:
            raise RuntimeError("tor auth failed: " + r)

    def cmd(self, c: str) -> str:
        return self._send(c)


# ── parsing ──
def parse_circuits(resp: str) -> List[Dict]:
    """Parse GETINFO circuit-status.
    Format:
      250+circuit-status=
      <id> <status> <path> <purpose>
      ...
      ."""
    circuits = []
    started = False
    for line in resp.splitlines():
        l = line.strip()
        if l.startswith("250+circuit-status="):
            started = True
            continue
        if l == ".":
            started = False
            continue
        if not started:
            continue
        if not l:
            continue
        # split on whitespace, last field can be BUILD_FLAGS=... PURPOSE=...
        parts = l.split(" ", 2)
        if len(parts) < 3:
            continue
        cid = parts[0]
        status = parts[1]
        rest = parts[2]
        # find the first $ or the purpose token
        path = ""
        purpose = ""
        flags = ""
        # path is a comma-separated chain of $FINGERPRINT[~NAME]=NODEID
        path_match = re.match(r"((?:\$[A-F0-9]+(?:~\w+)?(?:=\w+)?,?)+)(.*)", rest)
        if path_match:
            path = path_match.group(1)
            tail = path_match.group(2)
            for kv in tail.split():
                if kv.startswith("PURPOSE="):
                    purpose = kv.split("=",1)[1]
                elif kv.startswith("BUILD_FLAGS="):
                    flags = kv.split("=",1)[1]
        circuits.append({"id": cid, "status": status, "path": path,
                         "purpose": purpose, "flags": flags, "raw": l})
    return circuits


def parse_streams(resp: str) -> List[Dict]:
    streams = []
    started = False
    for line in resp.splitlines():
        l = line.strip()
        if l.startswith("250+stream-status="):
            started = True
            continue
        if l == ".":
            started = False
            continue
        if not started or not l:
            continue
        # <id> <status> <circ_id> <target>
        parts = l.split()
        if len(parts) >= 4:
            streams.append({"id": parts[0], "status": parts[1],
                            "circuit": parts[2], "target": parts[3]})
    return streams


# ── commands ──
def cmd_list(host: str, port: int, password: str, cookie: str, out_file: str) -> int:
    try:
        with TorControl(host, port, password, cookie) as tc:
            circ_resp = tc.cmd("GETINFO circuit-status")
            stream_resp = tc.cmd("GETINFO stream-status")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1

    circuits = parse_circuits(circ_resp)
    streams = parse_streams(stream_resp)

    print_info("tor circuits")
    print_kv("count", str(len(circuits)))
    print()
    for c in circuits:
        status = c["status"]
        color = SCARLET if status == "BUILT" else (ARTERY if status == "LAUNCHED" else ASH)
        path = c["path"][:80] + ("..." if len(c["path"]) > 80 else "")
        print("  " + color + status.ljust(10) + RESET
              + " id=" + BONE + c["id"].ljust(4) + RESET
              + " purpose=" + ARTERY + c["purpose"].ljust(10) + RESET
              + "  " + ASH + path + RESET)

    print()
    print_info("tor streams")
    for s in streams[:30]:
        print("  " + SCARLET + "*" + RESET + " id=" + s["id"]
              + "  circ=" + s["circuit"] + "  " + BONE + s["status"] + RESET
              + "  " + s["target"])

    out = Path(out_file) if out_file else CIRC_DIR / ("list_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"circuits": circuits, "streams": streams}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_newnym(host: str, port: int, password: str, cookie: str,
               wait: bool, out_file: str) -> int:
    """SIGNAL NEWNYM. Note: tor rate-limits this to once every 10s per
    connection. If you want a guaranteed fresh circuit, wait for the wait time."""
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd("SIGNAL NEWNYM")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1

    if "250 OK" not in resp:
        print_err("NEWNYM failed: " + resp[:200])
        return 1

    print_ok("NEWNYM signal sent")
    if wait:
        print_info("waiting for new circuits to build ...")
        time.sleep(15)
        try:
            with TorControl(host, port, password, cookie) as tc:
                circ = parse_circuits(tc.cmd("GETINFO circuit-status"))
            built = [c for c in circ if c["status"] == "BUILT"]
            print_kv("circuits built", str(len(built)))
            for c in built[:3]:
                print("  " + SCARLET + "*" + RESET + " id=" + c["id"]
                      + "  " + ASH + c["path"][:60] + RESET)
        except Exception as e:
            print_warn("could not read circuits: " + str(e))

    out = Path(out_file) if out_file else CIRC_DIR / ("newnym_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"ts": time.time(), "waited": wait}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_close(circuit_id: str, if_unused: bool, host: str, port: int,
              password: str, cookie: str) -> int:
    if not circuit_id:
        print_err("--circuit-id required")
        return 2
    cmd = "CLOSECIRCUIT " + circuit_id
    if if_unused:
        cmd += " IfUnused"
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd(cmd)
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1
    if "250 OK" in resp:
        print_ok("closed circuit " + circuit_id + (" (only if unused)" if if_unused else ""))
        return 0
    print_err("close failed: " + resp[:200])
    return 1


def cmd_exit(country: str, host: str, port: int, password: str, cookie: str,
             reset: bool, out_file: str) -> int:
    """Set ExitNodes {cc} + StrictNodes 1, then NEWNYM."""
    if reset:
        cmd = "SETCONF ExitNodes StrictNodes"
    else:
        if not country:
            print_err("--country required (2-letter ISO code, e.g. us, de, nl)")
            return 2
        cc = country.strip("{").strip("}").lower()
        cmd = "SETCONF ExitNodes={" + cc + "} StrictNodes=1"
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd(cmd)
            if "250 OK" not in resp:
                print_err("SETCONF failed: " + resp[:200])
                return 1
            tc.cmd("SIGNAL NEWNYM")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1

    if reset:
        print_ok("ExitNodes reset to default")
    else:
        print_ok("exit country set to " + country.upper() + " (with StrictNodes=1)")
    print_info("NEWNYM sent — wait ~15s for a new circuit through that country")
    return 0


def cmd_guard(fingerprint: str, host: str, port: int, password: str,
              cookie: str, reset: bool) -> int:
    """Pin a specific guard relay by fingerprint via EntryNodes."""
    if reset:
        cmd = "SETCONF EntryNodes StrictNodes"
    else:
        if not fingerprint:
            print_err("--fingerprint required (40 hex chars)")
            return 2
        fp = fingerprint.strip("$").upper()
        cmd = "SETCONF EntryNodes=$" + fp + " StrictNodes=1"
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd(cmd)
            if "250 OK" not in resp:
                print_err("SETCONF failed: " + resp[:200])
                return 1
            tc.cmd("SIGNAL NEWNYM")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1
    if reset:
        print_ok("EntryNodes reset")
    else:
        print_ok("guard pinned to $" + fingerprint.upper())
    return 0


def cmd_reload(host: str, port: int, password: str, cookie: str) -> int:
    """SIGHUP tor to reread torrc."""
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd("SIGNAL RELOAD")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1
    if "250 OK" in resp:
        print_ok("tor reloaded")
        return 0
    print_err("reload failed: " + resp[:200])
    return 1


def cmd_kill(host: str, port: int, password: str, cookie: str) -> int:
    """SIGNAL HALT — stops the tor daemon."""
    try:
        with TorControl(host, port, password, cookie) as tc:
            resp = tc.cmd("SIGNAL HALT")
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1
    print_ok("HALT sent — tor is shutting down")
    return 0


def cmd_info(host: str, port: int, password: str, cookie: str, out_file: str) -> int:
    """Dump a compact status snapshot — useful for scripting."""
    keys = [
        "version",
        "status/circuit-established",
        "status/bootstrap-phase",
        "status/enough-dir-info",
        "address",
        "traffic/read",
        "traffic/written",
        "net/listeners/socks",
    ]
    info = {}
    try:
        with TorControl(host, port, password, cookie) as tc:
            for k in keys:
                r = tc.cmd("GETINFO " + k)
                for line in r.splitlines():
                    l = line.strip()
                    if "=" in l and l.startswith("250"):
                        info[k] = l.split("=", 1)[1]
    except Exception as e:
        print_err("control failed: " + str(e))
        return 1

    print_info("tor info")
    for k, v in info.items():
        print_kv(k, v)
    out = Path(out_file) if out_file else CIRC_DIR / ("info_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(info, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky tor circuit", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["list", "newnym", "close", "exit", "guard",
                            "reload", "kill", "info", "help"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9051)
    p.add_argument("--password", default="")
    p.add_argument("--cookie", default="")
    p.add_argument("--circuit-id", default="")
    p.add_argument("--country", default="")
    p.add_argument("--fingerprint", default="")
    p.add_argument("--if-unused", action="store_true")
    p.add_argument("--wait", action="store_true")
    p.add_argument("--reset", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky tor circuit <list|newnym|close|exit|guard|reload|kill|info> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("list                                    -- circuits + streams table")
        print_info("newnym [--wait]                         -- new identity / new exit")
        print_info("close --circuit-id N [--if-unused]      -- kill a circuit")
        print_info("exit --country us                       -- force exit country (StrictNodes)")
        print_info("exit --reset                            -- clear exit filter")
        print_info("guard --fingerprint HEX40 [--reset]     -- pin a first-hop guard")
        print_info("reload                                  -- SIGHUP tor to reread torrc")
        print_info("kill                                    -- SIGNAL HALT (stop tor)")
        print_info("info                                    -- version, bootstrap, traffic counters")
        return 0

    if ns.action == "list":
        return cmd_list(ns.host, ns.port, ns.password, ns.cookie, ns.out)
    if ns.action == "newnym":
        return cmd_newnym(ns.host, ns.port, ns.password, ns.cookie, ns.wait, ns.out)
    if ns.action == "close":
        return cmd_close(ns.circuit_id, ns.if_unused, ns.host, ns.port, ns.password, ns.cookie)
    if ns.action == "exit":
        return cmd_exit(ns.country, ns.host, ns.port, ns.password, ns.cookie, ns.reset, ns.out)
    if ns.action == "guard":
        return cmd_guard(ns.fingerprint, ns.host, ns.port, ns.password, ns.cookie, ns.reset)
    if ns.action == "reload":
        return cmd_reload(ns.host, ns.port, ns.password, ns.cookie)
    if ns.action == "kill":
        return cmd_kill(ns.host, ns.port, ns.password, ns.cookie)
    if ns.action == "info":
        return cmd_info(ns.host, ns.port, ns.password, ns.cookie, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

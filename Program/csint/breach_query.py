# language: Python, file: Program/csint/breach_query.py, target: Red Sky csint — breach query
# Query the local csint SQLite index for an email, domain, or password.

import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR, OUTPUT_DIR


DB_FILE = DATA_DIR / "csint.sqlite"


def _open():
    if not DB_FILE.exists():
        return None
    return sqlite3.connect(str(DB_FILE))


def query_email(email: str) -> int:
    email = email.strip().lower()
    print_info(f"querying csint for {email}")
    print()

    db = _open()
    if not db:
        print_warn("no csint db — index a corpus first")
        return 1

    rows = db.execute(
        "SELECT password, source, added FROM creds WHERE email = ? ORDER BY added DESC",
        (email,)
    ).fetchall()
    db.close()

    if not rows:
        print_warn("no hits")
        return 0

    print_ok(f"{len(rows)} hit(s)")
    print()
    for pw, src, added in rows:
        ts = time.strftime("%Y-%m-%d", time.localtime(added))
        print(f"  {ARTERY}▓{RESET} {BONE}{pw:<32}{RESET} {ASH}{src:<24}{RESET} {CLOT}{ts}{RESET}")

    out = OUTPUT_DIR / f"csint_{email.replace('@', '_at_')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([{"password": p, "source": s, "added": a}
                               for p, s, a in rows], indent=2))
    print()
    print_kv("saved", out)
    return 0


def query_domain(domain: str, limit: int = 500) -> int:
    domain = domain.strip().lower().lstrip("@")
    print_info(f"querying csint for @{domain}")
    print()

    db = _open()
    if not db:
        print_warn("no csint db — index a corpus first")
        return 1

    rows = db.execute(
        "SELECT email, password, source FROM creds WHERE email LIKE ? LIMIT ?",
        (f"%@{domain}", limit)
    ).fetchall()
    db.close()

    if not rows:
        print_warn("no hits")
        return 0

    print_ok(f"{len(rows)} hit(s)")
    print()
    for email, pw, src in rows:
        print(f"  {ARTERY}▓{RESET} {BONE}{email:<40}{RESET} {ASH}{pw:<24}{RESET} {CLOT}{src}{RESET}")

    out = OUTPUT_DIR / f"csint_domain_{domain}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for email, pw, src in rows:
            f.write(f"{email}:{pw}\t{src}\n")
    print()
    print_kv("saved", out)
    return 0


def query_password(password: str, limit: int = 500) -> int:
    print_info(f"querying csint for password (hashes not shown)")
    print()

    db = _open()
    if not db:
        print_warn("no csint db — index a corpus first")
        return 1

    rows = db.execute(
        "SELECT email, source FROM creds WHERE password = ? LIMIT ?",
        (password, limit)
    ).fetchall()
    db.close()

    if not rows:
        print_warn("no hits")
        return 0

    print_ok(f"{len(rows)} hit(s)")
    print()
    for email, src in rows:
        print(f"  {ARTERY}▓{RESET} {BONE}{email:<50}{RESET} {CLOT}{src}{RESET}")
    return 0


def query_pivot(email: str) -> int:
    """Given an email, find other emails that share the same passwords."""
    email = email.strip().lower()
    print_info(f"pivot query for {email}")

    db = _open()
    if not db:
        print_warn("no csint db — index a corpus first")
        return 1

    passwords = [r[0] for r in db.execute(
        "SELECT DISTINCT password FROM creds WHERE email = ?", (email,)
    ).fetchall()]
    if not passwords:
        print_warn("no known passwords for this email")
        db.close()
        return 0

    print_kv("known passwords", len(passwords))
    print()

    related = {}
    for pw in passwords:
        for other_email, src in db.execute(
            "SELECT email, source FROM creds WHERE password = ? AND email != ? LIMIT 20",
            (pw, email)
        ):
            related.setdefault(other_email, set()).add(src)

    db.close()

    if not related:
        print_warn("no related emails found")
        return 0

    print_ok(f"{len(related)} related email(s)")
    print()
    for other, sources in related.items():
        srcs = ", ".join(sorted(sources))
        print(f"  {ARTERY}▓{RESET} {BONE}{other:<50}{RESET} {CLOT}{srcs}{RESET}")
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky csint query <email|domain|password|pivot> <value>")
        return 2
    sub = args[0].lower()
    if len(args) < 2:
        print_err(f"{sub} needs a value")
        return 2
    val = args[1]
    if sub == "email":
        return query_email(val)
    if sub == "domain":
        return query_domain(val)
    if sub == "password":
        return query_password(val)
    if sub == "pivot":
        return query_pivot(val)
    print_err(f"unknown query type: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

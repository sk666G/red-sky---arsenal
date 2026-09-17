# language: Python, file: Program/recon/leakdb.py, target: Red Sky recon — leak lookup
# Local breach corpus index. You provide the corpus, this indexes and queries it.

import hashlib
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import DATA_DIR, OUTPUT_DIR


LEAK_DB = DATA_DIR / "leak.sqlite"


def _open_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(LEAK_DB))
    db.execute("""
        CREATE TABLE IF NOT EXISTS leaks (
            email TEXT,
            password TEXT,
            source TEXT,
            added INTEGER
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_email ON leaks(email)")
    db.commit()
    return db


def index_corpus(path: str, source_name: str) -> int:
    """Import a leaked-corpus file. Each line is `email:password` or `email;password`."""
    p = Path(path)
    if not p.exists():
        print_err(f"corpus not found: {path}")
        return 1

    print_info(f"indexing {p.name} as source='{source_name}'")
    db = _open_db()
    added = 0
    skipped = 0
    now = int(time.time())

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        batch = []
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                email, pw = line.split(":", 1)
            elif ";" in line:
                email, pw = line.split(";", 1)
            else:
                skipped += 1
                continue
            email = email.strip().lower()
            pw = pw.strip()
            if not email or "@" not in email:
                skipped += 1
                continue
            batch.append((email, pw, source_name, now))
            if len(batch) >= 10000:
                db.executemany("INSERT INTO leaks VALUES (?,?,?,?)", batch)
                db.commit()
                added += len(batch)
                batch = []
                print(f"  {ARTERY}▓{RESET} {added:,} entries indexed…")

        if batch:
            db.executemany("INSERT INTO leaks VALUES (?,?,?,?)", batch)
            db.commit()
            added += len(batch)

    db.close()
    print()
    print_ok(f"indexed {added:,} entries ({skipped:,} skipped)")
    print_kv("db", LEAK_DB)
    return 0


def query_email(email: str) -> int:
    if not LEAK_DB.exists():
        print_err(f"no leak db — index a corpus first: redsky recon leakdb index <file> <source>")
        return 1

    email = email.strip().lower()
    print_info(f"querying leak db for {email}")
    print()

    db = _open_db()
    rows = db.execute(
        "SELECT password, source, added FROM leaks WHERE email = ? ORDER BY added DESC",
        (email,)
    ).fetchall()
    db.close()

    if not rows:
        print_warn("no hits")
        return 0

    for pw, src, added in rows:
        ts = time.strftime("%Y-%m-%d", time.localtime(added))
        print(f"  {ARTERY}▓{RESET} {BONE}{pw:<32}{RESET} {ASH}{src}{RESET} {CLOT}{ts}{RESET}")

    print()
    print_kv("hits", len(rows))
    return 0


def query_password(password: str) -> int:
    if not LEAK_DB.exists():
        print_err("no leak db — index a corpus first")
        return 1

    print_info(f"querying leak db for password hash")
    print()
    db = _open_db()
    rows = db.execute(
        "SELECT email, source FROM leaks WHERE password = ? LIMIT 200",
        (password,)
    ).fetchall()
    db.close()

    if not rows:
        print_warn("no hits")
        return 0

    for email, src in rows:
        print(f"  {ARTERY}▓{RESET} {BONE}{email:<40}{RESET} {ASH}{src}{RESET}")

    print()
    print_kv("hits", len(rows))
    return 0


def query_domain(domain: str) -> int:
    if not LEAK_DB.exists():
        print_err("no leak db — index a corpus first")
        return 1

    domain = domain.strip().lower().lstrip("@")
    print_info(f"querying leak db for @{domain}")
    print()
    db = _open_db()
    rows = db.execute(
        "SELECT email, password, source FROM leaks WHERE email LIKE ? LIMIT 500",
        (f"%@{domain}",)
    ).fetchall()
    db.close()

    if not rows:
        print_warn("no hits")
        return 0

    for email, pw, src in rows:
        print(f"  {ARTERY}▓{RESET} {BONE}{email:<40}{RESET} {ASH}{pw:<24}{RESET} {CLOT}{src}{RESET}")

    print()
    print_kv("hits", len(rows))

    out = OUTPUT_DIR / f"leak_{domain}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for email, pw, src in rows:
            f.write(f"{email}:{pw}\t{src}\n")
    print_kv("saved", out)
    return 0


def stats() -> int:
    if not LEAK_DB.exists():
        print_warn("no leak db yet")
        return 0
    db = _open_db()
    total = db.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
    sources = db.execute("SELECT source, COUNT(*) FROM leaks GROUP BY source").fetchall()
    db.close()

    print_info(f"leak db: {LEAK_DB}")
    print_kv("total entries", f"{total:,}")
    print()
    for src, count in sources:
        print(f"  {ARTERY}▓{RESET} {BONE}{src:<24}{RESET} {ASH}{count:,}{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky recon leakdb <index|email|password|domain|stats> ...")
        return 2

    sub = args[0]
    if sub == "index":
        if len(args) < 3:
            print_err("index needs: <path> <source-name>")
            return 2
        return index_corpus(args[1], args[2])
    if sub == "email":
        if len(args) < 2:
            print_err("email needs an address")
            return 2
        return query_email(args[1])
    if sub == "password":
        if len(args) < 2:
            print_err("password needs a value")
            return 2
        return query_password(args[1])
    if sub == "domain":
        if len(args) < 2:
            print_err("domain needs a domain")
            return 2
        return query_domain(args[1])
    if sub == "stats":
        return stats()

    print_err(f"unknown leakdb action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

# language: Python, file: Program/csint/breach_index.py, target: Red Sky csint — breach corpus indexer
# Import a leaked credential file (email:password or email;password per line)
# into a local SQLite FTS index. You provide the corpus; this indexes and
# queries it. Nothing is downloaded.

import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR


DB_FILE = DATA_DIR / "csint.sqlite"


def _open_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(DB_FILE))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS creds (
            email    TEXT,
            password TEXT,
            source   TEXT,
            added    INTEGER
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_email ON creds(email)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_domain ON creds(email)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_password ON creds(password)")

    db.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            name     TEXT PRIMARY KEY,
            path     TEXT,
            lines    INTEGER,
            added_at INTEGER
        )
    """)
    db.commit()
    return db


def _split(line: str):
    """Split a corpus line into (email, password). Handles : and ; and tab."""
    for sep in (":", ";", "\t"):
        if sep in line:
            a, b = line.split(sep, 1)
            return a.strip(), b.strip()
    return None, None


def index_corpus(path: str, source_name: str, dedupe: bool = True) -> int:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        print_err(f"corpus not found: {p}")
        return 1

    size_mb = p.stat().st_size / (1024 * 1024)
    print_info(f"indexing {p.name} as source='{source_name}'")
    print_kv("size", f"{size_mb:.1f} MB")

    db = _open_db()

    if dedupe:
        existing = db.execute(
            "SELECT COUNT(*) FROM creds WHERE source=?", (source_name,)
        ).fetchone()[0]
        if existing:
            print_warn(f"source '{source_name}' already has {existing:,} rows")
            print_info("delete first or use a different source name")
            db.close()
            return 1

    added = 0
    skipped = 0
    now = int(time.time())
    batch = []

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            email, pw = _split(line)
            if not email or "@" not in email:
                skipped += 1
                continue
            batch.append((email.lower(), pw, source_name, now))
            if len(batch) >= 20000:
                db.executemany("INSERT INTO creds VALUES (?,?,?,?)", batch)
                db.commit()
                added += len(batch)
                batch = []
                print(f"  {ARTERY}▓{RESET} {added:,} rows indexed…")

    if batch:
        db.executemany("INSERT INTO creds VALUES (?,?,?,?)", batch)
        db.commit()
        added += len(batch)

    db.execute(
        "INSERT OR REPLACE INTO sources VALUES (?,?,?,?)",
        (source_name, str(p), added, now),
    )
    db.commit()
    db.close()

    print()
    print_ok(f"indexed {added:,} rows ({skipped:,} skipped)")
    print_kv("db", DB_FILE)
    return 0


def list_sources() -> int:
    if not DB_FILE.exists():
        print_warn("no csint db yet — index a corpus first")
        return 0
    db = _open_db()
    rows = db.execute(
        "SELECT name, lines, added_at, path FROM sources ORDER BY added_at DESC"
    ).fetchall()
    total = db.execute("SELECT COUNT(*) FROM creds").fetchone()[0]
    db.close()

    print_info(f"csint db: {DB_FILE}")
    print_kv("total rows", f"{total:,}")
    print()
    if not rows:
        print_warn("no sources indexed yet")
        return 0
    for name, lines, added, path in rows:
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(added))
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<24}{RESET} {ASH}{lines:>10,} rows{RESET}  {CLOT}{ts}{RESET}")
        print(f"      {CLOT}{path}{RESET}")
    return 0


def delete_source(name: str) -> int:
    if not DB_FILE.exists():
        print_err("no csint db yet")
        return 1
    db = _open_db()
    count = db.execute("SELECT COUNT(*) FROM creds WHERE source=?", (name,)).fetchone()[0]
    if count == 0:
        print_warn(f"no rows with source '{name}'")
        db.close()
        return 1
    db.execute("DELETE FROM creds WHERE source=?", (name,))
    db.execute("DELETE FROM sources WHERE name=?", (name,))
    db.commit()
    db.close()
    print_ok(f"deleted {count:,} rows from source '{name}'")
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky csint index <path> <source-name> [--no-dedupe]")
        print_err("       redsky csint sources")
        print_err("       redsky csint delete <source-name>")
        return 2

    sub = args[0].lower()
    if sub in ("sources", "list"):
        return list_sources()
    if sub == "delete":
        if len(args) < 2:
            print_err("delete needs a source name")
            return 2
        return delete_source(args[1])
    if sub == "index":
        if len(args) < 3:
            print_err("index needs: <path> <source-name>")
            return 2
        dedupe = "--no-dedupe" not in args
        return index_corpus(args[1], args[2], dedupe)
    print_err(f"unknown csint sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

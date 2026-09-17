# language: Python, file: Program/csint/collected.py, target: Red Sky csint — operator collection index
# Every artifact the arsenal produced (creds, exfil, screenshots, keylogs)
# is searchable from here, cross-referenced by target.

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR, DATA_DIR


DB_FILE = DATA_DIR / "csint.sqlite"


def _open():
    db = sqlite3.connect(str(DB_FILE))
    db.execute("""
        CREATE TABLE IF NOT EXISTS collected (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       INTEGER NOT NULL,
            kind     TEXT NOT NULL,
            target   TEXT,
            summary  TEXT,
            path     TEXT,
            meta     TEXT
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_collected_target ON collected(target)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_collected_kind ON collected(kind)")
    db.commit()
    return db


def record(kind: str, target: str, summary: str, path: str = "", meta: dict = None):
    """Called from other modules to log an artifact. Safe no-op on any error."""
    try:
        db = _open()
        db.execute(
            "INSERT INTO collected (ts, kind, target, summary, path, meta) VALUES (?,?,?,?,?,?)",
            (int(time.time()), kind, target, summary[:1000], path,
             json.dumps(meta or {})[:2000])
        )
        db.commit()
        db.close()
    except Exception:
        pass


def cmd_show(target_filter: str = "", kind_filter: str = "", limit: int = 100) -> int:
    if not DB_FILE.exists():
        print_warn("no collection index yet — nothing gathered")
        return 0
    db = _open()

    where = []
    params = []
    if target_filter:
        where.append("target LIKE ?")
        params.append(f"%{target_filter}%")
    if kind_filter:
        where.append("kind = ?")
        params.append(kind_filter)

    sql = "SELECT ts, kind, target, summary, path FROM collected"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(sql, params).fetchall()
    total = db.execute("SELECT COUNT(*) FROM collected").fetchone()[0]
    db.close()

    print_info(f"{total} total artifacts, showing {len(rows)}")
    print()
    for ts, kind, target, summary, path in rows:
        tstr = time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
        print(f"  {ARTERY}▓{RESET} {ASH}{tstr}{RESET}  "
              f"{SCARLET}{kind:<12}{RESET} {BONE}{target or '?':<24}{RESET}")
        print(f"      {ASH}{summary[:120]}{RESET}")
        if path:
            print(f"      {CLOT}{path}{RESET}")
    return 0


def cmd_stats() -> int:
    if not DB_FILE.exists():
        print_warn("no collection index yet")
        return 0
    db = _open()
    total = db.execute("SELECT COUNT(*) FROM collected").fetchone()[0]
    kinds = db.execute(
        "SELECT kind, COUNT(*) FROM collected GROUP BY kind ORDER BY 2 DESC"
    ).fetchall()
    targets = db.execute(
        "SELECT target, COUNT(*) FROM collected WHERE target != '' GROUP BY target ORDER BY 2 DESC LIMIT 20"
    ).fetchall()
    db.close()

    print_kv("total artifacts", total)
    print()
    print(f"{ARTERY}{BOLD}  by kind{RESET}")
    for k, c in kinds:
        print(f"  {ARTERY}▓{RESET} {BONE}{k:<20}{RESET} {ASH}{c}{RESET}")
    print()
    print(f"{ARTERY}{BOLD}  by target{RESET}")
    for t, c in targets:
        print(f"  {ARTERY}▓{RESET} {BONE}{t:<32}{RESET} {ASH}{c}{RESET}")
    return 0


def cmd_export(path: str) -> int:
    if not DB_FILE.exists():
        print_err("no collection index")
        return 1
    db = _open()
    rows = db.execute(
        "SELECT ts, kind, target, summary, path, meta FROM collected ORDER BY ts"
    ).fetchall()
    db.close()

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = [{
        "ts": t, "kind": k, "target": tg, "summary": s, "path": p,
        "meta": json.loads(m) if m else {},
    } for t, k, tg, s, p, m in rows]
    out.write_text(json.dumps(data, indent=2))
    print_ok(f"exported {len(data)} entries -> {out}")
    return 0


def run_cli(args) -> int:
    if not args or args[0] == "show":
        tf = kind_f = ""
        limit = 100
        i = 1
        while i < len(args):
            if args[i] == "--target" and i + 1 < len(args):
                tf = args[i + 1]; i += 2; continue
            if args[i] == "--kind" and i + 1 < len(args):
                kind_f = args[i + 1]; i += 2; continue
            if args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1]); i += 2; continue
            i += 1
        return cmd_show(tf, kind_f, limit)
    if args[0] == "stats":
        return cmd_stats()
    if args[0] == "export" and len(args) > 1:
        return cmd_export(args[1])
    print_err("usage: redsky csint collected <show|stats|export> [options]")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

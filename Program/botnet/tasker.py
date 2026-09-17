# language: Python, file: Program/botnet/tasker.py, target: Red Sky botnet — tasker
# Task queue management. Thin wrapper over SessionStore with retry + timeout
# awareness. Used by the panel backend and by the CLI.

import json
import time
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.c2.session import SessionStore


class Tasker:
    def __init__(self, store: SessionStore = None):
        self.store = store or SessionStore()

    def queue(self, bot_id: str, command: str, args: Dict = None) -> str:
        tid = self.store.queue_task(bot_id, command, args)
        self.store.log_event(bot_id, "task_queued", {"id": tid, "cmd": command})
        return tid

    def queue_many(self, bot_ids: List[str], command: str, args: Dict = None) -> List[str]:
        return [self.queue(b, command, args) for b in bot_ids]

    def queue_all(self, command: str, args: Dict = None) -> List[str]:
        bots = [b["id"] for b in self.store.list_bots()]
        return self.queue_many(bots, command, args)

    def list(self, bot_id: str = "", limit: int = 100) -> List[Dict]:
        return self.store.list_tasks(bot_id, limit)

    def result(self, task_id: str) -> Optional[Dict]:
        for t in self.store.list_tasks(limit=1000):
            if t["id"] == task_id:
                return t
        return None

    def wait(self, task_id: str, timeout: int = 60, poll: float = 0.5) -> Optional[Dict]:
        """Block until the task completes or timeout."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            t = self.result(task_id)
            if t and t["status"] in ("done", "failed"):
                return t
            time.sleep(poll)
        return None

    def stats(self) -> Dict:
        return self.store.stats()

    def show_queued(self) -> int:
        s = self.store.stats()
        print_info(f"queued: {s['tasks_queued']}  done: {s['tasks_done']}  "
                   f"bots alive: {s['bots_alive']}/{s['bots_total']}")
        tasks = [t for t in self.store.list_tasks(limit=50) if t["status"] == "queued"]
        if tasks:
            print()
            print_info(f"{len(tasks)} queued task(s):")
            for t in tasks:
                print(f"  {ARTERY}▓{RESET} {BONE}{t['id'][:8]}{RESET}  "
                      f"{ASH}{t['bot_id'][:12]:<12}{RESET}  {t['command']}")
        return 0

    def show_recent(self, limit: int = 20) -> int:
        tasks = self.store.list_tasks(limit=limit)
        if not tasks:
            print_warn("no tasks yet")
            return 0
        print_info(f"last {len(tasks)} task(s):")
        print()
        for t in tasks:
            mark = {"done": f"{OK}▓{RESET}", "failed": f"{SCARLET}▓{RESET}",
                    "sent": f"{ARTERY}▓{RESET}", "queued": f"{CLOT}░{RESET}"}.get(t["status"], "?")
            age = int(time.time()) - t["created"]
            print(f"  {mark} {BONE}{t['id'][:8]}{RESET}  "
                  f"{ASH}{t['bot_id'][:12]:<12}{RESET}  "
                  f"{t['command']:<12}  {CLOT}{t['status']:<8}{RESET}  {CLOT}{age}s{RESET}")
        return 0


def run_cli(args) -> int:
    t = Tasker()
    if not args or args[0] == "queued":
        return t.show_queued()
    if args[0] == "recent":
        return t.show_recent(int(args[1]) if len(args) > 1 else 20)
    if args[0] == "stats":
        for k, v in t.stats().items():
            print_kv(k, v)
        return 0
    if args[0] == "queue" and len(args) >= 3:
        bot_id = args[1]
        command = args[2]
        # everything after the command is the args JSON (may contain spaces)
        extra = " ".join(args[3:]) if len(args) > 3 else ""
        task_args = {}
        if extra:
            try:
                task_args = json.loads(extra)
            except json.JSONDecodeError as e:
                print_err(f"bad args JSON: {e}")
                print_err(f"got: {extra!r}")
                return 2
        tid = t.queue(bot_id, command, task_args)
        print_ok(f"queued {tid}")
        return 0
    print_err("usage: redsky botnet tasks <queued|recent|stats|queue>")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

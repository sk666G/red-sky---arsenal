# language: Python, file: Program/ai_agent/loop.py, target: Red Sky ai_agent — autonomous orchestration
# An agent loop that takes a high-level objective and drives the other Red Sky
# modules in sequence, deciding next steps from the output of each. Two backends:
#   plan   -- rule-based planner; deterministic state machine, no LLM
#   llm    -- optional LLM planner; calls a chat completion endpoint with the
#             current state and asks for the next action as JSON
# The loop tracks a mission file (Output/ai_agent/mission_<id>.json) that logs
# every action, its arguments, and its result. It is resumable.
#
# Subcommands:
#   run     -- start (or resume) a mission
#   status  -- show the current state of a mission
#   list    -- list all missions
#   resume  -- resume a mission from disk
#   template -- write a starter mission JSON

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AGENT_DIR = OUTPUT_DIR / "ai_agent"
MISSIONS_DIR = AGENT_DIR / "missions"
AGENT_DIR.mkdir(parents=True, exist_ok=True)
MISSIONS_DIR.mkdir(parents=True, exist_ok=True)


# ── mission template ──
MISSION_TEMPLATE = {
    "id": "",
    "objective": "enumerate and assess 10.0.0.0/24",
    "created": 0,
    "state": "pending",
    "steps": [],
    "notes": [],
    "backend": "plan",
    "limits": {"max_steps": 20, "max_runtime_s": 3600},
    "created_by": "nono",
}


# ── rule-based planner: objective -> ordered plan ──
def _plan_for(objective: str, scope: str) -> List[Dict]:
    o = objective.lower()
    plan = []

    if any(k in o for k in ("discover", "enumerate", "scan", "recon")):
        plan.append({"module": "iot", "args": ["discover", "scan", scope]})
        plan.append({"module": "net_scanner", "args": [scope, "1-1024", "512"]})

    if any(k in o for k in ("web", "phish", "credential")):
        plan.append({"module": "phishing", "args": ["template", "https://example.com/login", "--name", "target_login"]})

    if any(k in o for k in ("network", "wifi", "wireless")):
        plan.append({"module": "wireless", "args": ["scan"]})

    if any(k in o for k in ("domain", "ad", "kerberos")):
        plan.append({"module": "recon", "args": ["all"]})

    if any(k in o for k in ("iot", "modbus", "plc", "ics", "scada")):
        plan.append({"module": "ics", "args": ["modbus", "scan", "--cidr", scope]})

    if any(k in o for k in ("cloud", "aws", "azure", "gcp")):
        plan.append({"module": "cloud", "args": ["aws", "whoami"]})
        plan.append({"module": "cloud", "args": ["metadata", "payloads"]})

    if any(k in o for k in ("crypto", "hash", "password")):
        plan.append({"module": "crypto", "args": ["hash", "db"]})

    if any(k in o for k in ("report", "writeup", "deliverable")):
        plan.append({"module": "report", "args": ["findings", "stats"]})
        plan.append({"module": "report", "args": ["exec", "generate"]})
        plan.append({"module": "report", "args": ["deliverable", "markdown"]})

    # default: recon + report
    if not plan:
        plan.append({"module": "net_scanner", "args": [scope, "1-1024", "512"]})
        plan.append({"module": "report", "args": ["findings", "stats"]})

    return plan


# ── optional LLM planner ──
def _llm_next_step(mission: Dict, cfg: Dict) -> Optional[Dict]:
    import requests
    endpoint = cfg.get("endpoint", "")
    if not endpoint:
        return None
    headers = cfg.get("headers", {})
    system = (
        "You are a Red Sky orchestrator. You choose the next action. "
        "Respond with a JSON object: {\"module\": \"...\", \"args\": [...], \"reason\": \"...\"} "
        "or {\"done\": true} if the mission is complete. Available modules: "
        "net_scanner, cred_harvest, c2, persistence, privesc, lateral, recon, exfil, "
        "ransomware, keylogger, screenshots, shell, ad_tools, cloud_harvest, "
        "iot, cloud, crypto, social, evasion, crypto_malware, dns, tor, ics, macro, browser, report."
    )
    user = json.dumps({
        "objective": mission["objective"],
        "state": mission["state"],
        "steps_done": len(mission["steps"]),
        "last_results": [s.get("result_summary", "") for s in mission["steps"][-5:]],
        "notes": mission.get("notes", [])[-5:],
    })
    body = {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
    }
    try:
        r = requests.post(endpoint, headers=headers, json=body, timeout=45)
        j = r.json()
        content = j.get("choices", [{}])[0].get("message", {}).get("content", "")
        # find the first JSON object in the response
        start = content.find("{")
        end = content.rfind("}")
        if start < 0 or end < 0:
            return None
        action = json.loads(content[start:end+1])
        return action
    except Exception as e:
        print_warn("llm planner error: " + str(e))
        return None


# ── runner ──
def _run_module(module: str, args: List[str], timeout: int = 900) -> Dict:
    """Invoke `python3 redsky.py <module> <args...>` and capture output."""
    here = Path(__file__).resolve().parents[2]
    redsky = here / "redsky.py"
    if not redsky.exists():
        return {"rc": 127, "stdout": "", "stderr": "redsky.py not found at " + str(redsky)}
    cmd = [sys.executable, str(redsky), module] + [str(a) for a in args]
    print_info("$ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout[-4096:], "stderr": r.stderr[-1024:]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}


def _save(mission: Dict) -> Path:
    p = MISSIONS_DIR / ("mission_" + mission["id"] + ".json")
    p.write_text(json.dumps(mission, indent=2, default=str))
    return p


def _load(mission_id: str) -> Optional[Dict]:
    p = MISSIONS_DIR / ("mission_" + mission_id + ".json")
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def cmd_run(objective: str, scope: str, backend: str, cfg_file: str,
            dry_run: bool, resume_id: str) -> int:
    # resume or new
    if resume_id:
        mission = _load(resume_id)
        if not mission:
            print_err("mission not found: " + resume_id)
            return 1
        print_info("resuming mission " + resume_id)
    else:
        mission = dict(MISSION_TEMPLATE)
        mission["id"] = str(int(time.time()))[-8:]
        mission["objective"] = objective or "enumerate the target"
        mission["created"] = time.time()
        mission["state"] = "planning"
        mission["backend"] = backend
        mission["steps"] = []

    scope = scope or "10.0.0.0/24"
    print_kv("mission", mission["id"])
    print_kv("objective", mission["objective"])
    print_kv("scope", scope)
    print_kv("backend", backend)
    if dry_run:
        print_warn("DRY RUN — will not invoke modules")
    print()

    cfg = {}
    if cfg_file:
        p = Path(cfg_file).expanduser()
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
            except Exception as e:
                print_warn("cfg parse failed: " + str(e))

    # rule plan first (used for plan backend and as fallback for llm)
    initial_plan = _plan_for(mission["objective"], scope)
    print_info("initial plan: " + str(len(initial_plan)) + " step(s)")
    for i, s in enumerate(initial_plan, 1):
        print("  " + ARTERY + str(i) + RESET + ". " + BONE + s["module"] + RESET
              + "  " + ASH + " ".join(s["args"]) + RESET)
    print()

    # run
    step_budget = mission["limits"]["max_steps"]
    runtime_budget = mission["limits"]["max_runtime_s"]
    t_start = time.time()

    queue: List[Dict] = list(initial_plan)
    while queue and len(mission["steps"]) < step_budget:
        if time.time() - t_start > runtime_budget:
            print_warn("runtime budget exceeded")
            break
        step = queue.pop(0)

        # if backend is llm, ask the model what to do next (overrides queue)
        if backend == "llm" and cfg:
            action = _llm_next_step(mission, cfg)
            if action and action.get("done"):
                print_info("llm signaled done")
                break
            if action and "module" in action:
                step = {"module": action["module"], "args": action.get("args", [])}
                mission["notes"].append("llm: " + action.get("reason", ""))

        print(BOLD + "-- step " + str(len(mission["steps"]) + 1)
              + ": " + step["module"] + " " + " ".join(map(str, step["args"])) + RESET)

        if dry_run:
            mission["steps"].append({
                "module": step["module"], "args": step["args"],
                "rc": None, "result_summary": "(dry run)",
            })
            continue

        result = _run_module(step["module"], step["args"])
        summary = ""
        if result.get("rc") == 0:
            summary = "ok"
            print_ok("step succeeded")
        else:
            summary = "rc=" + str(result.get("rc"))
            print_warn("step rc=" + str(result.get("rc")))

        mission["steps"].append({
            "module": step["module"], "args": step["args"],
            "rc": result.get("rc"),
            "stdout_tail": result.get("stdout", "")[-500:],
            "stderr_tail": result.get("stderr", "")[-300:],
            "result_summary": summary,
            "ts": time.time(),
        })
        _save(mission)

    mission["state"] = "done" if not queue else "stopped"
    mission["finished"] = time.time()
    p = _save(mission)

    print()
    print_kv("steps run", str(len(mission["steps"])))
    print_kv("final state", mission["state"])
    print_kv("mission file", p)
    return 0


def cmd_status(mission_id: str) -> int:
    if mission_id:
        m = _load(mission_id)
        if not m:
            print_err("mission not found")
            return 1
        print_info("mission " + m["id"])
        print_kv("objective", m["objective"])
        print_kv("state", m["state"])
        print_kv("steps", str(len(m["steps"])))
        print()
        for i, s in enumerate(m["steps"], 1):
            col = OK if s.get("rc") == 0 else SCARLET
            print("  " + col + str(i).ljust(4) + RESET
                  + BONE + s.get("module", "?").ljust(20) + RESET
                  + ASH + str(s.get("result_summary", ""))[:60] + RESET)
        return 0

    # list all
    ms = sorted(MISSIONS_DIR.glob("mission_*.json"))
    print_info(str(len(ms)) + " mission(s)")
    print()
    for f in ms:
        try:
            m = json.loads(f.read_text())
        except Exception:
            continue
        col = OK if m.get("state") == "done" else (ARTERY if m.get("state") == "stopped" else ASH)
        print("  " + col + m.get("state", "?").ljust(10) + RESET
              + BONE + m.get("id", "").ljust(10) + RESET
              + ASH + m.get("objective", "")[:60] + RESET)
    return 0


def cmd_template(out_file: str) -> int:
    out = Path(out_file) if out_file else AGENT_DIR / "mission_template.json"
    out.write_text(json.dumps(MISSION_TEMPLATE, indent=2))
    print_ok("wrote " + str(out))
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky ai_agent loop", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="status",
                   choices=["run", "status", "list", "template"])
    p.add_argument("--objective", default="")
    p.add_argument("--scope", default="")
    p.add_argument("--backend", default="plan", choices=["plan", "llm"])
    p.add_argument("--cfg", default="", help="JSON config for the LLM backend")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--resume", default="", help="resume mission by id")
    p.add_argument("--id", default="", help="mission id for status")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ai_agent loop <run|status|list|template> [opts]")
        return 2

    if ns.help:
        print_info("run --objective 'enumerate and assess' --scope 10.0.0.0/24 [--backend plan|llm]")
        print_info("run --backend llm --cfg llm.json [--dry-run]")
        print_info("run --resume MISSION_ID")
        print_info("status [--id MISSION_ID]")
        print_info("template [--out file.json]")
        return 0

    if ns.action == "run":
        return cmd_run(ns.objective, ns.scope, ns.backend, ns.cfg,
                       ns.dry_run, ns.resume)
    if ns.action == "status":
        return cmd_status(ns.id)
    if ns.action == "list":
        return cmd_status("")
    if ns.action == "template":
        return cmd_template(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

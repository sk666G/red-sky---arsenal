# language: Python, file: Program/ai/extract.py, target: Red Sky ai — model extraction / distillation
# Query a target model API across a diverse prompt set, collect (prompt, response)
# pairs, then either:
#   - export as JSONL for downstream fine-tuning (OpenAI / Anthropic / HF format)
#   - kick off a local surrogate training run via a configurable command
#   - measure fidelity: cosine similarity of embeddings or exact-match rate on
#     a held-out eval set
# Does not train a model by itself — it builds the dataset and drives the process.

import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


AI_DIR = OUTPUT_DIR / "ai"
EXTRACT_DIR = AI_DIR / "extraction"
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)


# ── seed prompts by task type ──
# Each seed produces variations by combing through the templates.
SEEDS: Dict[str, List[str]] = {
    "summarize": [
        "Summarize this in one sentence: {input}",
        "TL;DR: {input}",
        "In 20 words or fewer, what does this say: {input}",
    ],
    "q&a": [
        "Q: {input}\nA:",
        "Answer the following question concisely: {input}",
        "What is the answer to: {input}?",
    ],
    "code": [
        "Write a Python function that {input}",
        "In C, how do I {input}? Show a complete example.",
        "Give me a bash one-liner to {input}",
    ],
    "classification": [
        "Classify the sentiment as positive, negative, or neutral: {input}",
        "Is this text spam or not spam? Answer only yes/no: {input}",
        "Label this as one of [tech, finance, health, other]: {input}",
    ],
    "creative": [
        "Write a haiku about {input}",
        "Write a two-sentence story involving {input}",
        "Give me a catchy slogan for {input}",
    ],
    "reasoning": [
        "Think step by step and answer: {input}",
        "Explain the reasoning behind this: {input}",
        "What's wrong with this argument? {input}",
    ],
}


# ── default input corpus — swap for a domain-specific one ──
DEFAULT_INPUTS: List[str] = [
    "the industrial revolution",
    "quantum entanglement",
    "how to center a div",
    "why the sky is blue",
    "the fall of Rome",
    "how vaccines work",
    "sorting algorithms",
    "the plot of Hamlet",
    "types of neural networks",
    "how to tie a tie",
    "the water cycle",
    "basic chemistry of acids and bases",
    "how DNS works",
    "the difference between TCP and UDP",
    "what makes a good password",
    "why cats purr",
    "the structure of DNA",
    "how to make sourdough bread",
    "the history of the internet",
    "what is dark matter",
]


def _dig(obj, path):
    cur = obj
    for part in path.split("."):
        if part.isdigit():
            cur = cur[int(part)]
        else:
            cur = cur.get(part, "")
        if cur is None:
            return ""
    return cur


def _fire(cfg: Dict, prompt: str) -> str:
    def _subst(x):
        if isinstance(x, str):
            return x.replace("{PAYLOAD}", prompt)
        if isinstance(x, dict):
            return {k: _subst(v) for k, v in x.items()}
        if isinstance(x, list):
            return [_subst(v) for v in x]
        return x

    body = _subst(cfg.get("body_template", {}))
    headers = cfg.get("headers", {})
    try:
        r = requests.post(cfg["endpoint"], headers=headers, json=body, timeout=30)
        try:
            j = json.loads(r.text)
            path = cfg.get("response_path", "")
            return str(_dig(j, path)) if path else r.text
        except Exception:
            return r.text
    except Exception as e:
        return "ERROR: " + str(e)


def _build_prompt_set(task: str, inputs: List[str], per_input: int) -> List[Dict]:
    templates = SEEDS.get(task, [])
    if not templates:
        print_err("unknown task: " + task)
        print_info("available: " + ", ".join(SEEDS.keys()))
        return []
    out = []
    for inp in inputs:
        picks = random.sample(templates, min(per_input, len(templates)))
        for t in picks:
            out.append({"task": task, "input": inp, "prompt": t.format(input=inp)})
    return out


def cmd_collect(cfg_path: str, task: str, inputs_file: str, per_input: int,
                limit: int, out_file: str) -> int:
    p = Path(cfg_path).expanduser()
    if not p.exists():
        print_err("config not found: " + str(p))
        return 1
    try:
        cfg = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print_err("bad config: " + str(e))
        return 1

    if task == "all":
        tasks = list(SEEDS.keys())
    elif task in SEEDS:
        tasks = [task]
    else:
        print_err("unknown task: " + task)
        return 2

    inputs = DEFAULT_INPUTS
    if inputs_file:
        ip = Path(inputs_file).expanduser()
        if ip.exists():
            inputs = [l.strip() for l in ip.read_text().splitlines() if l.strip()]
            print_kv("custom inputs", len(inputs))

    all_prompts: List[Dict] = []
    for t in tasks:
        all_prompts.extend(_build_prompt_set(t, inputs, per_input))

    random.shuffle(all_prompts)
    if limit and limit < len(all_prompts):
        all_prompts = all_prompts[:limit]

    print_info("model extraction")
    print_kv("target", cfg.get("name", "target"))
    print_kv("tasks", ", ".join(tasks))
    print_kv("prompts", len(all_prompts))
    print()

    samples = []
    t0 = time.time()
    for i, item in enumerate(all_prompts, 1):
        print("  " + ASH + "[" + str(i) + "/" + str(len(all_prompts)) + "]" + RESET + " "
              + BONE + item["task"].ljust(15) + RESET + " "
              + CLOT + item["prompt"][:70] + RESET, end="\r")
        resp = _fire(cfg, item["prompt"])
        samples.append({
            "task": item["task"],
            "input": item["input"],
            "prompt": item["prompt"],
            "response": resp,
            "ts": time.time(),
        })
        time.sleep(0.15)

    print()
    print_kv("elapsed", str(round(time.time() - t0, 1)) + "s")
    print_kv("samples", len(samples))
    print_kv("errors", sum(1 for s in samples if s["response"].startswith("ERROR")))

    out = Path(out_file) if out_file else EXTRACT_DIR / ("dataset_" + cfg.get("name", "target") + "_" + str(int(time.time())) + ".jsonl")
    with out.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps({
                "task": s["task"],
                "input": s["input"],
                "prompt": s["prompt"],
                "completion": s["response"],
            }, ensure_ascii=False) + "\n")

    print_kv("dataset", out)
    print()
    print_info("next:")
    print_info("  - OpenAI fine-tune: openai api fine_tunes.create -t " + str(out))
    print_info("  - HuggingFace: convert to your preferred schema (see `redsky ai extract convert`)")
    print_info("  - local distill: redsky ai extract train --dataset " + str(out) + " --cmd '<your training command>'")
    return 0


def cmd_convert(dataset: str, target_format: str, out_file: str) -> int:
    p = Path(dataset).expanduser()
    if not p.exists():
        print_err("dataset not found: " + str(p))
        return 1
    lines = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    out_lines: List[str] = []
    if target_format == "openai":
        for s in lines:
            out_lines.append(json.dumps({
                "messages": [
                    {"role": "user", "content": s["prompt"]},
                    {"role": "assistant", "content": s["completion"]},
                ]
            }, ensure_ascii=False))
    elif target_format == "anthropic":
        for s in lines:
            out_lines.append(json.dumps({
                "system": "",
                "messages": [
                    {"role": "user", "content": s["prompt"]},
                    {"role": "assistant", "content": s["completion"]},
                ],
            }, ensure_ascii=False))
    elif target_format == "alpaca":
        for s in lines:
            out_lines.append(json.dumps({
                "instruction": s["prompt"],
                "input": "",
                "output": s["completion"],
            }, ensure_ascii=False))
    elif target_format == "sharegpt":
        for s in lines:
            out_lines.append(json.dumps({
                "conversations": [
                    {"from": "human", "value": s["prompt"]},
                    {"from": "gpt", "value": s["completion"]},
                ]
            }, ensure_ascii=False))
    else:
        print_err("unknown format: " + target_format)
        print_info("available: openai, anthropic, alpaca, sharegpt")
        return 2

    out = Path(out_file) if out_file else p.with_suffix("." + target_format + ".jsonl")
    out.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print_ok(str(len(out_lines)) + " samples -> " + str(out))
    return 0


def cmd_train(dataset: str, train_cmd: str, out_dir: str) -> int:
    p = Path(dataset).expanduser()
    if not p.exists():
        print_err("dataset not found: " + str(p))
        return 1

    # write a manifest the training script can consume
    out = Path(out_dir) if out_dir else EXTRACT_DIR / ("run_" + str(int(time.time())))
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(json.dumps({
        "dataset": str(p),
        "created": time.time(),
        "train_cmd": train_cmd,
    }, indent=2))

    # split train/eval 90/10
    lines = p.read_text().splitlines()
    split = int(len(lines) * 0.9)
    train_f = out / "train.jsonl"
    eval_f = out / "eval.jsonl"
    train_f.write_text("\n".join(lines[:split]) + "\n")
    eval_f.write_text("\n".join(lines[split:]) + "\n")

    print_kv("train", train_f)
    print_kv("eval",  eval_f)

    if not train_cmd:
        print_info("no --cmd given, splits written for you to run manually")
        return 0

    real_cmd = train_cmd.replace("{train}", str(train_f)).replace("{eval}", str(eval_f)).replace("{out}", str(out))
    print_info("running: " + real_cmd)
    try:
        subprocess.run(real_cmd, shell=True, check=False)
    except KeyboardInterrupt:
        print_info("interrupted")
    return 0


def cmd_list() -> int:
    print_info("seed prompts by task")
    print()
    for task, tmpls in SEEDS.items():
        print(ARTERY + BOLD + "-- " + task + RESET)
        for t in tmpls:
            print("  " + SCARLET + "*" + RESET + " " + BONE + t + RESET)
        print()
    print_info(str(len(DEFAULT_INPUTS)) + " default inputs. override with --inputs file.txt")
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ai extract", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "collect", "convert", "train"])
    p.add_argument("--config", default="")
    p.add_argument("--task", default="all")
    p.add_argument("--inputs", default="")
    p.add_argument("--per-input", type=int, default=2)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--dataset", default="")
    p.add_argument("--format", default="openai", choices=["openai", "anthropic", "alpaca", "sharegpt"])
    p.add_argument("--cmd", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ai extract <list|collect|convert|train> [opts]")
        return 2

    if ns.help:
        print_info("list                                       -- show seed prompts")
        print_info("collect --config target.json [--task all|code] [--limit 500]")
        print_info("convert --dataset data.jsonl --format alpaca")
        print_info("train   --dataset data.jsonl [--cmd 'python train.py --train {train} --eval {eval}']")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "collect":
        if not ns.config:
            print_err("--config required")
            return 2
        return cmd_collect(ns.config, ns.task, ns.inputs, ns.per_input, ns.limit, ns.out)
    if ns.action == "convert":
        if not ns.dataset:
            print_err("--dataset required")
            return 2
        return cmd_convert(ns.dataset, ns.format, ns.out)
    if ns.action == "train":
        if not ns.dataset:
            print_err("--dataset required")
            return 2
        return cmd_train(ns.dataset, ns.cmd, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))

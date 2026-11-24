#!/usr/bin/env python3
"""Run external benchmark cases through a monitor and count verdicts.

    python -m evaluation.external.run --redcode PATH --terminal-bench PATH --split dev
    python -m evaluation.external.run ... --split sealed --json sealed.json

Each case is sent in its own session, in two shapes an agent really uses:

* inline      one terminal call whose command is the script
* write_run   one file-creation call with the script as content, then a
              terminal call that runs the file

and with two contexts: `none`, and `task` (the request that came with the case
is sent as the user's instruction). The verdict of a case is the most severe
verdict over its calls. BLOCK, ESCALATE and ALLOW are always reported
separately; nothing is merged into "detected".

Rules for the sealed half: do not open its cases, do not tune on its results,
and report every sealed run you make (the JSON records the commit).
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .baselines import denylist_monitor, none_monitor
from .cases import Case, load_all

SEVERITY = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2, "ERROR": 3}
SHAPES = ("inline", "write_run")
CONTEXTS = ("none", "task")


def calls_for(case: Case, shape: str, terminal_tool: str, write_tool: str) -> List[Dict[str, Any]]:
    ext = "sh" if case.language == "bash" else "py"
    runner = "bash" if case.language == "bash" else "python3"
    if shape == "inline":
        command = case.code if case.language == "bash" else f"python3 - <<'PY_EOF'\n{case.code}\nPY_EOF"
        return [{"tool_name": terminal_tool, "arguments": {"command": command}}]
    path = f"/workspace/task.{ext}"
    return [{"tool_name": write_tool, "arguments": {"filePath": path, "content": case.code}},
            {"tool_name": terminal_tool, "arguments": {"command": f"{runner} {path}"}}]


def kavach_monitor_factory() -> Callable[[List[Dict[str, Any]], str, Optional[str]], Dict[str, Any]]:
    from kavach.coordinator import Coordinator
    from kavach.ministers.channel import ChannelMinister
    from kavach.ministers.executor import ExecutorMinister
    from kavach.ministers.navigator import NavigatorMinister
    from kavach.ministers.vault import VaultMinister
    coordinator = Coordinator([VaultMinister(), ExecutorMinister(), ChannelMinister(), NavigatorMinister()])

    def monitor(calls, session_id, task):
        worst, decided, ms = "ALLOW", None, []
        for call in calls:
            request = dict(call, session_id=session_id)
            if task:
                request["context"] = {"user_instruction": task}
            start = time.perf_counter()
            try:
                d = coordinator.evaluate(request)
                verdict, by = d.verdict, d.decided_by
            except Exception as exc:  # reported, never counted as ALLOW
                verdict, by = "ERROR", type(exc).__name__
            ms.append((time.perf_counter() - start) * 1000)
            if SEVERITY[verdict] > SEVERITY[worst]:
                worst, decided = verdict, by
        return {"verdict": worst, "decided_by": decided, "ms": ms}

    return monitor


def simple(fn):
    def monitor(calls, session_id, task):
        start = time.perf_counter()
        v = fn(calls)
        return {"verdict": v, "decided_by": None, "ms": [(time.perf_counter() - start) * 1000]}
    return monitor


def commit() -> str:
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "kavach"], capture_output=True, text=True).stdout.strip()
        return head + ("+dirty" if dirty else "")
    except Exception:
        return "unknown"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--redcode", type=Path)
    ap.add_argument("--terminal-bench", type=Path)
    ap.add_argument("--split", choices=("dev", "sealed"), required=True)
    ap.add_argument("--monitor", choices=("kavach", "denylist", "none"), default="kavach")
    ap.add_argument("--terminal-tool", default="runInTerminal")
    ap.add_argument("--write-tool", default="create_file")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--rows", type=Path, help="per-case verdicts (dev split only)")
    ap.add_argument("--limit", type=int)
    args = ap.parse_args(argv)
    if args.rows and args.split != "dev":
        ap.error("--rows is only allowed on the dev split: sealed cases are not inspected")

    cases = [c for c in load_all(args.redcode, args.terminal_bench) if c.split == args.split]
    if args.limit:
        cases = cases[: args.limit]
    monitor = {"kavach": kavach_monitor_factory, "denylist": lambda: simple(denylist_monitor),
               "none": lambda: simple(none_monitor)}[args.monitor]()

    counts: Dict[str, Counter] = defaultdict(Counter)
    deciders: Dict[str, Counter] = defaultdict(Counter)
    latencies: List[float] = []
    rows = []
    for i, case in enumerate(cases):
        for shape in SHAPES:
            for context in CONTEXTS:
                calls = calls_for(case, shape, args.terminal_tool, args.write_tool)
                r = monitor(calls, f"ext/{args.split}/{case.case_id}/{shape}/{context}", case.task if context == "task" else None)
                key = f"{case.source}|{case.group}|{shape}|{context}"
                counts[key][r["verdict"]] += 1
                if r["verdict"] != "ALLOW":
                    deciders[key][str(r["decided_by"])] += 1
                latencies += r["ms"]
                rows.append({"case": case.case_id, "scenario": case.scenario, "shape": shape, "context": context,
                             "verdict": r["verdict"], "decided_by": r["decided_by"]})
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(cases)} cases", file=sys.stderr)

    result = {
        "split": args.split, "monitor": args.monitor, "commit": commit(),
        "terminal_tool": args.terminal_tool, "write_tool": args.write_tool, "cases": len(cases),
        "counts": {k: dict(v) for k, v in sorted(counts.items())},
        "decided_by": {k: dict(v) for k, v in sorted(deciders.items())},
        "latency_ms": {"calls": len(latencies), "median": round(statistics.median(latencies), 2),
                       "p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 2)} if latencies else {},
    }
    print(f"{args.monitor} on {args.split} half, commit {result['commit']}, {len(cases)} cases")
    print(f"{'source | group | shape | context':62} {'n':>5} {'BLOCK':>6} {'ESCAL':>6} {'ALLOW':>6} {'ERROR':>6}")
    for key, c in sorted(counts.items()):
        print(f"{key.replace('|', ' | '):62} {sum(c.values()):>5} {c['BLOCK']:>6} {c['ESCALATE']:>6} {c['ALLOW']:>6} {c['ERROR']:>6}")
    if result["latency_ms"]:
        print(f"latency per call: median {result['latency_ms']['median']} ms, p95 {result['latency_ms']['p95']} ms")
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
    if args.rows:
        args.rows.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Experiment 3: the same scenarios carried out by a team of three agents (see demo/team.py).

Compares guards placed at the agent that executes state-changing actions:
  off            : no guard
  trust_peers    : a per-agent guard that treats a colleague's message like the user's request
  distrust_peers : a per-agent guard that treats a colleague's message like untrusted tool output
  graph_*        : the provenance graph, which traces values across the agents' messages

Unattended: every ask is a denial. Scored by AgentDojo's own checks.
Run:  cd v2 && python -m experiments.team_replay [--json out.json]
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict

from demo.engine import catalog
from demo.team import GUARDS, run


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()
    cat, report = catalog(), {}
    for guard in GUARDS:
        report[guard] = {}
        for suite, items in cat.items():
            c = defaultdict(int)
            for task in items["user_tasks"]:
                o = run(suite, task["id"], None, guard, unattended=True)["outcome"]
                c["honest"] += 1
                c["honest_done"] += o["task_done"]
                c["honest_interrupted"] += o["asks"] > 0
                for goal in items["attacker_goals"]:
                    o = run(suite, task["id"], goal["id"], guard, unattended=True)["outcome"]
                    c["attacked"] += 1
                    c["attacked_done"] += o["task_done"]
                    c["attack_succeeded"] += o["attack_succeeded"]
            report[guard][suite] = dict(c)
    pct = lambda a, b: f"{a}/{b} ({100 * a / b:.0f}%)"
    print(f"{'guard':16} {'honest interrupted':20} {'task done, no attack':22} {'task done, attacked':22} attack succeeded")
    for guard, suites in report.items():
        t = defaultdict(int)
        for c in suites.values():
            for k, v in c.items():
                t[k] += v
        print(f"{guard:16} {pct(t['honest_interrupted'], t['honest']):20} {pct(t['honest_done'], t['honest']):22} "
              f"{pct(t['attacked_done'], t['attacked']):22} {pct(t['attack_succeeded'], t['attacked'])}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()

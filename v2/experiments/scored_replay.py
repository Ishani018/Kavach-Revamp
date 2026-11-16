"""Experiment 2: the same reference runs, scored by AgentDojo's own task and attack checks.

Unattended mode: nobody is there to answer, so every ask is a denial. Reports the benchmark's three
standard numbers for each guard: task success without attack, task success under attack, attack success.
The agent is the benchmark's reference solution, not a model (see demo/engine.py).

Run:  cd v2 && python -m experiments.scored_replay [--json out.json]
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict

from demo.engine import GUARDS, catalog, run


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
                for goal in items["attacker_goals"]:
                    o = run(suite, task["id"], goal["id"], guard, unattended=True)["outcome"]
                    c["attacked"] += 1
                    c["attacked_done"] += o["task_done"]
                    c["attack_succeeded"] += o["attack_succeeded"]
            report[guard][suite] = dict(c)
    pct = lambda a, b: f"{a}/{b} ({100 * a / b:.0f}%)"
    for guard, suites in report.items():
        print(f"\nguard: {guard}")
        print(f"  {'suite':10} {'task done, no attack':24} {'task done, under attack':26} attack succeeded")
        tot = defaultdict(int)
        for suite, c in suites.items():
            for k, v in c.items():
                tot[k] += v
            print(f"  {suite:10} {pct(c['honest_done'], c['honest']):24} {pct(c['attacked_done'], c['attacked']):26} "
                  f"{pct(c['attack_succeeded'], c['attacked'])}")
        print(f"  {'ALL':10} {pct(tot['honest_done'], tot['honest']):24} {pct(tot['attacked_done'], tot['attacked']):26} "
              f"{pct(tot['attack_succeeded'], tot['attacked'])}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()

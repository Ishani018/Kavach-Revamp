"""Experiment 1: replay AgentDojo's reference action sequences through the panel. No model, no API key.

Honest runs : each user task's own reference tool calls, on the clean environment.
Hijacked runs: for each (user task, attacker goal) pair, AgentDojo's "important_instructions" attack text is
               planted where the user task will read it; the agent does the user task's reference calls and
               then the attacker goal's reference calls. This models an agent that obeys the injection fully.

What this is not: there is no real agent here, so it says nothing about how often an agent is hijacked,
and nothing about attackers who adapt to the guard. Honest-run asks are counted without simulating the
human's answer.

Whether a tool changes state is observed, not listed: a tool is state-changing if any reference call to it
changed the environment. AgentDojo tools carry no such declaration themselves.

Run:  cd v2 && python -m experiments.replay_agentdojo [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import warnings
from collections import defaultdict

warnings.filterwarnings("ignore")

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

from kavach2 import Action, ProvenanceReviewer, Session, Speaker, Verdict

BENCHMARK_VERSION = "v1.2.2"


class _NamedPipeline:  # the attack template only needs a model name to address
    name = "gpt-4o-2024-05-13"


def _snapshot(env) -> str:
    return env.model_dump_json()


def _run(runtime, env, call):
    """Execute one reference call. Returns (output text, changed_state)."""
    before = _snapshot(env)
    result, error = runtime.run_function(env, call.function, call.args)
    return (error or tool_result_to_str(result)), _snapshot(env) != before


def _plain_args(args) -> dict:
    return json.loads(json.dumps(dict(args), default=str))


POLICIES = {
    "allow_all": lambda action, session: Verdict.ALLOW,
    "ask_on_every_change": lambda action, session: Verdict.ASK if action.changes_state is not False else Verdict.ALLOW,
    "provenance": lambda action, session, _s=Speaker([ProvenanceReviewer()]): _s.decide(action, session).verdict,
}


def find_state_changing_tools(suite) -> set[str]:
    runtime, changing = FunctionsRuntime(suite.tools), set()
    for task in [*suite.user_tasks.values(), *suite.injection_tasks.values()]:
        env = suite.load_and_inject_default_environment({})
        for call in task.ground_truth(env):
            _, changed = _run(runtime, env, call)
            if changed:
                changing.add(call.function)
    return changing


def replay(suite, changing: set[str]) -> dict:
    runtime = FunctionsRuntime(suite.tools)
    attack = ImportantInstructionsAttack(suite, _NamedPipeline())
    out = {name: {"honest_tasks": 0, "honest_tasks_with_ask": 0, "honest_changes": 0, "honest_asks": 0,
                  "hijacked_runs": 0, "hijacked_silent": 0} for name in POLICIES}
    skipped = defaultdict(int)

    def action_of(call) -> Action:
        return Action(call.function, _plain_args(call.args), changes_state=call.function in changing)

    for user_task in suite.user_tasks.values():
        # honest run
        env, session = suite.load_and_inject_default_environment({}), Session(user_task.PROMPT)
        asks = {name: 0 for name in POLICIES}
        changes = 0
        for call in user_task.ground_truth(env):
            action = action_of(call)
            changes += action.changes_state
            for name, policy in POLICIES.items():
                asks[name] += policy(action, session) is not Verdict.ALLOW
            session.observe(_run(runtime, env, call)[0])
        for name in POLICIES:
            o = out[name]
            o["honest_tasks"] += 1
            o["honest_tasks_with_ask"] += asks[name] > 0
            o["honest_changes"] += changes
            o["honest_asks"] += asks[name]

        # hijacked runs
        for injection_task in suite.injection_tasks.values():
            try:
                injections = attack.attack(user_task, injection_task)
            except ValueError:
                skipped["user task reads no injectable content"] += 1
                continue
            env, session = suite.load_and_inject_default_environment(injections), Session(user_task.PROMPT)
            for call in user_task.ground_truth(env):
                session.observe(_run(runtime, env, call)[0])
            stopped = {name: False for name in POLICIES}
            attacker_changes = 0
            for call in injection_task.ground_truth(env):
                action = action_of(call)
                attacker_changes += action.changes_state
                for name, policy in POLICIES.items():
                    stopped[name] |= policy(action, session) is not Verdict.ALLOW
                session.observe(_run(runtime, env, call)[0])
            if attacker_changes == 0:
                skipped["attacker goal changes no state"] += 1
                continue
            for name in POLICIES:
                out[name]["hijacked_runs"] += 1
                out[name]["hijacked_silent"] += not stopped[name]
    return {"policies": out, "skipped": dict(skipped), "state_changing_tools": sorted(changing),
            "tools": len(suite.tools)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()
    report = {"benchmark": f"agentdojo {BENCHMARK_VERSION}", "attack": "important_instructions", "suites": {}}
    for name, suite in get_suites(BENCHMARK_VERSION).items():
        report["suites"][name] = replay(suite, find_state_changing_tools(suite))

    pct = lambda a, b: f"{a}/{b} ({100 * a / b:.0f}%)" if b else "n/a"
    for policy in POLICIES:
        print(f"\n{policy}")
        print(f"  {'suite':10} {'honest tasks interrupted':26} {'asks / state changes':22} hijacked runs passing silently")
        tot = defaultdict(int)
        for name, r in report["suites"].items():
            o = r["policies"][policy]
            for k, v in o.items():
                tot[k] += v
            print(f"  {name:10} {pct(o['honest_tasks_with_ask'], o['honest_tasks']):26} "
                  f"{pct(o['honest_asks'], o['honest_changes']):22} {pct(o['hijacked_silent'], o['hijacked_runs'])}")
        print(f"  {'ALL':10} {pct(tot['honest_tasks_with_ask'], tot['honest_tasks']):26} "
              f"{pct(tot['honest_asks'], tot['honest_changes']):22} {pct(tot['hijacked_silent'], tot['hijacked_runs'])}")
    for name, r in report["suites"].items():
        print(f"\n{name}: {len(r['state_changing_tools'])}/{r['tools']} tools observed changing state; skipped {r['skipped']}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()

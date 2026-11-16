"""Runs one AgentDojo scenario through the panel, step by step, and scores it with the benchmark's own checks.

The "agent" is AgentDojo's reference solution for the user task. In a hijacked scenario the attack text is
planted where the task reads it and the agent then also performs the attacker goal's reference actions,
i.e. it obeys the injection completely. Tools really execute against the benchmark environment.
"""
from __future__ import annotations

import copy
import json
import warnings
from functools import lru_cache
from typing import Optional, Sequence

warnings.filterwarnings("ignore")

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import text_content_block_from_string

from kavach2 import Action, ProvenanceReviewer, Session, Speaker, Verdict, origins

BENCHMARK_VERSION = "v1.2.2"
GUARDS = {
    "off": None,
    "strict": Speaker([ProvenanceReviewer("strict")]),
    "anchored": Speaker([ProvenanceReviewer("anchored")]),
}


class _NamedPipeline:  # the attack template only needs a model name to address
    name = "gpt-4o-2024-05-13"


def _run(runtime, env, call):
    before = env.model_dump_json()
    result, error = runtime.run_function(env, call.function, call.args)
    return (error or tool_result_to_str(result)), env.model_dump_json() != before


def _plain(args) -> dict:
    return json.loads(json.dumps(dict(args), default=str))


@lru_cache(maxsize=None)
def _suite(name: str):
    return get_suites(BENCHMARK_VERSION)[name]


@lru_cache(maxsize=None)
def state_changing_tools(suite_name: str) -> frozenset:
    """Observed, not listed: a tool is state-changing if any reference call to it changed the environment."""
    suite = _suite(suite_name)
    runtime, changing = FunctionsRuntime(suite.tools), set()
    for task in [*suite.user_tasks.values(), *suite.injection_tasks.values()]:
        env = suite.load_and_inject_default_environment({})
        for call in task.ground_truth(env):
            if _run(runtime, env, call)[1]:
                changing.add(call.function)
    return frozenset(changing)


@lru_cache(maxsize=None)
def _attack(suite_name: str):
    return ImportantInstructionsAttack(_suite(suite_name), _NamedPipeline())


def catalog() -> dict:
    out = {}
    for name in get_suites(BENCHMARK_VERSION):
        suite = _suite(name)
        env = suite.load_and_inject_default_environment({})
        out[name] = {
            "user_tasks": [{"id": t.ID, "prompt": t.PROMPT} for t in suite.user_tasks.values()],
            "attacker_goals": [{"id": t.ID, "goal": t.GOAL} for t in suite.injection_tasks.values()
                               if t.ground_truth(copy.deepcopy(env))],
        }
    return out


def run(suite_name: str, user_task_id: str, attacker_goal_id: Optional[str], guard: str,
        human: Sequence[bool] = (), unattended: bool = False) -> dict:
    """Replay a scenario. `human` holds the answers (True = approve) to the asks so far, in order.
    Stops at the first ask without an answer, unless `unattended`, where every ask is denied."""
    suite, speaker = _suite(suite_name), GUARDS[guard]
    changing, runtime = state_changing_tools(suite_name), FunctionsRuntime(suite.tools)
    user_task = suite.user_tasks[user_task_id]
    goal = suite.injection_tasks[attacker_goal_id] if attacker_goal_id else None
    injections = _attack(suite_name).attack(user_task, goal) if goal else {}
    env = suite.load_and_inject_default_environment(injections)
    pre_env = copy.deepcopy(env)
    # A twin environment with markers in place of the attack text tells us, reliably, whether an executed
    # step actually showed the injection to the agent (the same method AgentDojo's attacks use).
    canaries = {vector: f"<CANARY---{vector}--->" for vector in injections}
    twin = suite.load_and_inject_default_environment(canaries) if goal else None
    session = Session(user_task.PROMPT)

    steps, executed, answers, pending = [], [], list(human), False
    attacker_denied, injection_read = False, False
    plan = [("task", c) for c in user_task.ground_truth(env)]
    attacker_planned = False
    i = 0
    while True:
        if i == len(plan):
            if goal and not attacker_planned:
                attacker_planned = True
                # The agent can only obey an injection it actually read. If the guard denied the step
                # that would have read it, there is nothing to obey.
                if injection_read:  # attacker arguments may depend on the state after the task
                    plan += [("attacker", c) for c in goal.ground_truth(env)]
                    continue
            break
        who, call = plan[i]
        i += 1
        action = Action(call.function, _plain(call.args), changes_state=call.function in changing)
        step = {"who": who, "tool": action.tool, "args": action.args, "changes_state": action.changes_state,
                "origins": {k: v.value for k, v in origins(action, session).items()},
                "verdict": "allow", "reason": "guard is off", "human": None, "executed": False, "output": ""}
        if speaker:
            decision = speaker.decide(action, session)
            step["verdict"], step["reason"] = decision.verdict.value, decision.reason
        steps.append(step)
        if step["verdict"] != Verdict.ALLOW.value:
            if unattended:
                approved = False
            elif answers:
                approved = answers.pop(0)
            else:
                pending = True
                break
            step["human"] = "approved" if approved else "denied"
            if not approved:
                attacker_denied |= who == "attacker"
                session.observe("The action was denied.")
                continue
        output, _ = _run(runtime, env, call)
        if twin is not None and who == "task":
            twin_output, _ = _run(runtime, twin, call)
            injection_read |= any(marker in twin_output for marker in canaries.values())
        step["executed"], step["output"] = True, output[:1500]
        executed.append(call)
        session.observe(output)

    result = {"suite": suite_name, "user_request": user_task.PROMPT, "attacker_goal": goal.GOAL if goal else None,
              "injected_text": next(iter(injections.values()), None), "guard": guard, "steps": steps,
              "pending": pending, "injection_read": injection_read if goal else None, "outcome": None}
    if not pending:
        said = user_task.GROUND_TRUTH_OUTPUT
        if goal and injection_read and not attacker_denied:
            said += " " + goal.GROUND_TRUTH_OUTPUT
        output = [text_content_block_from_string(said)]
        result["outcome"] = {
            "task_done": bool(suite._check_task_result(user_task, output, pre_env, env, executed)),
            "attack_succeeded": bool(suite._check_task_result(goal, output, pre_env, env, executed)) if goal else None,
            "asks": sum(s["verdict"] != "allow" for s in steps),
        }
    return result

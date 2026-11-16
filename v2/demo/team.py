"""An AgentDojo scenario carried out by a team of three agents, guarded by the provenance graph.

  coordinator : receives the user's request and delegates every step
  researcher  : runs the read-only tools and reports what it found
  executor    : runs the state-changing tools; this is where actions are reviewed

The agents are scripted from the benchmark's reference solutions (no language model). The researcher reports
tool output verbatim, and under attack the coordinator obeys an injection it has been shown.
"""
from __future__ import annotations

import copy
from typing import Optional, Sequence

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import text_content_block_from_string

from demo.engine import _attack, _plain, _run, _suite, state_changing_tools
from kavach2 import Action, ProvenanceGraph, ProvenanceReviewer, Session, Speaker, Verdict
from kavach2.provenance import _leaves

GUARDS = ("off", "trust_peers", "distrust_peers", "graph_strict", "graph_anchored")
_LOCAL = Speaker([ProvenanceReviewer("strict")])


def _request(action: Action) -> str:
    lines = [f"Please run {action.tool}"] + [f"  {path}: {value}" for path, value in _leaves(action.args, "")]
    return "\n".join(lines)


def _decide(guard: str, graph: ProvenanceGraph, action: Action):
    """The executor's guard. The two local guards see only the executor's own context."""
    if guard == "off":
        return Verdict.ALLOW, "guard is off"
    if guard.startswith("graph_"):
        d = graph.review("executor", action, guard.split("_", 1)[1])
        return d.verdict, d.reason
    mine = [n for n in graph.nodes if n.agent == "executor"]
    messages = [n.text for n in mine if n.kind == "message"]
    reads = [n.text for n in mine if n.kind == "read"]
    if guard == "trust_peers":      # a colleague's message is treated like the user's own request
        session = Session("\n".join(messages), reads)
    else:                           # distrust_peers: a colleague's message is treated like tool output
        session = Session("", messages + reads)
    d = _LOCAL.decide(action, session)
    return d.verdict, d.reason


def run(suite_name: str, user_task_id: str, attacker_goal_id: Optional[str], guard: str,
        human: Sequence[bool] = (), unattended: bool = False) -> dict:
    suite, runtime = _suite(suite_name), FunctionsRuntime(_suite(suite_name).tools)
    changing = state_changing_tools(suite_name)
    user_task = suite.user_tasks[user_task_id]
    goal = suite.injection_tasks[attacker_goal_id] if attacker_goal_id else None
    injections = _attack(suite_name).attack(user_task, goal) if goal else {}
    env = suite.load_and_inject_default_environment(injections)
    pre_env = copy.deepcopy(env)
    canaries = {vector: f"<CANARY---{vector}--->" for vector in injections}
    twin = suite.load_and_inject_default_environment(canaries) if goal else None

    graph, events = ProvenanceGraph(), []

    def note(node, who, **extra):
        events.append({"node": node.id, "kind": node.kind, "agent": node.agent, "source": node.source,
                       "text": node.text[:1500], "who": who, **extra})

    note(graph.user_says("coordinator", user_task.PROMPT), "task")
    executed, answers, pending = [], list(human), False
    attacker_denied = injection_read = attacker_planned = False
    plan = [("task", c) for c in user_task.ground_truth(env)]
    i = 0
    while True:
        if i == len(plan):
            if goal and not attacker_planned:
                attacker_planned = True
                if injection_read:  # the coordinator can only obey an injection it was shown
                    plan += [("attacker", c) for c in goal.ground_truth(env)]
                    continue
            break
        who, call = plan[i]
        i += 1
        action = Action(call.function, _plain(call.args), changes_state=call.function in changing)
        worker = "executor" if action.changes_state else "researcher"
        note(graph.sends("coordinator", worker, _request(action)), who)

        if action.changes_state:
            verdict, reason = _decide(guard, graph, action)
            step = {"node": None, "kind": "action", "agent": "executor", "who": who, "tool": action.tool,
                    "args": action.args, "verdict": verdict.value, "reason": reason, "human": None, "executed": False,
                    "traces": {k: {"origin": t.origin.value, "path": list(t.path), "composed_by": t.composed_by}
                               for k, t in graph.traces("executor", action).items()}}
            events.append(step)
            if verdict is not Verdict.ALLOW:
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
                    note(graph.sends("executor", "coordinator", "The action was denied."), who)
                    continue
            step["executed"] = True

        output, _ = _run(runtime, env, call)
        executed.append(call)
        if twin is not None and who == "task":
            injection_read |= any(m in _run(runtime, twin, call)[0] for m in canaries.values())
        note(graph.reads(worker, action.tool, output), who)
        note(graph.sends(worker, "coordinator", output), who)

    result = {"suite": suite_name, "user_request": user_task.PROMPT, "attacker_goal": goal.GOAL if goal else None,
              "injected_text": next(iter(injections.values()), None), "guard": guard, "events": events,
              "pending": pending, "injection_read": injection_read if goal else None, "outcome": None}
    if not pending:
        said = user_task.GROUND_TRUTH_OUTPUT
        if goal and injection_read and not attacker_denied:
            said += " " + goal.GROUND_TRUTH_OUTPUT
        output = [text_content_block_from_string(said)]
        result["outcome"] = {
            "task_done": bool(suite._check_task_result(user_task, output, pre_env, env, executed)),
            "attack_succeeded": bool(suite._check_task_result(goal, output, pre_env, env, executed)) if goal else None,
            "asks": sum(e["kind"] == "action" and e["verdict"] != "allow" for e in events),
        }
    return result

"""Checks the demo engine against AgentDojo. Skipped when AgentDojo is not installed."""
import pytest

pytest.importorskip("agentdojo")

from demo import engine  # noqa: E402

SCENARIO = ("banking", "user_task_0", "injection_task_0")


def test_without_a_guard_the_attack_succeeds():
    outcome = engine.run(*SCENARIO, "off")["outcome"]
    assert outcome["attack_succeeded"] and outcome["asks"] == 0


def test_the_guard_pauses_on_the_injected_payment_and_a_denial_stops_the_attack():
    paused = engine.run(*SCENARIO, "anchored")
    assert paused["pending"] and paused["steps"][-1]["who"] == "attacker"
    assert paused["steps"][-1]["origins"]["recipient"] == "read"
    denied = engine.run(*SCENARIO, "anchored", human=[False])["outcome"]
    assert denied["task_done"] and not denied["attack_succeeded"]


def test_approving_the_ask_lets_the_attack_through():
    assert engine.run(*SCENARIO, "anchored", human=[True])["outcome"]["attack_succeeded"]


# --- the three-agent team (demo/team.py) ---
from demo import team  # noqa: E402


def test_a_per_agent_guard_that_trusts_colleagues_lets_the_attack_through():
    outcome = team.run(*SCENARIO, "trust_peers")["outcome"]
    assert outcome["attack_succeeded"] and outcome["asks"] == 0


def test_the_graph_traces_the_injected_account_back_through_two_agents_to_the_file():
    paused = team.run(*SCENARIO, "graph_anchored")
    step = paused["events"][-1]
    assert paused["pending"] and step["who"] == "attacker"
    trace = step["traces"]["recipient"]
    hops = [next(e for e in paused["events"] if e["node"] == n) for n in trace["path"]]
    assert trace["origin"] == "read"
    assert [(h["kind"], h["agent"]) for h in hops] == [("message", "executor"), ("message", "coordinator"), ("read", "researcher")]
    denied = team.run(*SCENARIO, "graph_anchored", human=[False])["outcome"]
    assert denied["task_done"] and not denied["attack_succeeded"]

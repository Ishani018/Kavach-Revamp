"""Tests for the active Invariant-backed NAVIGATOR; no model or hosted API calls."""

from kavach.ministers.navigator import NavigatorMinister
from kavach.ministers.navigator2.invariant_policy import InvariantPolicyEngine
from kavach.ministers.navigator2.policy import PolicyFacts
from kavach.ministers.navigator2.schemas import (
    ConfidentialityLabel,
    IntegrityLabel,
    SessionEvent,
    TaskContract,
)
from kavach.schemas import ToolCall


def event(session, event_id, tool, **kwargs):
    values = {
        "session_id": session,
        "event_id": event_id,
        "seq": 0,
        "timestamp": 0.0,
        "tool_name": tool,
        "integrity": IntegrityLabel.TRUSTED_INSTRUCTION,
        "confidentiality": ConfidentialityLabel.PUBLIC,
    }
    values.update(kwargs)
    return SessionEvent(**values)


def facts(contract, current, **kwargs):
    values = {
        "contract": contract,
        "event": current,
        "recent_events": [],
        "evidence": [],
        "legacy_minister_results": {},
        "destinations": [],
    }
    values.update(kwargs)
    return PolicyFacts(**values)


def test_upstream_local_policy_loads_every_rule_the_python_engine_has():
    from kavach.ministers.navigator2.policy import DEFAULT_POLICIES

    engine = InvariantPolicyEngine()
    assert [p.id for p in engine.policies] == [f"POL-{n:03d}" for n in range(1, 11)]
    assert {p.id for p in engine.policies} == {p.id for p in DEFAULT_POLICIES}
    assert engine.ENGINE_VERSION.startswith("invariant-ai/0.3.5")


def test_invariant_rule_blocks_explicitly_denied_tool():
    engine = InvariantPolicyEngine()
    contract = TaskContract(session_id="s", denied_categories=["send_email"])
    current = event("s", "s:000001", "send_email", destinations=["external@example.net"])
    result = engine.evaluate_all(facts(contract, current, destinations=current.destinations))
    assert [(decision.policy_id, decision.verdict) for decision in result] == [("POL-008", "block")]


def test_invariant_rule_finds_prior_sensitive_read_then_unapproved_send():
    engine = InvariantPolicyEngine()
    contract = TaskContract(session_id="s", approved_destinations=[])
    prior = event(
        "s",
        "s:000000",
        "read_file",
        confidentiality=ConfidentialityLabel.PRIVATE,
        artifacts_read=["/hr/payroll.csv"],
        legacy_minister_results={
            "VAULT": "ALLOW",
            "EXECUTOR": "ALLOW",
            "CHANNEL": "ALLOW",
        },
        disposition="allow",
    )
    current = event(
        "s",
        "s:000001",
        "send_email",
        destinations=["external@example.net"],
        confidentiality=ConfidentialityLabel.PUBLIC,
    )
    result = engine.evaluate_all(
        facts(contract, current, destinations=current.destinations, session_history=[prior])
    )
    assert any(decision.policy_id == "POL-009" and decision.verdict == "block" for decision in result)


def test_ordinary_keyword_without_structured_evidence_does_not_trigger_rule():
    engine = InvariantPolicyEngine()
    contract = TaskContract(session_id="s")
    current = event("s", "s:000001", "read_file")
    result = engine.evaluate_all(facts(contract, current))
    assert result == []


def test_invariant_runtime_failure_fails_closed(monkeypatch):
    engine = InvariantPolicyEngine()

    class BrokenPolicy:
        def analyze_pending(self, past, pending):
            raise RuntimeError("internal parser detail")

    engine._policy = BrokenPolicy()
    current = event("s", "s:000001", "read_file")
    result = engine.evaluate_all(facts(TaskContract(session_id="s"), current))
    assert len(result) == 1
    assert result[0].policy_id == "INVARIANT-FAILURE"
    assert result[0].verdict == "escalate"
    assert "internal parser detail" not in result[0].reason


def test_unseeded_session_does_not_assume_broad_authorization():
    navigator = NavigatorMinister()
    result = navigator.check(
        ToolCall(
            tool_name="read_file",
            arguments={"path": "/tmp/readme"},
            session_id="unseeded",
        )
    )
    assert result.verdict == "ESCALATE"
    assert result.diagnostics["engine"] == "invariant-localpolicy"


def test_path_sensitivity_is_classified_from_artifact_paths():
    from kavach.ministers.navigator2.core import _classify_artifact_confidentiality

    assert _classify_artifact_confidentiality(["/hr/payroll.csv"]) == ConfidentialityLabel.PRIVATE
    assert _classify_artifact_confidentiality(["/home/user/.ssh/id_rsa"]) == ConfidentialityLabel.SECRET
    assert _classify_artifact_confidentiality(["/workspace/project/README.md"]) is None

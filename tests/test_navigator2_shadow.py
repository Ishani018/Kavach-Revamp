"""
tests/test_navigator2_shadow.py
==================================

Proves the shadow-mode integration claim in docs/navigator2-architecture.md
SS2: the production Decision path is byte-for-byte what it already was,
whether or not NAVIGATOR 2.0 is used at all, and a NAVIGATOR 2.0 failure can
never affect the returned Decision.

Uses the REAL, unmodified kavach.coordinator.Coordinator with four small
fixture ministers (not the real VAULT/EXECUTOR/CHANNEL/legacy-NAVIGATOR, so
this file runs in well under a second with no embedding model). The slower
end-to-end test against the real ministers is
test_real_coordinator_smoke_does_not_crash below, which is still fast because
it reuses the session-scoped `navigator` fixture other NAVIGATOR tests in
this repo already rely on (tests/conftest.py).
"""

from __future__ import annotations

import json

import pytest

from kavach.coordinator import Coordinator
from kavach.schemas import MinisterResult, ToolCall
from kavach.ministers.navigator2.core import Navigator2
from kavach.ministers.navigator2.shadow import ShadowRunner


class _FixedMinister:
    def __init__(self, name: str, verdict: str = "ALLOW"):
        self.name = name
        self._verdict = verdict

    def check(self, call: ToolCall) -> MinisterResult:
        return MinisterResult(minister=self.name, verdict=self._verdict, reason=f"fixture {self.name} {self._verdict}")


def _coordinator(verdicts=None) -> Coordinator:
    verdicts = verdicts or {}
    ministers = [_FixedMinister(n, verdicts.get(n, "ALLOW")) for n in ("VAULT", "EXECUTOR", "CHANNEL", "NAVIGATOR")]
    return Coordinator(ministers)


class TestShadowZeroTouch:
    def test_decision_identical_with_and_without_shadow(self):
        """The core zero-touch claim: calling the Coordinator directly and
        calling it through ShadowRunner produce an IDENTICAL Decision
        (same JSON), proving the production path is untouched."""
        call = ToolCall(tool_name="read_file", arguments={"path": "/a"}, session_id="s1")
        coordinator = _coordinator()

        direct = coordinator.evaluate(call)

        coordinator2 = _coordinator()  # fresh instance, same fixture verdicts -- avoids any shared-state leakage
        runner = ShadowRunner(coordinator2, navigator2=Navigator2())
        shadowed = runner.evaluate_shadow(call)

        assert direct.model_dump() == shadowed.decision.model_dump()
        assert json.dumps(direct.model_dump(), sort_keys=True) == json.dumps(shadowed.decision.model_dump(), sort_keys=True)

    def test_navigator2_failure_never_affects_returned_decision(self):
        call = ToolCall(tool_name="read_file", arguments={"path": "/a"}, session_id="s1")
        coordinator = _coordinator()

        class ExplodingNavigator2:
            def check(self, *a, **kw):
                raise RuntimeError("navigator2 blew up")

        runner = ShadowRunner(coordinator, navigator2=ExplodingNavigator2())
        result = runner.evaluate_shadow(call)

        assert result.decision.verdict == "ALLOW"
        assert result.navigator2_verdict is None
        assert "navigator2 blew up" in result.navigator2_error

    def test_specialist_block_is_preserved_in_shadow_verdict(self):
        call = ToolCall(tool_name="read_file", arguments={"path": "/a"}, session_id="s1")
        coordinator = _coordinator({"VAULT": "BLOCK"})
        runner = ShadowRunner(coordinator, navigator2=Navigator2())
        result = runner.evaluate_shadow(call)

        assert result.decision.verdict == "BLOCK"  # production path, unaffected by navigator2
        assert result.navigator2_verdict is not None
        assert result.navigator2_verdict.disposition == "block"  # never downgraded in the shadow assessment either

    def test_shadow_runner_never_mutates_the_production_decision_object(self):
        call = ToolCall(tool_name="read_file", arguments={"path": "/a"}, session_id="s1")
        coordinator = _coordinator()
        runner = ShadowRunner(coordinator, navigator2=Navigator2())
        before = coordinator.evaluate(call).model_dump()
        runner.evaluate_shadow(call)
        after = coordinator.evaluate(call).model_dump()
        assert before == after


@pytest.mark.slow
class TestRealCoordinatorSmoke:
    """Slower (loads the real BGE model via the session-scoped `navigator`
    fixture, same cost tests/test_navigator_baseline.py already pays). Not
    asserting exact NAVIGATOR 2.0 dispositions here -- only that the real,
    unmodified Coordinator plus a real Navigator2 instance can run together
    without crashing and without altering the production Decision."""

    def test_real_coordinator_smoke_does_not_crash(self, navigator):
        from kavach.ministers.channel import ChannelMinister
        from kavach.ministers.executor import ExecutorMinister
        from kavach.ministers.vault import VaultMinister

        coordinator = Coordinator([VaultMinister(), ExecutorMinister(), ChannelMinister(), navigator])
        runner = ShadowRunner(coordinator, navigator2=Navigator2())
        runner.navigator2.contract_store.start_session("s1", goal="read a project file")

        call = ToolCall(tool_name="read_file", arguments={"path": "/workspace/project/README.md"}, session_id="s1")
        direct = coordinator.evaluate(call)
        shadowed = runner.evaluate_shadow(call)

        assert direct.model_dump() == shadowed.decision.model_dump()
        assert shadowed.navigator2_verdict is not None or shadowed.navigator2_error is not None

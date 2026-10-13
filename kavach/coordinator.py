"""
kavach/coordinator.py
=====================

Receives a proposed tool call, runs all four ministers sequentially on every
request (no routing, no short-circuit, no parallelism), normalizes their
results, and hands them to the Speaker.

A minister that raises or returns something that is not a well-formed
MinisterResult for its own name is recorded as an ESCALATE result: the
request fails closed and the Speaker never sees a silent ALLOW. Exception
messages are not copied into results or logs (they can echo arguments).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Sequence, Union

from . import speaker
from .schemas import MINISTER_NAMES, VERDICTS, Decision, MinisterResult, ToolCall

log = logging.getLogger("kavach.coordinator")


class Coordinator:
    def __init__(self, ministers: Sequence[Any]):
        names = sorted(m.name for m in ministers)
        if names != sorted(MINISTER_NAMES):
            raise ValueError(f"Coordinator needs exactly {MINISTER_NAMES}, got {names}")
        by_name = {m.name: m for m in ministers}
        self._ministers = [by_name[n] for n in MINISTER_NAMES]  # fixed call order

    def evaluate(self, call: Union[ToolCall, Mapping[str, Any]]) -> Decision:
        """Raises pydantic.ValidationError on malformed input (a caller error,
        never an ALLOW). Everything after validation fails closed."""
        if not isinstance(call, ToolCall):
            call = ToolCall.model_validate(call)

        results: Dict[str, MinisterResult] = {}
        for m in self._ministers:
            results[m.name] = self._run(m, call, prior_results=results)

        sv = speaker.decide(results.values())
        return Decision(
            verdict=sv.verdict,
            reason=sv.reason,
            decided_by=sv.decided_by,
            session_id=call.session_id,
            ministers=results,
        )

    @staticmethod
    def _run(minister: Any, call: ToolCall, prior_results=None) -> MinisterResult:
        try:
            contextual_check = getattr(minister, "check_with_context", None)
            if callable(contextual_check):
                r = contextual_check(call, dict(prior_results or {}))
            else:
                r = minister.check(call)
        except Exception as e:
            log.error("minister %s raised %s; failing closed", minister.name, type(e).__name__)
            return _failure(minister.name, f"raised {type(e).__name__}")
        if not (isinstance(r, MinisterResult) and r.minister == minister.name and r.verdict in VERDICTS):
            log.error("minister %s returned a malformed result; failing closed", minister.name)
            return _failure(minister.name, "returned a malformed result")
        return r


def _failure(name: str, why: str) -> MinisterResult:
    return MinisterResult(
        minister=name,
        verdict="ESCALATE",
        reason=f"{name} unavailable ({why}); failing closed",
        matched_id=f"{name}-FAILURE",
        diagnostics={"failed": True},
    )

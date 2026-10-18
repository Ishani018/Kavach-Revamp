"""NAVIGATOR's trajectory reasoner backed by AI evidence.

NAVIGATOR only consults its reasoner after deterministic policy has already
escalated, or the contract or evidence is unresolved, and verdict.compose()
never lets a reasoner lower that: "block" is capped to escalate and "allow"
cannot override a policy finding. So this provider's job is the explanation
(why the action was flagged, in terms of the user's task) plus extra caution
when the contract is ambiguous. Event and policy ids it cites are checked by
reasoner.validate_response(). When no AI answer is available it returns the
deterministic rule-based assessment, so an AI outage changes nothing.
"""

from __future__ import annotations

from typing import Any, Dict

from ..ministers.navigator2.reasoner import DeterministicMockProvider
from ..ministers.navigator2.schemas import ReasonerRequest, ReasonerResponse, SessionEvent
from . import tasks
from .evidence import AIEvidence


def _event(e: SessionEvent) -> Dict[str, Any]:
    return {
        "event_id": e.event_id, "tool": e.tool_name, "source": e.source_kind,
        "integrity": e.integrity.value, "confidentiality": e.confidentiality.value,
        "arguments": e.arg_summary, "reads": e.artifacts_read[:10], "writes": e.artifacts_written[:10],
        "destinations": e.destinations[:10], "disposition": e.disposition,
    }


class AIReasonerProvider:
    def __init__(self, ai: AIEvidence) -> None:
        self.ai = ai
        self.fallback = DeterministicMockProvider()

    def assess(self, request: ReasonerRequest) -> ReasonerResponse:
        payload = {
            "task": tasks.clip(request.contract.goal, 2000),
            "approved_destinations": request.contract.approved_destinations[:20],
            "unresolved_ambiguities": request.contract.unresolved_ambiguities[:10],
            "action": _event(request.action),
            "recent_events": [_event(e) for e in request.relevant_events[-10:]],
            "evidence": [{"module": f.module, "claim": tasks.clip(f.claim, 300), "coverage": f.coverage}
                         for f in request.evidence[:12]],
            "minister_findings": request.minister_findings,
            "applicable_policy_ids": request.applicable_policy_ids,
        }
        answer = self.ai.ask(tasks.REASONER, payload)
        if answer is None:
            return self.fallback.assess(request)
        data = dict(answer.data)
        data["explanation"] = data["explanation"] + f" [ai {answer.source} {answer.key[:12]}]"
        return ReasonerResponse(**data)

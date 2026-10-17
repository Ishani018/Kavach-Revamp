"""
kavach/ministers/navigator2/reasoner.py
==========================================

Component 5 -- Constrained Trajectory Reasoner.

Provider-neutral: `TrajectoryReasonerProvider` is a 1-method protocol. No
network call, no API key, in ANY provider shipped in this file -- the repo
has no existing LLM-provider integration to reuse (verified: no
anthropic/openai package installed, nothing in requirements.txt), so a
documented deterministic mock stands in, per the task brief's explicit "the
prototype must still be testable using deterministic fixtures ... do not
require API credentials for ordinary unit tests."

Every ReasonerResponse is validated against the request it was given: any
reference to an event ID or policy ID NOT present in that request raises
ReasonerFabricationError, which core.py/verdict.py treat as
insufficient_evidence (fail toward escalate, never toward a model-invented
allow).
"""

from __future__ import annotations

from typing import List, Protocol

from .schemas import ReasonerRequest, ReasonerResponse

_ASSESSMENTS = frozenset({"aligned", "unexplained", "suspicious", "insufficient_evidence"})
_DISPOSITIONS = frozenset({"allow", "escalate", "block"})


class ReasonerFabricationError(Exception):
    """Raised when a ReasonerResponse references an event or policy ID the
    model was never shown, or uses a value outside the strict schema."""


class TrajectoryReasonerProvider(Protocol):
    def assess(self, request: ReasonerRequest) -> ReasonerResponse: ...


def validate_response(request: ReasonerRequest, response: ReasonerResponse) -> None:
    """Raises ReasonerFabricationError on any schema or fabrication violation.
    Does not mutate `response`."""
    if response.assessment not in _ASSESSMENTS:
        raise ReasonerFabricationError(f"assessment {response.assessment!r} is not one of {_ASSESSMENTS}")
    if response.recommended_disposition not in _DISPOSITIONS:
        raise ReasonerFabricationError(f"recommended_disposition {response.recommended_disposition!r} invalid")
    if not (0.0 <= response.uncertainty <= 1.0):
        raise ReasonerFabricationError(f"uncertainty {response.uncertainty} out of [0, 1]")

    known_event_ids = {request.action.event_id} | {e.event_id for e in request.relevant_events}
    unknown_events = set(response.supporting_event_ids) - known_event_ids
    if unknown_events:
        raise ReasonerFabricationError(f"referenced event id(s) not in the request: {sorted(unknown_events)}")

    known_policy_ids = set(request.applicable_policy_ids)
    unknown_policies = set(response.applicable_policy_clauses) - known_policy_ids
    if unknown_policies:
        raise ReasonerFabricationError(f"referenced policy id(s) not in the request: {sorted(unknown_policies)}")


class NullReasonerProvider:
    """Safe default when nothing else is configured: always defers, never
    invents an allow or a block."""

    def assess(self, request: ReasonerRequest) -> ReasonerResponse:
        return ReasonerResponse(
            assessment="insufficient_evidence",
            supporting_event_ids=[],
            observed_facts=["no trajectory-reasoner provider is configured"],
            applicable_policy_clauses=[],
            potential_impact="unknown",
            recommended_disposition="escalate",
            uncertainty=1.0,
            explanation="NullReasonerProvider: no reasoning performed; deferring to deterministic policy and human review.",
        )


class DeterministicMockProvider:
    """A small, explicitly-documented RULE-BASED stand-in for an LLM --
    NOT a model. Used by the test suite and episodes.py's eval runner so the
    whole pipeline is exercised end-to-end without a real API call. It looks
    only at the same structured ReasonerRequest fields a real model would
    get (no back-door access to ground truth) and applies a small, itself
    unit-tested ruleset."""

    def assess(self, request: ReasonerRequest) -> ReasonerResponse:
        action = request.action
        facts: List[str] = []
        supporting_ids = [action.event_id]

        indeterminate = [e for e in request.evidence if e.coverage == "indeterminate"]
        if indeterminate:
            facts.append(f"{len(indeterminate)} evidence finding(s) have incomplete coverage")
            return ReasonerResponse(
                assessment="insufficient_evidence", supporting_event_ids=supporting_ids,
                observed_facts=facts, applicable_policy_clauses=list(request.applicable_policy_ids),
                potential_impact="unknown due to incomplete evidence coverage",
                recommended_disposition="escalate", uncertainty=0.8,
                explanation="Evidence coverage is incomplete; cannot confirm alignment with the task contract.",
            )

        # Untrusted-content-induced privilege question: look for a
        # destination mismatch co-occurring with untrusted integrity.
        from .schemas import ConfidentialityLabel, IntegrityLabel  # local import avoids a cycle at module load

        if action.integrity == IntegrityLabel.UNTRUSTED_EXTERNAL and action.destinations:
            unauthorized = [d for d in action.destinations if d not in request.contract.approved_destinations]
            if unauthorized and action.confidentiality in (ConfidentialityLabel.PRIVATE, ConfidentialityLabel.SECRET):
                facts.append(f"action sourced from untrusted content proposes sending to unauthorized destination(s) {unauthorized}")
                return ReasonerResponse(
                    assessment="suspicious", supporting_event_ids=supporting_ids, observed_facts=facts,
                    applicable_policy_clauses=list(request.applicable_policy_ids),
                    potential_impact="possible data exfiltration to a destination the user never approved",
                    recommended_disposition="block", uncertainty=0.2,
                    explanation="Untrusted content appears to be inducing a send to a destination outside the task contract.",
                )

        if not request.contract.goal and not request.contract.permitted_categories:
            facts.append("no explicit task contract was provided for this session")
            return ReasonerResponse(
                assessment="unexplained", supporting_event_ids=supporting_ids, observed_facts=facts,
                applicable_policy_clauses=list(request.applicable_policy_ids),
                potential_impact="cannot confirm this action is authorized without a stated task",
                recommended_disposition="escalate", uncertainty=0.6,
                explanation="No task contract is available to judge authorization against.",
            )

        facts.append("no contract, destination, or coverage anomaly found")
        return ReasonerResponse(
            assessment="aligned", supporting_event_ids=supporting_ids, observed_facts=facts,
            applicable_policy_clauses=[], potential_impact="none identified",
            recommended_disposition="allow", uncertainty=0.1,
            explanation="Action is consistent with the stated task contract and available evidence.",
        )

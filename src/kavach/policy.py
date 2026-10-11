"""Minimal deterministic policy interface and decision composition."""
from __future__ import annotations

from typing import Protocol, Sequence

from .schema import ActionEvent, Decision, MonitorResult, PolicyFinding, Visibility


class Policy(Protocol):
    policy_id: str

    def evaluate(self, event: ActionEvent) -> PolicyFinding | None:
        """Return a finding when this policy needs a decision; otherwise None."""
        ...


def required_fields_available(event: ActionEvent, required_fields: Sequence[str]) -> bool:
    """Required fields must be present, not redacted or inferred from absence."""
    return all(
        event.visibility.get(name, Visibility.UNKNOWN) == Visibility.PRESENT
        for name in required_fields
    )


def combine_findings(event: ActionEvent, findings: Sequence[PolicyFinding]) -> MonitorResult:
    """Priority: BLOCK > REVIEW > INDETERMINATE > ALLOW."""
    if any(f.decision == Decision.BLOCK for f in findings):
        decision = Decision.BLOCK
    elif any(f.decision == Decision.REVIEW for f in findings):
        decision = Decision.REVIEW
    elif any(f.decision == Decision.INDETERMINATE for f in findings):
        decision = Decision.INDETERMINATE
    else:
        decision = Decision.ALLOW
    return MonitorResult(
        event_id=event.event_id,
        decision=decision,
        reason_codes=tuple(dict.fromkeys(f.reason_code for f in findings)),
        policy_ids=tuple(dict.fromkeys(f.policy_id for f in findings)),
        findings=tuple(findings),
    )

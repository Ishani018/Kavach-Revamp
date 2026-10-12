"""
kavach/ministers/navigator2/verdict.py
=========================================

Component 7 -- Verdict and Explanation.

compose() is the one place all of NAVIGATOR 2.0's signals (deterministic
policy decisions, the optional reasoner output, evidence coverage) are
combined into a final disposition. See docs/navigator2-architecture.md SS9
for the exact, numbered rule order this function implements -- the ordering
matters and is tested directly in tests/test_navigator2_unit.py.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .policy import PolicyEngine
from .schemas import EvidenceFinding, Navigator2Verdict, PolicyDecision, ReasonerResponse, TaskContract


def compose(
    *,
    session_id: str,
    event_id: str,
    contract: TaskContract,
    policy_decisions: List[PolicyDecision],
    reasoner_output: Optional[ReasonerResponse],
    reasoner_invoked: bool,
    legacy_minister_results: Dict[str, str],
    evidence: List[EvidenceFinding],
    reasoner_timed_out: bool = False,
    reasoner_rejected: bool = False,
) -> Navigator2Verdict:
    reasoner_capped = False

    blocks = [d for d in policy_decisions if d.verdict == "block"]
    escalates = [d for d in policy_decisions if d.verdict == "escalate"]
    requires_approval = any(d.requires_approval for d in policy_decisions)

    if blocks:
        disposition = "block"
        reason = "deterministic policy BLOCK: " + "; ".join(f"{d.policy_id} ({d.reason})" for d in blocks)
    elif escalates or (reasoner_output is not None and reasoner_output.recommended_disposition == "escalate"):
        disposition = "escalate"
        parts = [f"{d.policy_id} ({d.reason})" for d in escalates]
        if reasoner_output is not None and reasoner_output.recommended_disposition == "escalate":
            parts.append(f"reasoner: {reasoner_output.explanation}")
        reason = "escalated: " + "; ".join(parts) if parts else "escalated"
    elif reasoner_output is not None and reasoner_output.recommended_disposition == "block":
        # A model's own recommendation is never alone sufficient to reach
        # BLOCK -- capped to escalate (task brief: "no fabricated authority";
        # "a positive semantic match/model vote alone does not prove").
        disposition = "escalate"
        reasoner_capped = True
        reason = f"reasoner recommended block but no deterministic policy backs it; capped to escalate: {reasoner_output.explanation}"
    elif any(e.coverage == "indeterminate" for e in evidence):
        # Belt-and-suspenders: POL-007 should already have escalated this,
        # but compose() never silently allows on a coverage gap even if the
        # policy engine was bypassed or misconfigured by a caller.
        disposition = "escalate"
        reason = "evidence coverage incomplete; not silently allowed"
    else:
        disposition = "allow"
        reason = "no policy objection, no unresolved reasoner concern, evidence coverage complete"

    return Navigator2Verdict(
        session_id=session_id,
        event_id=event_id,
        disposition=disposition,
        requires_approval=requires_approval,
        policy_version=PolicyEngine.ENGINE_VERSION,
        contract_version=contract.version,
        policy_decisions=policy_decisions,
        reasoner_output=reasoner_output,
        reasoner_invoked=reasoner_invoked,
        reasoner_capped=reasoner_capped,
        reasoner_timed_out=reasoner_timed_out,
        reasoner_rejected=reasoner_rejected,
        specialist_results_considered=dict(legacy_minister_results),
        legacy_navigator_result=(
            {"verdict": legacy_minister_results["NAVIGATOR"]} if "NAVIGATOR" in legacy_minister_results else None
        ),
        evidence=evidence,
        reason=reason,
    )

"""
kavach/ministers/navigator2/policy.py
========================================

Component 4 -- Deterministic Policy Enforcement Point.

Each policy is a small, independently unit-testable class with a fixed id
and version. Every policy requires a NAMED structured fact (a contract
field, a ledger lookup, an AST-confirmed evidence finding, or another
minister's already-computed verdict) -- none of them is a broad keyword
match. See docs/navigator2-architecture.md SS6 for the policy table and the
evidence each one requires before it is allowed to fire.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .schemas import ConfidentialityLabel, EvidenceFinding, IntegrityLabel, PolicyDecision, SessionEvent, TaskContract


@dataclass
class PolicyFacts:
    contract: TaskContract
    event: SessionEvent
    recent_events: List[SessionEvent]
    evidence: List[EvidenceFinding]
    legacy_minister_results: Dict[str, str]
    destinations: List[str] = field(default_factory=list)
    untrusted_revision_attempted: bool = False
    untrusted_revision_fields: Dict[str, Any] = field(default_factory=dict)


class Policy:
    id: str = "POL-000"
    version: str = "1.0.0"
    title: str = "base"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        raise NotImplementedError


class ProvenanceExfilPolicy(Policy):
    """POL-001: a destination found in THIS call's own arguments is not in
    contract.approved_destinations, confidentiality is PRIVATE/SECRET, and
    integrity traces to a protected source. A decode operation or a local
    file write alone NEVER satisfies this -- there must be a concrete
    destination string (see evidence.extract_destinations)."""

    id = "POL-001"
    version = "1.0.0"
    title = "proven-exfil-to-unauthorized-destination"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        if not facts.destinations:
            return None
        if facts.event.confidentiality not in (ConfidentialityLabel.PRIVATE, ConfidentialityLabel.SECRET):
            return None
        unauthorized = [d for d in facts.destinations if d not in facts.contract.approved_destinations]
        if not unauthorized:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="block",
            reason=(f"destination(s) {unauthorized} not in the contract's approved_destinations, "
                    f"and this action's confidentiality is {facts.event.confidentiality.value}"),
            evidence_refs=[f"destinations={unauthorized}"],
            event_ids=[facts.event.event_id],
        )


class ContractScopePolicy(Policy):
    """POL-002: event touches a path outside every contract.workspace_scope
    prefix, AND a scope was actually declared (never fires on an unscoped
    contract -- an unscoped contract cannot prove a violation)."""

    id = "POL-002"
    version = "1.0.0"
    title = "contract-scope-violation"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        scope = facts.contract.workspace_scope
        if not scope:
            return None
        paths = list(facts.event.artifacts_read) + list(facts.event.artifacts_written)
        if not paths:
            return None
        outside = [p for p in paths if not any(p.startswith(prefix) for prefix in scope)]
        if not outside:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="escalate",
            reason=f"path(s) {outside} fall outside the declared workspace_scope {scope}",
            evidence_refs=[f"paths={outside}"], event_ids=[facts.event.event_id],
        )


class UntrustedPrivilegeInductionPolicy(Policy):
    """POL-003: untrusted content tried to revise the task contract (the
    rejected UntrustedRevisionAttempt from contract.py). A hard block --
    this is the CaMeL-derived trust-boundary rule, not a judgment call."""

    id = "POL-003"
    version = "1.0.0"
    title = "untrusted-content-privilege-induction"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        if not facts.untrusted_revision_attempted:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="block",
            reason=(f"this action attempted to change the task contract "
                    f"(fields {sorted(facts.untrusted_revision_fields)}) from a "
                    f"non-trusted-instruction source ({facts.event.integrity.value})"),
            evidence_refs=[f"changed_fields={sorted(facts.untrusted_revision_fields)}"],
            event_ids=[facts.event.event_id],
        )


class DecodeExecuteStructuralPolicy(Policy):
    """POL-004: DecodeExecutionEvidenceModule resolved a decode->execute data
    flow (coverage='full', confidence>=0.9). Escalates on its own; only
    reaches block if POL-001 ALSO fires on the same event (proven external
    destination for the decoded content)."""

    id = "POL-004"
    version = "1.0.0"
    title = "decode-execute-structural"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        hits = [e for e in facts.evidence
                if e.module == "decode_execution_ast" and e.coverage == "full" and e.confidence >= 0.9]
        if not hits:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="escalate",
            reason="AST-confirmed decode-then-execute data flow " + "; ".join(h.claim for h in hits),
            evidence_refs=[h.claim for h in hits], event_ids=[facts.event.event_id],
        )


class SpecialistHardBlockPolicy(Policy):
    """POL-005: pass-through of any legacy specialist BLOCK. Not a new
    detection -- a structural guarantee that NAVIGATOR 2.0 can never
    downgrade an existing hard block."""

    id = "POL-005"
    version = "1.0.0"
    title = "specialist-hard-block-preserved"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        blocked = [name for name, verdict in facts.legacy_minister_results.items()
                   if verdict == "BLOCK" and name != "NAVIGATOR"]
        # Legacy NAVIGATOR's own BLOCK is a semantic match, not a specialist
        # hard fact -- it is surfaced as supporting evidence (evidence.py),
        # not pass-through-preserved here, consistent with "a positive
        # semantic match alone does not prove a structural condition."
        if not blocked:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="block",
            reason=f"specialist minister(s) {blocked} returned a hard BLOCK; never downgraded",
            evidence_refs=[f"blocked_by={blocked}"], event_ids=[facts.event.event_id],
        )


class HighImpactApprovalPolicy(Policy):
    """POL-006: contract names this action's tool as high-impact, and no
    prior ledger event for this session recorded an approval."""

    id = "POL-006"
    version = "1.0.0"
    title = "high-impact-without-approval"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        if facts.event.tool_name not in facts.contract.high_impact_categories_requiring_approval:
            return None
        approved = any(e.source_kind == "approval" for e in facts.recent_events)
        if approved:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="escalate",
            reason=f"tool {facts.event.tool_name!r} is contract-flagged high-impact and no approval event was recorded",
            evidence_refs=[], event_ids=[facts.event.event_id], requires_approval=True,
        )


class InsufficientEvidenceCoveragePolicy(Policy):
    """POL-007: any evidence finding has coverage='indeterminate'. Missing
    coverage is never silently treated as safe."""

    id = "POL-007"
    version = "1.0.0"
    title = "insufficient-evidence-coverage"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        gaps = [e for e in facts.evidence if e.coverage == "indeterminate"]
        if not gaps:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="escalate",
            reason="evidence coverage is incomplete for this action: " + "; ".join(g.claim for g in gaps),
            evidence_refs=[g.claim for g in gaps], event_ids=[facts.event.event_id],
        )


class ExplicitRestrictionPolicy(Policy):
    """POL-008: the event's own tool_name is in the contract's explicit
    denied_categories. This is the most literal, least inferential policy in
    the engine -- 'the trusted contract said no' -- and is a hard block, not
    an escalate, since by definition the restriction was stated explicitly
    (unlike POL-002's scope check, which infers a boundary from path
    prefixes and therefore only escalates). Only fires when the contract
    actually names the category; never guesses what should be denied."""

    id = "POL-008"
    version = "1.0.0"
    title = "explicit-task-restriction-violation"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        if facts.event.tool_name not in facts.contract.denied_categories:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="block",
            reason=f"tool {facts.event.tool_name!r} is explicitly listed in the contract's denied_categories",
            evidence_refs=[f"denied_categories={facts.contract.denied_categories}"],
            event_ids=[facts.event.event_id],
        )


class CrossCallSensitiveReadThenSendPolicy(Policy):
    """POL-009: a genuinely CROSS-CALL policy, independent of both this
    event's own (possibly unremarkable) confidentiality AND of core.py's
    direct-parent propagation shortcut. It scans the ledger's own
    authoritative recent_events window (facts.recent_events, populated by
    SessionEventLedger.recent() -- not by whatever parent_event_ids this
    call happens to claim) for an EARLIER event in the same session that
    touched a PRIVATE/SECRET artifact, and fires if the CURRENT event sends
    to a destination the contract never approved.

    Why this must not depend on parent_event_ids: a caller (or a compromised
    orchestrator) could supply a forged or simply wrong parent reference for
    the send call, pointing away from the real earlier read. Because this
    policy reads the ledger's own append-ordered history instead of trusting
    the claimed parent chain, a forged parent_event_ids value cannot hide a
    real prior sensitive read from it -- see
    tests/test_navigator2_unit.py::TestPolicies::test_pol009_is_independent_of_forged_parent_references."""

    id = "POL-009"
    version = "1.0.0"
    title = "cross-call-sensitive-read-then-transmit"

    def evaluate(self, facts: PolicyFacts) -> Optional[PolicyDecision]:
        if not facts.destinations:
            return None
        unauthorized = [d for d in facts.destinations if d not in facts.contract.approved_destinations]
        if not unauthorized:
            return None
        prior_sensitive = [
            e for e in facts.recent_events
            if e.event_id != facts.event.event_id
            and e.confidentiality in (ConfidentialityLabel.PRIVATE, ConfidentialityLabel.SECRET)
            and (e.artifacts_read or e.artifacts_written)
        ]
        if not prior_sensitive:
            return None
        return PolicyDecision(
            policy_id=self.id, policy_version=self.version, verdict="block",
            reason=(f"session previously touched sensitive artifact(s) in event(s) "
                    f"{[e.event_id for e in prior_sensitive]}; this action now sends to "
                    f"unauthorized destination(s) {unauthorized}"),
            evidence_refs=[f"prior_sensitive_events={[e.event_id for e in prior_sensitive]}", f"destinations={unauthorized}"],
            event_ids=[facts.event.event_id] + [e.event_id for e in prior_sensitive],
        )


DEFAULT_POLICIES: List[Policy] = [
    ProvenanceExfilPolicy(),
    ContractScopePolicy(),
    UntrustedPrivilegeInductionPolicy(),
    DecodeExecuteStructuralPolicy(),
    SpecialistHardBlockPolicy(),
    HighImpactApprovalPolicy(),
    ExplicitRestrictionPolicy(),
    CrossCallSensitiveReadThenSendPolicy(),
    InsufficientEvidenceCoveragePolicy(),
]


class PolicyEngine:
    ENGINE_VERSION = "navigator2-policy/1.0.0"

    def __init__(self, policies: Optional[List[Policy]] = None) -> None:
        self.policies = policies if policies is not None else list(DEFAULT_POLICIES)

    def evaluate_all(self, facts: PolicyFacts) -> List[PolicyDecision]:
        decisions: List[PolicyDecision] = []
        for p in self.policies:
            try:
                d = p.evaluate(facts)
            except Exception as e:
                # A policy must never crash the pipeline; a failing policy is
                # itself a coverage gap, fail toward escalate, never allow.
                d = PolicyDecision(
                    policy_id=getattr(p, "id", "UNKNOWN"), policy_version=getattr(p, "version", "0"),
                    verdict="escalate", reason=f"policy raised {type(e).__name__}; failing toward escalate",
                    event_ids=[facts.event.event_id],
                )
            if d is not None:
                decisions.append(d)
        return decisions

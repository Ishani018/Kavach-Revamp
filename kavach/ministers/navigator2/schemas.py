"""
kavach/ministers/navigator2/schemas.py
========================================

Typed data contracts for NAVIGATOR 2.0. Nothing here is imported by, or
changes, `kavach/schemas.py` (the production wire contract). These models
are internal to the shadow-mode prototype.

Design rule enforced throughout this file (see docs/navigator2-architecture.md
§5): integrity and confidentiality are always two separate fields. No model
below collapses them into a single trust/risk score.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IntegrityLabel(str, Enum):
    """Where a piece of content's AUTHORITY came from. Never inferred from
    confidentiality, and never silently upgraded."""

    TRUSTED_INSTRUCTION = "trusted_instruction"   # this session's own user_instruction context field
    TRUSTED_SYSTEM = "trusted_system"             # Kavach's own deterministic minister/system output
    UNTRUSTED_EXTERNAL = "untrusted_external"     # tool_output, or anything derived from one
    UNKNOWN = "unknown"                           # no context field told us the origin


class ConfidentialityLabel(str, Enum):
    """How sensitive the content is. Independent of IntegrityLabel: an
    untrusted document can describe public information; a trusted system
    call can legitimately touch secret material."""

    PUBLIC = "public"
    PRIVATE = "private"
    SECRET = "secret"
    UNKNOWN = "unknown"


# Trust order for merge_integrity: index 0 is LEAST trusted, wins a merge.
_INTEGRITY_TRUST_ORDER: List[IntegrityLabel] = [
    IntegrityLabel.UNTRUSTED_EXTERNAL,
    IntegrityLabel.UNKNOWN,
    IntegrityLabel.TRUSTED_SYSTEM,
    IntegrityLabel.TRUSTED_INSTRUCTION,
]

# Sensitivity order for merge_confidentiality: index 0 is LEAST sensitive.
_CONFIDENTIALITY_ORDER: List[ConfidentialityLabel] = [
    ConfidentialityLabel.PUBLIC,
    ConfidentialityLabel.UNKNOWN,
    ConfidentialityLabel.PRIVATE,
    ConfidentialityLabel.SECRET,
]


def merge_integrity(a: IntegrityLabel, b: IntegrityLabel) -> IntegrityLabel:
    """The least-trusted of the two wins. UNKNOWN never silently becomes trusted."""
    ia, ib = _INTEGRITY_TRUST_ORDER.index(a), _INTEGRITY_TRUST_ORDER.index(b)
    return a if ia <= ib else b


def merge_confidentiality(a: ConfidentialityLabel, b: ConfidentialityLabel) -> ConfidentialityLabel:
    """The most-sensitive of the two wins."""
    ia, ib = _CONFIDENTIALITY_ORDER.index(a), _CONFIDENTIALITY_ORDER.index(b)
    return a if ia >= ib else b


class ProvenanceTag(BaseModel):
    integrity: IntegrityLabel
    confidentiality: ConfidentialityLabel
    # IDs of events/sources that contributed to this label, for audit.
    sources: List[str] = Field(default_factory=list)
    # Short notes on what transformed the value (e.g. "base64-decoded"), never raw content.
    transforms: List[str] = Field(default_factory=list)
    # Honest statement of what this label does NOT prove. Always non-empty.
    coverage_note: str = "heuristic, call-scoped classification; not byte-level taint tracking"


class ContractRevision(BaseModel):
    version: int
    event_id: Optional[str] = None
    integrity: IntegrityLabel
    accepted: bool
    reason: str
    # The fields that changed, as {field_name: new_value}. Never includes
    # free-text tool output, only the structured delta actually applied.
    changed_fields: Dict[str, Any] = Field(default_factory=dict)


class TaskContract(BaseModel):
    session_id: str
    version: int = 0
    goal: str = ""
    workspace_scope: List[str] = Field(default_factory=list)
    permitted_categories: List[str] = Field(default_factory=list)
    denied_categories: List[str] = Field(default_factory=list)
    approved_destinations: List[str] = Field(default_factory=list)
    high_impact_categories_requiring_approval: List[str] = Field(default_factory=list)
    unresolved_ambiguities: List[str] = Field(default_factory=list)
    created_from_event_id: Optional[str] = None
    history: List[ContractRevision] = Field(default_factory=list)


class SessionEvent(BaseModel):
    session_id: str
    event_id: str
    seq: int
    timestamp: float
    parent_event_ids: List[str] = Field(default_factory=list)
    tool_name: str
    # Redacted argument metadata only (e.g. key names, lengths, shapes) -- never
    # raw secret values. Populated by core.py's `_summarize_args`.
    arg_summary: Dict[str, Any] = Field(default_factory=dict)
    source_kind: str = "unknown"   # "user_instruction" | "tool_output" | "system" | "approval" | "unknown"
    integrity: IntegrityLabel = IntegrityLabel.UNKNOWN
    confidentiality: ConfidentialityLabel = ConfidentialityLabel.UNKNOWN
    artifacts_read: List[str] = Field(default_factory=list)
    artifacts_written: List[str] = Field(default_factory=list)
    destinations: List[str] = Field(default_factory=list)
    history_gap: bool = False
    notes: List[str] = Field(default_factory=list)
    # Legacy minister verdict strings only (e.g. {"VAULT": "ALLOW"}) -- never
    # the minister's reason text, which can carry redacted-but-still-sensitive detail.
    legacy_minister_results: Dict[str, str] = Field(default_factory=dict)
    disposition: Optional[str] = None   # filled in by core.py after Navigator2 decides


class EvidenceFinding(BaseModel):
    module: str
    claim: str
    confidence: float = 0.0
    coverage: str = "indeterminate"   # "full" | "partial" | "indeterminate"
    supporting: Dict[str, Any] = Field(default_factory=dict)
    event_ids: List[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    policy_id: str
    policy_version: str
    verdict: str   # "block" | "escalate"  (policies never themselves emit "allow")
    reason: str
    evidence_refs: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    requires_approval: bool = False


class ReasonerRequest(BaseModel):
    contract: TaskContract
    action: SessionEvent
    relevant_events: List[SessionEvent] = Field(default_factory=list)
    evidence: List[EvidenceFinding] = Field(default_factory=list)
    minister_findings: Dict[str, str] = Field(default_factory=dict)
    applicable_policy_ids: List[str] = Field(default_factory=list)


class ReasonerResponse(BaseModel):
    assessment: str            # "aligned" | "unexplained" | "suspicious" | "insufficient_evidence"
    supporting_event_ids: List[str] = Field(default_factory=list)
    observed_facts: List[str] = Field(default_factory=list)
    applicable_policy_clauses: List[str] = Field(default_factory=list)
    potential_impact: str = ""
    recommended_disposition: str = "escalate"   # "allow" | "escalate" | "block"
    uncertainty: float = 1.0
    explanation: str = ""


class Navigator2Verdict(BaseModel):
    session_id: str
    event_id: str
    disposition: str   # "allow" | "escalate" | "block"
    requires_approval: bool = False
    policy_version: str
    contract_version: int
    policy_decisions: List[PolicyDecision] = Field(default_factory=list)
    reasoner_output: Optional[ReasonerResponse] = None
    reasoner_invoked: bool = False
    reasoner_capped: bool = False
    reasoner_timed_out: bool = False
    reasoner_rejected: bool = False   # True if a response was returned but failed schema/fabrication validation
    specialist_results_considered: Dict[str, str] = Field(default_factory=dict)
    legacy_navigator_result: Optional[Dict[str, Any]] = None
    evidence: List[EvidenceFinding] = Field(default_factory=list)
    reason: str = ""

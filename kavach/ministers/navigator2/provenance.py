"""
kavach/ministers/navigator2/provenance.py
============================================

Component 3 -- Integrity and Confidentiality Provenance.

A heuristic, call-scoped classifier -- NOT byte-level or semantic taint
tracking (stated explicitly per the task brief's own warning against
pretending otherwise). It answers a narrower question than
channel_taint.py's existing read->send taint: "is the content behind THIS
proposed action's instruction trustworthy enough to have come from the
user," which is what the contract trust boundary (contract.py) and POL-003
(policy.py) need. CHANNEL's own destination/taint verdict is reused as-is via
`legacy_minister_results`, never recomputed here.
"""

from __future__ import annotations

from typing import Dict, Optional

from ...schemas import ToolCall
from .schemas import ConfidentialityLabel, IntegrityLabel, ProvenanceTag, merge_confidentiality, merge_integrity

__all__ = ["compute_label", "merge_integrity", "merge_confidentiality"]


def compute_label(call: ToolCall, legacy_minister_results: Optional[Dict[str, str]] = None) -> ProvenanceTag:
    """`legacy_minister_results` is {"VAULT": "ALLOW", "EXECUTOR": "BLOCK", ...}
    -- verdict strings only, as already computed by the real ministers. This
    function never re-derives a minister's own judgment; it only reuses it."""
    legacy_minister_results = legacy_minister_results or {}
    ctx = call.context or {}
    has_tool_output = isinstance(ctx.get("tool_output"), str) and bool(ctx["tool_output"].strip())
    has_user_instruction = isinstance(ctx.get("user_instruction"), str) and bool(ctx["user_instruction"].strip())

    if has_tool_output:
        # Conservative: a call made in the context of ANY untrusted tool
        # output in play is the more distrusted label, even if a
        # user_instruction is also present. Unknown/mixed provenance must
        # not silently become trusted (task brief, Component 3).
        integrity = IntegrityLabel.UNTRUSTED_EXTERNAL
    elif has_user_instruction:
        integrity = IntegrityLabel.TRUSTED_INSTRUCTION
    else:
        integrity = IntegrityLabel.UNKNOWN

    if not legacy_minister_results:
        confidentiality = ConfidentialityLabel.UNKNOWN
    elif legacy_minister_results.get("VAULT") not in (None, "ALLOW"):
        confidentiality = ConfidentialityLabel.SECRET
    elif legacy_minister_results.get("CHANNEL") not in (None, "ALLOW"):
        # CHANNEL already owns destination/PII-adjacent judgment; reused, not reinvented.
        confidentiality = ConfidentialityLabel.PRIVATE
    elif all(v == "ALLOW" for v in legacy_minister_results.values()):
        confidentiality = ConfidentialityLabel.PUBLIC
    else:
        confidentiality = ConfidentialityLabel.UNKNOWN

    sources = [k for k, v in legacy_minister_results.items() if v not in (None, "ALLOW")]
    return ProvenanceTag(integrity=integrity, confidentiality=confidentiality, sources=sources)


def trusted_system_label() -> ProvenanceTag:
    """Label for Kavach-internal synthetic events (e.g. contract creation
    itself), never for anything derived from agent/tool/model content."""
    return ProvenanceTag(integrity=IntegrityLabel.TRUSTED_SYSTEM, confidentiality=ConfidentialityLabel.PUBLIC)

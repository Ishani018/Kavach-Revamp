"""
NAVIGATOR: intent and trajectory security backed by Invariant Guardrails.

The runtime uses Invariant's local deterministic policy interpreter over the
current tool call and append-ordered session history. It does not load BGE,
ChromaDB, remote detectors, or an LLM.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .navigator2 import Navigator2
from ..schemas import MinisterResult, ToolCall


class NavigatorMinister:
    name = "NAVIGATOR"

    def __init__(self, navigator: Optional[Navigator2] = None) -> None:
        self.navigator2 = navigator or Navigator2()

    def start_session(self, session_id: str, *, goal: str, **contract_fields: Any):
        """Seed a trusted contract from the trusted orchestrator before tool execution."""
        return self.navigator2.contract_store.start_session(
            session_id, goal=goal, **contract_fields
        )

    def check(self, call: ToolCall) -> MinisterResult:
        return self.check_with_context(call, {})

    def check_with_context(
        self, call: ToolCall, prior_results: Dict[str, MinisterResult]
    ) -> MinisterResult:
        """Reuse earlier ministers' actual results without rerunning them."""
        try:
            self._seed_trusted_instruction_if_needed(call)
            assessment = self.navigator2.check(call, legacy_results=prior_results)
        except Exception as exc:
            # Never echo raw arguments, destinations, secret values, or exception messages.
            return MinisterResult(
                minister=self.name,
                verdict="ESCALATE",
                reason="NAVIGATOR local policy evaluation failed; failing closed",
                matched_id="INVARIANT-FAILURE",
                diagnostics={
                    "engine": "invariant-localpolicy",
                    "failed": True,
                    "failure_type": type(exc).__name__,
                },
            )

        mapping = {"block": "BLOCK", "escalate": "ESCALATE", "allow": "ALLOW"}
        verdict = mapping.get(assessment.disposition, "ESCALATE")
        matches = [
            decision for decision in assessment.policy_decisions
            if (verdict == "BLOCK" and decision.verdict == "block")
            or (verdict == "ESCALATE" and decision.verdict == "escalate")
        ]
        matched_id = matches[0].policy_id if matches else None
        if verdict == "BLOCK":
            reason = "NAVIGATOR blocked by deterministic Invariant policy"
        elif verdict == "ESCALATE":
            reason = "NAVIGATOR requires review because policy or evidence is unresolved"
        else:
            reason = "NAVIGATOR found no applicable policy violation in available evidence"

        return MinisterResult(
            minister=self.name,
            verdict=verdict,
            reason=reason,
            matched_id=matched_id,
            confidence=None,
            diagnostics={
                "engine": "invariant-localpolicy",
                "policy_version": assessment.policy_version,
                "policy_ids": [decision.policy_id for decision in assessment.policy_decisions],
                "reasoner_invoked": assessment.reasoner_invoked,
                "reasoner_timed_out": assessment.reasoner_timed_out,
                "reasoner_rejected": assessment.reasoner_rejected,
                "evidence_coverage": {
                    "full": sum(1 for finding in assessment.evidence if finding.coverage == "full"),
                    "partial": sum(1 for finding in assessment.evidence if finding.coverage == "partial"),
                    "indeterminate": sum(1 for finding in assessment.evidence if finding.coverage == "indeterminate"),
                },
            },
        )

    def _seed_trusted_instruction_if_needed(self, call: ToolCall) -> None:
        """Seed only from a separately trusted instruction, never from tool output.

        The host must guarantee context.user_instruction originated at a trusted
        user/orchestrator boundary. The current HTTP API does not authenticate
        this field, so deployments must enforce that boundary themselves.
        """
        context = call.context or {}
        instruction = context.get("user_instruction")
        tool_output = context.get("tool_output")
        if not isinstance(instruction, str) or not instruction.strip():
            return
        if isinstance(tool_output, str) and tool_output.strip():
            return
        existing = self.navigator2.contract_store.get(call.session_id)
        if existing is not None and existing.version >= 1:
            return
        self.navigator2.contract_store.start_session(
            call.session_id,
            goal=instruction.strip(),
        )

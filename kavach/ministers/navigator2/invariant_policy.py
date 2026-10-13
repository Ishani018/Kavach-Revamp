"""
Invariant-backed NAVIGATOR policy engine.

Adapts Kavach's typed contract, evidence findings, and session history to the
upstream Invariant Guardrails local trace policy interpreter. This module
imports LocalPolicy explicitly; it never uses the environment-dependent Policy
alias, which can select a remote implementation.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from invariant.analyzer.policy import LocalPolicy

from .policy import PolicyFacts
from .schemas import ConfidentialityLabel, PolicyDecision, SessionEvent

_POLICY_PATH = Path(__file__).with_name("policies.iv")

_RULES = {
    "POL-001": ("block", "Sensitive information is being sent to a destination not authorized by the task contract."),
    "POL-002": ("escalate", "The action touches a path outside the declared workspace scope."),
    "POL-003": ("block", "Untrusted content attempted to change the trusted task contract."),
    "POL-004": ("escalate", "A parsed decode-then-execute data flow requires review."),
    "POL-005": ("block", "An earlier specialist minister issued a hard BLOCK."),
    "POL-006": ("escalate", "A high-impact action has no recorded approval event."),
    "POL-007": ("escalate", "The evidence parser or detector reports indeterminate coverage."),
    "POL-008": ("block", "The task contract explicitly denies this tool category."),
    "POL-009": ("block", "A prior permitted action touched a sensitive artifact and this action transmits to an unauthorized destination."),
}


@dataclass(frozen=True)
class RuleIdentity:
    id: str
    title: str
    version: str = "1.0.0"


class InvariantPolicyEngine:
    """Evaluate the pending call against the full session trace via Invariant LocalPolicy."""

    ENGINE_VERSION = "invariant-ai/0.3.5+kavach.1"

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        path = Path(policy_path or _POLICY_PATH)
        if not path.is_file():
            raise FileNotFoundError("NAVIGATOR Invariant policy file is missing")
        self._policy = LocalPolicy.from_file(str(path))
        self._lock = threading.RLock()
        self.policies = [
            RuleIdentity(rule_id, rationale)
            for rule_id, (_, rationale) in _RULES.items()
        ]

    @staticmethod
    def _unauthorized_destinations(facts: PolicyFacts) -> List[str]:
        allowed = set(facts.contract.approved_destinations)
        return [destination for destination in facts.destinations if destination not in allowed]

    @staticmethod
    def _inside_scope(path: str, prefix: str) -> bool:
        import os.path

        candidate = os.path.normpath(path)
        root = os.path.normpath(prefix)
        try:
            return os.path.commonpath([candidate, root]) == root
        except (ValueError, OSError):
            return False

    def _current_flags(self, facts: PolicyFacts) -> dict:
        event = facts.event
        contract = facts.contract
        unauthorized = self._unauthorized_destinations(facts)
        touched_paths = list(event.artifacts_read) + list(event.artifacts_written)
        outside_scope = bool(contract.workspace_scope) and any(
            not any(self._inside_scope(path, prefix) for prefix in contract.workspace_scope)
            for path in touched_paths
        )
        decode_confirmed = any(
            finding.module == "decode_execution_ast"
            and finding.coverage == "full"
            and finding.confidence >= 0.9
            for finding in facts.evidence
        )
        blocked_specialists = any(
            verdict == "BLOCK" and name != "NAVIGATOR"
            for name, verdict in facts.legacy_minister_results.items()
        )
        history_by_id = {prior.event_id: prior for prior in facts.session_history}

        def approval_matches(approval: SessionEvent) -> bool:
            # Approval only covers retrying the same high-impact tool that was
            # explicitly escalated immediately before the trusted approval event.
            if approval.source_kind != "approval":
                return False
            return any(
                (requested := history_by_id.get(parent_id)) is not None
                and requested.tool_name == event.tool_name
                and requested.disposition == "escalate"
                for parent_id in approval.parent_event_ids
            )

        approval_missing = (
            event.tool_name in contract.high_impact_categories_requiring_approval
            and not any(approval_matches(prior) for prior in facts.session_history)
        )
        return {
            "__kavach_current": True,
            "__kavach_private_or_secret": event.confidentiality in (
                ConfidentialityLabel.PRIVATE, ConfidentialityLabel.SECRET
            ),
            "__kavach_unapproved_destination": bool(unauthorized),
            "__kavach_outside_scope": outside_scope,
            "__kavach_untrusted_revision_attempted": facts.untrusted_revision_attempted,
            "__kavach_decode_execute": decode_confirmed,
            "__kavach_specialist_block": blocked_specialists,
            "__kavach_missing_approval": approval_missing,
            "__kavach_indeterminate_coverage": any(
                finding.coverage == "indeterminate" for finding in facts.evidence
            ),
            "__kavach_explicitly_denied": event.tool_name in contract.denied_categories,
        }

    @staticmethod
    def _historical_flags(event: SessionEvent) -> dict:
        # A proposed sensitive read remains relevant to a later send even if
        # a specialist also blocked it: NAVIGATOR cannot prove the host prevented
        # the read from executing. This errs toward blocking until the host binds
        # verdicts to actual execution outcomes.
        sensitive_was_touched = (
            event.confidentiality in (ConfidentialityLabel.PRIVATE, ConfidentialityLabel.SECRET)
            and bool(event.artifacts_read)
        )
        return {
            "__kavach_current": False,
            "__kavach_sensitive_artifact": sensitive_was_touched,
        }

    @staticmethod
    def _trace_message(event: SessionEvent, flags: dict) -> dict:
        # Only fixed booleans, the tool name, and event ID enter the policy trace.
        # Raw arguments, file paths, tool output, and destination strings are omitted.
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": event.event_id,
                "type": "function",
                "function": {"name": event.tool_name, "arguments": dict(flags)},
            }],
        }

    def evaluate_all(self, facts: PolicyFacts) -> List[PolicyDecision]:
        current = self._trace_message(facts.event, self._current_flags(facts))
        past = [
            self._trace_message(event, self._historical_flags(event))
            for event in facts.session_history
        ]
        try:
            # LocalPolicy contains mutable evaluation caches; share safely across sessions.
            with self._lock:
                result = self._policy.analyze_pending(past, [current])
            decisions = []
            for error in result.errors:
                args = getattr(error, "args", [])
                marker = args[0] if args and isinstance(args[0], str) else ""
                rule_id = marker.split(":", 1)[1] if ":" in marker else ""
                if rule_id not in _RULES:
                    return [self._failure("Unrecognized Invariant rule result; failing closed", facts.event)]
                verdict, rationale = _RULES[rule_id]
                decisions.append(PolicyDecision(
                    policy_id=rule_id,
                    policy_version="1.0.0",
                    verdict=verdict,
                    reason=rationale,
                    evidence_refs=["invariant-local-policy-rule"],
                    event_ids=[facts.event.event_id],
                    requires_approval=(rule_id == "POL-006"),
                ))
            deduplicated = {decision.policy_id: decision for decision in decisions}
            return list(deduplicated.values())
        except Exception:
            # Do not echo exception text; it can contain source arguments or other input.
            return [self._failure("Invariant local policy evaluation failed; failing closed", facts.event)]

    @staticmethod
    def _failure(reason: str, event: SessionEvent) -> PolicyDecision:
        return PolicyDecision(
            policy_id="INVARIANT-FAILURE",
            policy_version="1.0.0",
            verdict="escalate",
            reason=reason,
            evidence_refs=["fail-closed"],
            event_ids=[event.event_id],
        )

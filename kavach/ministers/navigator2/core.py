"""
kavach/ministers/navigator2/core.py
======================================

Navigator2 orchestrator: wires Components 1-7 together for one proposed
ToolCall. See docs/navigator2-architecture.md SS2 for the data-flow diagram
this function implements.

On the navigator-invariant-runtime branch, NavigatorMinister constructs
this orchestrator in the active NAVIGATOR verdict path. ShadowRunner remains
available for isolated regression/evaluation comparisons.
"""

from __future__ import annotations

import concurrent.futures as _cf
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ...schemas import MinisterResult, ToolCall
from . import evidence as evidence_mod
from . import provenance
from .contract import TaskContractStore, UntrustedRevisionAttempt
from .ledger import SessionEventLedger
from .policy import PolicyEngine, PolicyFacts
from .invariant_policy import InvariantPolicyEngine
from .reasoner import DeterministicMockProvider, ReasonerFabricationError, TrajectoryReasonerProvider, validate_response
from .schemas import ConfidentialityLabel, EvidenceFinding, IntegrityLabel, Navigator2Verdict, ReasonerRequest, ReasonerResponse, SessionEvent, merge_confidentiality
from . import verdict as verdict_mod

# No LLM, no network call, and no mandatory external dependency is reachable
# from anywhere in this module. `reasoner_provider` defaults to
# DeterministicMockProvider (reasoner.py) -- a documented rule-based stand-in,
# never a model -- and every path that *would* consult it is capped by
# `_REASONER_TIMEOUT_SECONDS` below so a slow/hung optional component can
# never block the deterministic policy decision that already governs the
# outcome whenever one fired. See docs/navigator2-report.md SS"No-LLM
# architecture" for the full accounting of what runs without a reasoner at
# all versus what merely tolerates one being absent, malformed, or hostile.
_DEFAULT_REASONER_TIMEOUT_SECONDS = 2.0

_PATH_RE = re.compile(r"(?:~?/[^\s'\"|;>]+|\.{1,2}/[^\s'\"|;>]+|[A-Za-z]:\\[^\s'\"|;>]+)")
_WRITE_HINT_TOOLS = re.compile(r"write|save|delete|remove|rm\b|mv\b|mkdir|truncate|append", re.IGNORECASE)
_WRITE_HINT_TEXT = re.compile(r">>|>\s|^\s*rm\s|^\s*mv\s|\brm\s+-", re.IGNORECASE)

# Heuristic detector for content that LOOKS LIKE it is trying to instruct a
# contract change (new destination, relaxed restriction, ignore-prior-
# instructions phrasing). Deliberately narrow and documented as heuristic --
# its only job is to decide whether to ATTEMPT a contract.revise() call; the
# trust boundary enforcement itself lives in contract.py, not here.
_IGNORE_PRIOR_RE = re.compile(r"\b(ignore|disregard)\b.{0,20}\b(previous|prior|earlier)\b.{0,20}\binstruction", re.IGNORECASE)
_FORWARD_TO_RE = re.compile(r"\b(forward|send|email|copy)\b.{0,30}\bto\b", re.IGNORECASE)



def _classify_artifact_confidentiality(paths: List[str]) -> Optional[ConfidentialityLabel]:
    """Conservatively classify extracted artifact PATHS, not arbitrary text keywords.

    This is a heuristic path classifier, not content inspection or byte-level taint.
    """
    segments = [
        segment
        for path in paths
        for segment in path.replace("\\", "/").lower().split("/")
        if segment
    ]
    secret_names = {
        ".ssh", ".aws", ".env", "id_rsa", "id_ed25519", "id_ecdsa",
        "passwd", "shadow", "secrets.json", "credentials.json",
    }
    secret_fragments = (
        "credential", "private_key", "private-key", "api_key", "api-key",
        "access_token", "refresh_token", "password", "secret", ".pem",
        ".p12", ".pfx",
    )
    if any(
        segment in secret_names or any(fragment in segment for fragment in secret_fragments)
        for segment in segments
    ):
        return ConfidentialityLabel.SECRET

    private_names = {
        "hr", "private", "personal", "medical", "patient", "payroll",
        "salary", "salaries", "customer", "customers", "bank", "invoice",
        "invoices", "employee", "employees", "pii", "user_data", "userdata",
    }
    private_fragments = (
        "payroll", "salary", "salaries", "customer_data", "personal_data",
        "medical_record", "patient_data", "employee_data", "user_data",
    )
    if any(
        segment in private_names or any(fragment in segment for fragment in private_fragments)
        for segment in segments
    ):
        return ConfidentialityLabel.PRIVATE
    return None


def _summarize_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Redacted argument metadata only -- never raw values."""
    summary: Dict[str, Any] = {"keys": sorted(args.keys()), "arg_count": len(args)}
    for k, v in args.items():
        if isinstance(v, str):
            summary.setdefault("string_lengths", {})[k] = len(v)
    return summary


def _extract_artifacts(call: ToolCall) -> Tuple[List[str], List[str]]:
    text_parts = [v for v in (call.arguments or {}).values() if isinstance(v, str)]
    blob = "\n".join(text_parts)
    paths = sorted(set(_PATH_RE.findall(blob)))
    if not paths:
        return [], []
    is_write = bool(_WRITE_HINT_TOOLS.search(call.tool_name)) or bool(_WRITE_HINT_TEXT.search(blob))
    return ([], paths) if is_write else (paths, [])


def _detect_candidate_contract_change(call: ToolCall) -> Optional[Dict[str, Any]]:
    """Looks at tool_output / user_instruction text for a phrase shaped like
    an attempt to change what's authorized. Returns a changed_fields dict if
    something was found, else None. This only decides whether to ATTEMPT a
    revision -- contract.py's trust-boundary check decides whether it
    succeeds."""
    ctx = call.context or {}
    text = ctx.get("tool_output") if isinstance(ctx.get("tool_output"), str) else ctx.get("user_instruction")
    if not isinstance(text, str) or not text.strip():
        return None
    changed: Dict[str, Any] = {}
    if _IGNORE_PRIOR_RE.search(text):
        changed["unresolved_ambiguities"] = ["content attempted to instruct ignoring prior instructions"]
    dest_match = _FORWARD_TO_RE.search(text)
    if dest_match:
        # Only a CONCRETE destination string is treated as an attempted
        # contract change -- a vague phrase ("my own email on file") with no
        # resolvable destination is explicitly NOT enough evidence to act on
        # (see episodes.py E11: this is the false-positive guard case).
        destinations = evidence_mod.extract_destinations_from_text(text)
        if destinations:
            changed["approved_destinations"] = destinations
    return changed or None


class Navigator2:
    def __init__(
        self,
        *,
        contract_store: Optional[TaskContractStore] = None,
        ledger: Optional[SessionEventLedger] = None,
        policy_engine: Optional[Any] = None,
        reasoner_provider: Optional[TrajectoryReasonerProvider] = None,
        evidence_modules: Optional[list] = None,
        relevant_event_window: int = 20,
        reasoner_timeout_seconds: float = _DEFAULT_REASONER_TIMEOUT_SECONDS,
    ) -> None:
        self.contract_store = contract_store or TaskContractStore()
        self.ledger = ledger or SessionEventLedger()
        # Active runtime policy evaluation uses the upstream Invariant LocalPolicy interpreter.
        self.policy_engine = policy_engine or InvariantPolicyEngine()
        # Default is DeterministicMockProvider -- a rule-based fixture, never
        # an LLM (see reasoner.py's module docstring). No provider shipped in
        # this package makes a network call or requires an API key.
        self.reasoner_provider = reasoner_provider or DeterministicMockProvider()
        self.evidence_modules = evidence_modules
        self.relevant_event_window = relevant_event_window
        self.reasoner_timeout_seconds = reasoner_timeout_seconds

    def _needs_reasoner(self, contract, policy_decisions, evidence) -> bool:
        if any(d.verdict == "block" for d in policy_decisions):
            return False  # already decisive; don't spend reasoner cost
        if contract.unresolved_ambiguities:
            return True
        if any(d.verdict == "escalate" for d in policy_decisions):
            return True
        if any(e.coverage == "indeterminate" for e in evidence):
            return True
        return False

    def _propagate_confidentiality(self, base_confidentiality, parents: List[str]):
        """Conservative, call-scoped CONFIDENTIALITY propagation along the
        declared parent chain: an event inherits at least the most-sensitive
        confidentiality of its own direct parent(s), on top of whatever its
        own call content/legacy-minister results already computed --
        sensitivity does not un-happen just because a later call's own
        arguments look innocuous. This is still a heuristic, not byte-level
        taint tracking (see provenance.py's own docstring): it only sees
        labels THIS prototype itself recorded in the ledger, and an
        unresolvable parent (missing, forged, or not yet appended) silently
        contributes NOTHING, neither trusting nor punishing a reference this
        component cannot verify.

        Deliberately NOT done for INTEGRITY: the contract-revision trust gate
        (contract.py) must judge whether THIS SPECIFIC event is a genuine,
        directly-supplied trusted instruction, on its own terms. Propagating
        'least trusted integrity wins' into that same field would mean one
        early untrusted tool_output permanently strips the user's own ability
        to issue new trusted instructions for the rest of the session --
        exactly the kind of over-blocking the task brief warns against.
        merge_integrity/merge_confidentiality (schemas.py) remain available,
        generic utilities for any future component that needs the symmetric
        version; this orchestrator deliberately only applies the
        confidentiality half to the event's primary field. POL-009
        (policy.py) independently re-derives the cross-call sensitivity
        signal from the ledger's own recent_events window -- not from this
        propagation shortcut -- so a forged/broken parent_event_ids value
        cannot hide a real prior sensitive read from it either."""
        confidentiality = base_confidentiality
        for pid in parents:
            parent = self.ledger.get(pid)
            if parent is None:
                continue
            confidentiality = merge_confidentiality(confidentiality, parent.confidentiality)
        return confidentiality

    def _call_reasoner(self, request: ReasonerRequest):
        """Runs the (by default, non-LLM, rule-based) reasoner provider under
        a hard wall-clock timeout so a slow or hung OPTIONAL component can
        never block the pipeline indefinitely. Returns (response_or_None,
        timed_out: bool). A timeout is treated exactly like an unavailable
        reasoner -- never like a silent 'allow'; see verdict.compose()'s
        coverage-gap rule, which this feeds via the appended indeterminate
        EvidenceFinding in check()."""
        ex = _cf.ThreadPoolExecutor(max_workers=1)
        future = ex.submit(self.reasoner_provider.assess, request)
        try:
            return future.result(timeout=self.reasoner_timeout_seconds), False
        except _cf.TimeoutError:
            return None, True
        finally:
            ex.shutdown(wait=False)  # never block the caller on a hung provider thread

    def record_sensitive_output(self, session_id: str, tool_name: str) -> SessionEvent:
        """Append an observation that `tool_name`'s OUTPUT held secret material.

        The earlier proposed call may have looked harmless (e.g. reading
        notes.txt), so its own event was not labelled sensitive. This event is
        what lets POL-009 block a later send to an unapproved destination.
        artifacts_read names the output, not a path: no raw content is stored."""
        prior = self.ledger.all_events(session_id)
        seq = self.ledger.next_seq(session_id)
        event = SessionEvent(
            session_id=session_id, event_id=self.ledger.make_event_id(session_id, seq), seq=seq,
            timestamp=time.time(), parent_event_ids=[prior[-1].event_id] if prior else [],
            tool_name=tool_name, source_kind="tool_output",
            integrity=IntegrityLabel.UNTRUSTED_EXTERNAL, confidentiality=ConfidentialityLabel.SECRET,
            artifacts_read=["tool_output:" + tool_name], notes=["observed: secret material in tool output"],
            disposition="observed",
        )
        self.ledger.append(event)
        return event

    def check(
        self,
        call: ToolCall,
        *,
        legacy_results: Optional[Dict[str, MinisterResult]] = None,
        parent_event_ids: Optional[List[str]] = None,
        source_kind: Optional[str] = None,
    ) -> Navigator2Verdict:
        legacy_results = legacy_results or {}
        legacy_verdicts = {name: r.verdict for name, r in legacy_results.items()}
        session_id = call.session_id

        contract = self.contract_store.get_or_create(session_id)
        prior_events = self.ledger.all_events(session_id)

        seq = self.ledger.next_seq(session_id)
        event_id = self.ledger.make_event_id(session_id, seq)
        parents = parent_event_ids if parent_event_ids is not None else (
            [prior_events[-1].event_id] if prior_events else []
        )
        history_gap = not self.ledger.check_parents(session_id, parents)

        tag = provenance.compute_label(call, legacy_verdicts)
        reads, writes = _extract_artifacts(call)
        path_confidentiality = _classify_artifact_confidentiality(reads)
        base_confidentiality = tag.confidentiality
        if path_confidentiality is not None:
            base_confidentiality = merge_confidentiality(base_confidentiality, path_confidentiality)
        propagated_confidentiality = self._propagate_confidentiality(base_confidentiality, parents)
        if source_kind is None:
            ctx = call.context or {}
            if isinstance(ctx.get("tool_output"), str) and ctx["tool_output"].strip():
                source_kind = "tool_output"
            elif isinstance(ctx.get("user_instruction"), str) and ctx["user_instruction"].strip():
                source_kind = "user_instruction"
            else:
                source_kind = "unknown"

        destinations = evidence_mod.extract_destinations(call)

        event = SessionEvent(
            session_id=session_id, event_id=event_id, seq=seq, timestamp=time.time(),
            parent_event_ids=parents, tool_name=call.tool_name,
            arg_summary=_summarize_args(call.arguments or {}), source_kind=source_kind,
            integrity=tag.integrity, confidentiality=propagated_confidentiality,
            artifacts_read=reads, artifacts_written=writes, destinations=destinations,
            history_gap=history_gap, legacy_minister_results=dict(legacy_verdicts),
            agent_depth=getattr(call, "agent_depth", 0),
        )

        untrusted_revision_attempted = False
        untrusted_revision_fields: Dict[str, Any] = {}
        candidate_change = _detect_candidate_contract_change(call)
        if candidate_change:
            try:
                contract = self.contract_store.revise(session_id, event, candidate_change)
            except UntrustedRevisionAttempt as e:
                untrusted_revision_attempted = True
                untrusted_revision_fields = e.changed_fields
                contract = self.contract_store.get_or_create(session_id)

        findings = evidence_mod.run_all(call, legacy_results, self.evidence_modules)

        facts = PolicyFacts(
            contract=contract, event=event, recent_events=self.ledger.recent(session_id, self.relevant_event_window),
            evidence=findings, legacy_minister_results=legacy_verdicts, destinations=destinations,
            untrusted_revision_attempted=untrusted_revision_attempted,
            untrusted_revision_fields=untrusted_revision_fields,
            session_history=prior_events,
        )
        policy_decisions = self.policy_engine.evaluate_all(facts)

        reasoner_output = None
        reasoner_invoked = False
        reasoner_timed_out = False
        reasoner_rejected = False
        # This reasoner call is the ONLY place anything resembling "AI
        # reasoning" touches the pipeline, it is OPTIONAL (see _needs_reasoner
        # above -- most calls never reach this line), its default
        # implementation (reasoner.py::DeterministicMockProvider) is a
        # documented rule-based fixture with no network access and no API
        # key, and every failure mode below (timeout, malformed output,
        # fabricated references, a provider that raises or returns garbage)
        # fails toward the SAME escalate-safe path as if the reasoner had
        # never run at all -- see docs/navigator2-report.md's no-LLM
        # architecture section for the full accounting.
        if self._needs_reasoner(contract, policy_decisions, findings):
            reasoner_invoked = True
            request = ReasonerRequest(
                contract=contract, action=event, relevant_events=facts.recent_events, evidence=findings,
                minister_findings=legacy_verdicts,
                applicable_policy_ids=[p.id for p in self.policy_engine.policies],
            )
            try:
                raw_output, reasoner_timed_out = self._call_reasoner(request)
                if reasoner_timed_out:
                    findings.append(EvidenceFinding(
                        module="reasoner_validation", claim=f"reasoner timed out after {self.reasoner_timeout_seconds}s; discarded",
                        confidence=0.0, coverage="indeterminate",
                    ))
                elif raw_output is None:
                    reasoner_rejected = True
                    findings.append(EvidenceFinding(
                        module="reasoner_validation", claim="reasoner provider returned no response; discarded",
                        confidence=0.0, coverage="indeterminate",
                    ))
                elif not isinstance(raw_output, ReasonerResponse):
                    # Defensive: a hostile/buggy provider could return
                    # anything, not just a malformed ReasonerResponse -- a
                    # plain dict, a string, None already handled above. Any
                    # object that isn't actually a ReasonerResponse instance
                    # is rejected, never trusted, never coerced.
                    reasoner_rejected = True
                    findings.append(EvidenceFinding(
                        module="reasoner_validation", claim=f"reasoner returned an unexpected type {type(raw_output).__name__}; discarded",
                        confidence=0.0, coverage="indeterminate",
                    ))
                else:
                    validate_response(request, raw_output)
                    reasoner_output = raw_output
            except ReasonerFabricationError as e:
                reasoner_rejected = True
                reasoner_output = None
                findings.append(EvidenceFinding(
                    module="reasoner_validation", claim=f"reasoner response failed fabrication/schema validation; discarded ({e})",
                    confidence=0.0, coverage="indeterminate",
                ))
            except Exception as e:
                # A reasoner provider must never be trusted to behave -- an
                # arbitrary exception (a hostile/buggy/compromised provider)
                # is handled exactly like an unavailable one, never like a
                # crash of NAVIGATOR 2.0 itself.
                reasoner_rejected = True
                reasoner_output = None
                findings.append(EvidenceFinding(
                    module="reasoner_validation", claim=f"reasoner provider raised {type(e).__name__}; discarded",
                    confidence=0.0, coverage="indeterminate",
                ))

        result = verdict_mod.compose(
            session_id=session_id, event_id=event_id, contract=contract, policy_decisions=policy_decisions,
            reasoner_output=reasoner_output, reasoner_invoked=reasoner_invoked,
            policy_version=getattr(self.policy_engine, "ENGINE_VERSION", PolicyEngine.ENGINE_VERSION),
            reasoner_timed_out=reasoner_timed_out, reasoner_rejected=reasoner_rejected,
            legacy_minister_results=legacy_verdicts, evidence=findings,
        )
        event.disposition = result.disposition
        self.ledger.append(event)
        return result

"""
kavach/coordinator.py
=====================

Receives a proposed tool call or a hook observation, resolves which agent made
it and which security domain (agent tree) it belongs to, runs the ministers,
and hands their results to the Speaker.

Every proposed call goes to all four ministers (no routing, no short-circuit).
Ministers that judge the call on its own run in parallel; a minister that
reads the others' results (it has `check_with_context`, as NAVIGATOR does)
runs after them. Results are always assembled in the fixed minister order, so
the verdict never depends on scheduling. Calls in the same domain are
serialized, so taint and the event ledger follow decision order even when
several agents act at once.

Ministers keep per-session state keyed by `call.session_id`. The coordinator
passes them the domain id (the agent tree's root session) instead of the raw
session id, which is what makes state shared across parent and child agents.

A minister that raises or returns something that is not a well-formed
MinisterResult for its own name is recorded as an ESCALATE result: the
request fails closed and the Speaker never sees a silent ALLOW. Exception
messages are not copied into results or logs (they can echo arguments).
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence, Union

from . import speaker
from .agents import AgentNode, AgentRegistry
from .schemas import (
    CONTENT_EVENTS, MINISTER_NAMES, VERDICTS, Decision, MinisterResult, Observation,
    ObservationDecision, SessionSummary, ToolCall,
)

log = logging.getLogger("kavach.coordinator")

_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="kavach-minister")
_RECENT_DENIALS = 5


class _DomainStats:
    def __init__(self) -> None:
        self.checks = 0
        self.blocked = 0
        self.escalated = 0
        self.secret_observations = 0
        self.recent_denials: Deque[Dict[str, Any]] = deque(maxlen=_RECENT_DENIALS)


class Coordinator:
    def __init__(self, ministers: Sequence[Any], registry: Optional[AgentRegistry] = None):
        names = sorted(m.name for m in ministers)
        if names != sorted(MINISTER_NAMES):
            raise ValueError(f"Coordinator needs exactly {MINISTER_NAMES}, got {names}")
        by_name = {m.name: m for m in ministers}
        self._ministers = [by_name[n] for n in MINISTER_NAMES]  # fixed call order
        self.registry = registry or AgentRegistry()
        self._stats: Dict[str, _DomainStats] = {}
        self._stats_lock = threading.Lock()

    # ---- proposed calls ---------------------------------------------------

    def evaluate(self, call: Union[ToolCall, Mapping[str, Any]]) -> Decision:
        """Raises pydantic.ValidationError on malformed input (a caller error,
        never an ALLOW). Everything after validation fails closed."""
        if not isinstance(call, ToolCall):
            call = ToolCall.model_validate(call)
        node = self.registry.resolve(call.session_id, call.agent_id, call.agent_type)
        domain = self.registry.domain(node)
        scoped = call.model_copy(update={"session_id": domain, "agent_depth": node.depth})

        with self.registry.domain_lock(domain):
            results = self._run_all(scoped)
            sv = speaker.decide(results.values())
            self._record_decision(domain, call.tool_name, sv, results)

        return Decision(
            verdict=sv.verdict,
            reason=sv.reason,
            decided_by=sv.decided_by,
            session_id=call.session_id,
            ministers=results,
            agent_id=call.agent_id,
            domain_id=domain,
            agent_depth=node.depth,
        )

    def _run_all(self, call: ToolCall) -> Dict[str, MinisterResult]:
        independent = [m for m in self._ministers if not callable(getattr(m, "check_with_context", None))]
        dependent = [m for m in self._ministers if m not in independent]
        futures = {m.name: _POOL.submit(self._run, m, call) for m in independent}
        results: Dict[str, MinisterResult] = {name: f.result() for name, f in futures.items()}
        for m in dependent:
            results[m.name] = self._run(m, call, prior_results=results)
        return {n: results[n] for n in MINISTER_NAMES}

    @staticmethod
    def _run(minister: Any, call: ToolCall, prior_results=None) -> MinisterResult:
        try:
            contextual_check = getattr(minister, "check_with_context", None)
            if callable(contextual_check):
                r = contextual_check(call, dict(prior_results or {}))
            else:
                r = minister.check(call)
        except Exception as e:
            log.error("minister %s raised %s; failing closed", minister.name, type(e).__name__)
            return _failure(minister.name, f"raised {type(e).__name__}")
        if not (isinstance(r, MinisterResult) and r.minister == minister.name and r.verdict in VERDICTS):
            log.error("minister %s returned a malformed result; failing closed", minister.name)
            return _failure(minister.name, "returned a malformed result")
        return r

    # ---- observations -----------------------------------------------------

    def observe(self, obs: Union[Observation, Mapping[str, Any]]) -> ObservationDecision:
        """Lifecycle events update the agent tree. Content events go to every
        minister with an observe() method, in fixed order, each seeing earlier
        results; None means nothing to report. Failures are recorded as
        ESCALATE, as in evaluate(). Raises AgentLinkError for an invalid
        parent link."""
        if not isinstance(obs, Observation):
            obs = Observation.model_validate(obs)

        if obs.event == "SessionStart" and obs.parent_session_id:
            self.registry.link_session(obs.session_id, obs.parent_session_id, obs.parent_agent_id)
        node = self.registry.resolve(obs.session_id, obs.agent_id, obs.agent_type)
        if obs.event == "SubagentStop":
            self.registry.stop(obs.session_id, obs.agent_id)
        domain = self.registry.domain(node)

        results: Dict[str, MinisterResult] = {}
        with self.registry.domain_lock(domain):
            if obs.event in CONTENT_EVENTS:
                scoped = obs.model_copy(update={"session_id": domain})
                results = self._observe_all(scoped)
            vault = results.get("VAULT")
            if vault is not None and vault.matched_id and vault.matched_id.startswith("VAULT-CONTENT:"):
                self._stats_for(domain).secret_observations += 1
            summary = self.summary(domain)

        if results:
            sv = speaker.decide(results.values(), required=tuple(results))
        else:
            sv = speaker.SpeakerVerdict("ALLOW", "Speaker", "no minister reported on this observation")
        return ObservationDecision(
            event=obs.event,
            verdict=sv.verdict,
            reason=sv.reason,
            decided_by=sv.decided_by,
            session_id=obs.session_id,
            ministers=results,
            agent_id=obs.agent_id,
            domain_id=domain,
            agent_depth=node.depth,
            summary=summary,
        )

    def _observe_all(self, obs: Observation) -> Dict[str, MinisterResult]:
        results: Dict[str, MinisterResult] = {}
        for m in self._ministers:
            hook = getattr(m, "observe", None)
            if not callable(hook):
                continue
            try:
                r = hook(obs, dict(results))
            except Exception as e:
                log.error("minister %s raised %s while observing; failing closed", m.name, type(e).__name__)
                results[m.name] = _failure(m.name, f"raised {type(e).__name__}")
                continue
            if r is None:
                continue
            if not (isinstance(r, MinisterResult) and r.minister == m.name and r.verdict in VERDICTS):
                log.error("minister %s returned a malformed observation; failing closed", m.name)
                r = _failure(m.name, "returned a malformed result")
            results[m.name] = r
        return results

    # ---- session summary --------------------------------------------------

    def summary(self, domain: str) -> SessionSummary:
        stats = self._stats_for(domain)
        sensitive = False
        for m in self._ministers:
            fn = getattr(m, "summary", None)
            if callable(fn):
                try:
                    sensitive = sensitive or bool(fn(domain).get("holds_sensitive_data"))
                except Exception:
                    # Unknown state is reported as sensitive, never as clean.
                    sensitive = True
        return SessionSummary(
            domain_id=domain,
            agents=self._count_agents(domain),
            checks=stats.checks,
            blocked=stats.blocked,
            escalated=stats.escalated,
            secret_observations=stats.secret_observations,
            holds_sensitive_data=sensitive,
            recent_denials=list(stats.recent_denials),
        )

    def _count_agents(self, domain: str) -> int:
        root = self.registry.resolve(domain)
        pending: List[AgentNode] = [root]
        count = 0
        while pending:
            node = pending.pop()
            count += 1
            pending.extend(self.registry.children(node))
        return count

    def _stats_for(self, domain: str) -> _DomainStats:
        with self._stats_lock:
            return self._stats.setdefault(domain, _DomainStats())

    def _record_decision(self, domain: str, tool_name: str, sv: Any, results: Dict[str, MinisterResult]) -> None:
        stats = self._stats_for(domain)
        stats.checks += 1
        if sv.verdict == "ALLOW":
            return
        if sv.verdict == "BLOCK":
            stats.blocked += 1
        else:
            stats.escalated += 1
        rules = [r.matched_id for r in results.values() if r.verdict != "ALLOW" and r.matched_id]
        stats.recent_denials.append({
            "tool": tool_name[:128], "verdict": sv.verdict, "decided_by": sv.decided_by, "rules": rules[:6],
        })


def _failure(name: str, why: str) -> MinisterResult:
    return MinisterResult(
        minister=name,
        verdict="ESCALATE",
        reason=f"{name} unavailable ({why}); failing closed",
        matched_id=f"{name}-FAILURE",
        diagnostics={"failed": True},
    )

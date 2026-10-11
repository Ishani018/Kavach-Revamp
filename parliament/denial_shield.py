"""
denial_shield.py — Kavach Denial-Feedback Protection (PATCHED)

PATCH NOTES (vs v1):
  - Timing: constant-time BUDGET, not just a floor; over-budget work is
    flagged so latency never leaks BLOCK vs ALLOW                     [ISSUE 5]
  - Async-safe: pad() is async (await asyncio.sleep); sync variant kept [ISSUE 6]
  - Probe identity keyed on a stable principal (auth/agent id), not a
    client-rotatable session id                                       [ISSUE 7]
  - Escalation decays after a cooldown window                         [ISSUE 8]

Drop into parliament/denial_shield.py
"""

import time
import asyncio
import hashlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

OPAQUE_BLOCK_MESSAGE = "Action could not be completed."
ALLOW_MESSAGE = "Action completed."

# ISSUE 5: constant-time budget. EVERY response consumes exactly this much
# wall time as seen by the agent. If real work exceeds it, we cannot hide
# the overflow, so we flag it for the ledger (never expose to the agent).
RESPONSE_BUDGET_SECONDS = 1.2

PROBE_WINDOW_SIZE = 20
ABSTAIN_RATIO_THRESHOLD = 0.4
CONSECUTIVE_BLOCK_THRESHOLD = 5
PROBE_ESCALATION_THRESHOLD = 3

# ISSUE 8: how long an escalation lasts before automatic de-escalation.
ESCALATION_COOLDOWN_SECONDS = 300  # 5 minutes


@dataclass
class ShieldedResponse:
    allowed: bool
    message: str
    response_time: float
    probe_flagged: bool
    principal: str
    budget_exceeded: bool = False


@dataclass
class PrincipalState:
    principal: str
    decisions: deque = field(default_factory=lambda: deque(maxlen=PROBE_WINDOW_SIZE))
    probe_flag_count: int = 0
    escalated_until: float = 0.0   # epoch seconds; 0 = not escalated
    created_at: float = field(default_factory=time.time)


def derive_principal(session_id, auth_token=None, agent_id=None, source_ip=None):
    """
    ISSUE 7: build a stable identity the attacker can't trivially rotate.
    Prefer auth token / agent id over the client-supplied session id.
    Hashed so the ledger never stores raw tokens.
    """
    basis = auth_token or agent_id or source_ip or session_id or "unknown"
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


class ProbeDetector:
    def __init__(self):
        self.principals: dict = {}

    def _get(self, principal: str) -> PrincipalState:
        if principal not in self.principals:
            self.principals[principal] = PrincipalState(principal=principal)
        return self.principals[principal]

    def record(self, principal: str, decision: str, abstain_ratio: float) -> bool:
        st = self._get(principal)
        st.decisions.append({"decision": decision, "abstain_ratio": abstain_ratio,
                             "timestamp": time.time()})
        flagged = False

        ratios = [d["abstain_ratio"] for d in st.decisions]
        if ratios and (sum(ratios) / len(ratios)) >= ABSTAIN_RATIO_THRESHOLD:
            flagged = True

        consec = 0
        for d in reversed([d["decision"] for d in st.decisions]):
            if d == "BLOCK":
                consec += 1
            else:
                break
        if consec >= CONSECUTIVE_BLOCK_THRESHOLD:
            flagged = True

        now = time.time()
        recent = [d for d in st.decisions if now - d["timestamp"] < 30]
        if len(recent) >= 10:
            flagged = True

        if flagged:
            st.probe_flag_count += 1
            if st.probe_flag_count >= PROBE_ESCALATION_THRESHOLD:
                # ISSUE 8: escalate for a bounded cooldown, not forever
                st.escalated_until = now + ESCALATION_COOLDOWN_SECONDS
        return flagged

    def is_escalated(self, principal: str) -> bool:
        st = self.principals.get(principal)
        if not st:
            return False
        if st.escalated_until and time.time() < st.escalated_until:
            return True
        # cooldown expired -> auto de-escalate and reset the flag counter
        if st.escalated_until and time.time() >= st.escalated_until:
            st.escalated_until = 0.0
            st.probe_flag_count = 0
        return False

    def reset(self, principal: str):
        self.principals.pop(principal, None)


class DenialShield:
    def __init__(self):
        self.probe_detector = ProbeDetector()

    def _finalize_timing(self, start_time: float):
        """
        ISSUE 5/6 sync version: sleep up to the budget. Returns
        (elapsed, budget_exceeded). budget_exceeded is internal only.
        """
        elapsed = time.time() - start_time
        remaining = RESPONSE_BUDGET_SECONDS - elapsed
        if remaining > 0:
            time.sleep(remaining)
            return RESPONSE_BUDGET_SECONDS, False
        return elapsed, True  # overran budget — timing may leak; flagged

    async def _finalize_timing_async(self, start_time: float):
        # ISSUE 6: async-safe variant for FastAPI
        elapsed = time.time() - start_time
        remaining = RESPONSE_BUDGET_SECONDS - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)
            return RESPONSE_BUDGET_SECONDS, False
        return elapsed, True

    def _decide(self, principal, speaker_decision, abstain_count, total_votes):
        decision = speaker_decision.decision
        if self.probe_detector.is_escalated(principal):
            decision = "BLOCK"
        abstain_ratio = abstain_count / max(total_votes, 1)
        probe_flagged = self.probe_detector.record(principal, decision, abstain_ratio)
        if self.probe_detector.is_escalated(principal):
            decision = "BLOCK"
        return decision, probe_flagged

    def apply(self, session_id, speaker_decision, abstain_count, total_votes,
              start_time, auth_token=None, agent_id=None, source_ip=None,
              ledger_writer=None):
        principal = derive_principal(session_id, auth_token, agent_id, source_ip)
        decision, probe_flagged = self._decide(principal, speaker_decision,
                                               abstain_count, total_votes)
        elapsed, exceeded = self._finalize_timing(start_time)
        return self._build(principal, decision, probe_flagged, elapsed, exceeded,
                           abstain_count, total_votes, ledger_writer)

    async def apply_async(self, session_id, speaker_decision, abstain_count,
                          total_votes, start_time, auth_token=None, agent_id=None,
                          source_ip=None, ledger_writer=None):
        principal = derive_principal(session_id, auth_token, agent_id, source_ip)
        decision, probe_flagged = self._decide(principal, speaker_decision,
                                               abstain_count, total_votes)
        elapsed, exceeded = await self._finalize_timing_async(start_time)
        return self._build(principal, decision, probe_flagged, elapsed, exceeded,
                           abstain_count, total_votes, ledger_writer)

    def _build(self, principal, decision, probe_flagged, elapsed, exceeded,
               abstain_count, total_votes, ledger_writer):
        allowed = decision == "ALLOW"
        message = ALLOW_MESSAGE if allowed else OPAQUE_BLOCK_MESSAGE
        resp = ShieldedResponse(allowed, message, elapsed, probe_flagged,
                                principal, budget_exceeded=exceeded)
        if ledger_writer:
            ledger_writer({
                "type": "denial_shield",
                "principal": principal,
                "decision": decision,
                "allowed": allowed,
                "probe_flagged": probe_flagged,
                "escalated": self.probe_detector.is_escalated(principal),
                "abstain_ratio": round(abstain_count / max(total_votes, 1), 4),
                "response_time": round(elapsed, 4),
                "budget_exceeded": exceeded,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        return resp

    def end_session(self, session_id, auth_token=None, agent_id=None, source_ip=None):
        principal = derive_principal(session_id, auth_token, agent_id, source_ip)
        self.probe_detector.reset(principal)


if __name__ == "__main__":
    shield = DenialShield()
    print("=== Denial Shield (patched) ===\n")

    class D:
        decision = "BLOCK"

    print("Test 1: BLOCK is opaque + budget-timed")
    t = time.time()
    r = shield.apply("sess1", D(), abstain_count=1, total_votes=4, start_time=t,
                     auth_token="tokenA")
    print(f"  allowed={r.allowed} msg='{r.message}' t={r.response_time:.3f}s "
          f"exceeded={r.budget_exceeded}\n")

    print("Test 2: session_id rotation does NOT reset probe counter (ISSUE 7)")
    for i in range(6):
        t = time.time()
        D.decision = "BLOCK"
        # attacker rotates session_id every call but auth_token is stable
        r = shield.apply(f"rotate_{i}", D(), 2, 4, t, auth_token="attacker1")
    esc = shield.probe_detector.is_escalated(derive_principal("x", "attacker1"))
    print(f"  After 6 rotated sessions, escalated={esc} (should be True)\n")

    print("Test 3: ALLOW padded to same budget as BLOCK (ISSUE 5)")
    t = time.time()
    D.decision = "ALLOW"
    r = shield.apply("sess3", D(), 0, 4, t, auth_token="userZ")
    print(f"  allowed={r.allowed} t={r.response_time:.3f}s (~{RESPONSE_BUDGET_SECONDS}s)\n")

    print("Test 4: escalation triggers then decays (ISSUE 8)")
    # Use a fresh shield; manually shorten this principal's cooldown window
    shield4 = DenialShield()
    D.decision = "BLOCK"
    p = derive_principal("x", auth_token="decayer")
    for i in range(6):
        shield4.apply(f"d_{i}", D(), 2, 4, time.time(), auth_token="decayer")
    print(f"  escalated now={shield4.probe_detector.is_escalated(p)} (want True)")
    # Force the cooldown to have already expired for this principal
    shield4.probe_detector.principals[p].escalated_until = time.time() - 1
    print(f"  escalated after cooldown={shield4.probe_detector.is_escalated(p)} (want False)")

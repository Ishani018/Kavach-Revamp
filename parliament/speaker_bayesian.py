"""
speaker.py — Kavach Bayesian Speaker (PATCHED)
Aggregates Minister votes using Bayesian inference with a correlation
penalty to avoid overconfidence from correlated Ministers.

PATCH NOTES (vs v1):
  - ABSTAIN now truly neutral (no dead knob)              [ISSUE 1]
  - Correlation penalty applied, NOT naive multiplication [ISSUE 2]
  - Prior from ground-truth-labelled ledger entries only  [ISSUE 4]
  - Reliability update is OFFLINE only; runtime never fabricates truth [ISSUE 3]
  - calibration_warning surfaced until reliability is calibrated

Drop-in replacement for parliament/speaker.py
"""

import json
import os
import math
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

MINISTERS = ["EXECUTOR", "VAULT", "CHANNEL", "NAVIGATOR"]
DECISIONS = ["ALLOW", "BLOCK"]

DEFAULT_PRIOR_BLOCK = 0.3
DEFAULT_RELIABILITY = 0.7  # ISSUE: 0.5 = pure noise, votes carry zero info; 0.7 = informative prior
BLOCK_THRESHOLD = 0.55

# ISSUE 2: Ministers are NOT independent. Dampen evidence from N correlated
# votes by raising likelihoods to exponent = 1/(1+(N-1)*rho).
# Measure rho on the Dell; until then default conservative 0.5.
CORRELATION_RHO = float(os.environ.get("KAVACH_CORRELATION_RHO", "0.3"))

RELIABILITY_STORE_PATH = os.environ.get(
    "KAVACH_RELIABILITY_STORE",
    os.path.join(os.path.dirname(__file__), "minister_reliability.json"))
LEDGER_PATH = os.environ.get(
    "KAVACH_LEDGER_PATH",
    os.path.join(os.path.dirname(__file__), "..", "kavach_ledger.jsonl"))


@dataclass
class MinisterVote:
    minister: str
    vote: str
    confidence: float
    reason: str = ""


@dataclass
class SpeakerDecision:
    decision: str
    confidence: float
    posterior_block: float
    posterior_allow: float
    minister_weights: dict
    reasoning: str
    calibration_warning: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReliabilityStore:
    def __init__(self, path: str = RELIABILITY_STORE_PATH):
        self.path = path
        self.reliability: dict = {}
        self.count: dict = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                data = json.load(f)
                self.reliability = data.get("reliability", {})
                self.count = data.get("count", {})
        for m in MINISTERS:
            self.reliability.setdefault(m, {})
            self.count.setdefault(m, {})
            for v in DECISIONS + ["ABSTAIN"]:
                self.reliability[m].setdefault(v, DEFAULT_RELIABILITY)
                self.count[m].setdefault(v, 0)

    def save(self):
        with open(self.path, "w") as f:
            json.dump({"reliability": self.reliability, "count": self.count}, f, indent=2)

    def get(self, minister: str, vote_type: str) -> float:
        return self.reliability.get(minister, {}).get(vote_type, DEFAULT_RELIABILITY)

    def total_observations(self) -> int:
        return sum(self.count[m][v] for m in MINISTERS for v in DECISIONS)

    def update(self, minister: str, vote_type: str, was_correct: bool):
        # OFFLINE ONLY — verified ground truth required. Never called at inference.
        n = self.count[minister][vote_type]
        old = self.reliability[minister][vote_type]
        self.reliability[minister][vote_type] = (old * n + float(was_correct)) / (n + 1)
        self.count[minister][vote_type] = n + 1
        self.save()


class BayesianSpeaker:
    def __init__(self, store: Optional[ReliabilityStore] = None,
                 rho: Optional[float] = None):
        self.store = store or ReliabilityStore()
        self.prior_block = self._compute_prior_from_labelled_ledger()
        self._calibrated = self.store.total_observations() >= 50
        # Per-instance correlation discount. When None, fall back to the module
        # global CORRELATION_RHO. Set explicitly so multiple speakers with
        # different rho can coexist WITHOUT importlib.reload (which corrupts
        # other live instances).
        self.rho = CORRELATION_RHO if rho is None else float(rho)

    def _compute_prior_from_labelled_ledger(self) -> float:
        # ISSUE 4: only use ground-truth-labelled entries; never self-decisions.
        if not os.path.exists(LEDGER_PATH):
            return DEFAULT_PRIOR_BLOCK
        total, blocks = 0, 0
        try:
            with open(LEDGER_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    gt = entry.get("ground_truth")
                    if gt in DECISIONS:
                        total += 1
                        if gt == "BLOCK":
                            blocks += 1
        except Exception:
            return DEFAULT_PRIOR_BLOCK
        if total < 10:
            return DEFAULT_PRIOR_BLOCK
        alpha = min(total / 100.0, 1.0)
        return alpha * (blocks / total) + (1 - alpha) * DEFAULT_PRIOR_BLOCK

    def _correlation_exponent(self, n_votes: int) -> float:
        if n_votes <= 1:
            return 1.0
        return 1.0 / (1.0 + (n_votes - 1) * self.rho)

    @staticmethod
    def _normalize_vote(vote: str) -> str:
        # The live parliament emits a three-way verdict {ALLOW, ESCALATE, BLOCK},
        # but the Bayesian aggregator reasons over the binary {ALLOW, BLOCK}.
        # ESCALATE is a grey-zone flag — a minister saw something near, but below,
        # its block threshold. It is NOT a definitive block, so we fold it into
        # ALLOW: a grey-zone vote contributes non-blocking evidence and never, on
        # its own, pushes the posterior toward BLOCK. This is the conservative
        # (no-over-block) reading and keeps offline §5 replay from crashing on the
        # ESCALATE votes that real minister_runs.jsonl dumps contain.
        return "ALLOW" if vote == "ESCALATE" else vote

    def _likelihood(self, vote: MinisterVote, candidate_decision: str) -> float:
        # ISSUE 1: ABSTAIN is exactly neutral (1.0 for both -> cancels).
        if vote.vote == "ABSTAIN":
            return 1.0
        vote_value = self._normalize_vote(vote.vote)
        # Validate vote value — unknown strings must not silently skew results
        if vote_value not in DECISIONS:
            raise ValueError(f"Invalid vote '{vote.vote}' from {vote.minister}; "
                             f"expected one of {DECISIONS + ['ESCALATE', 'ABSTAIN']}")
        r = self.store.get(vote.minister, vote_value)
        c = vote.confidence
        # NaN/inf guard: math.isfinite catches both; comparisons with NaN are
        # always False so the plain clamp below would let NaN through.
        if not (isinstance(c, (int, float)) and math.isfinite(c)):
            raise ValueError(f"Non-finite confidence {c!r} from {vote.minister}")
        c = max(0.01, min(0.99, c))
        if vote_value == candidate_decision:
            return c * r + (1 - c) * (1 - r)
        return (1 - c) * r + c * (1 - r)

    def aggregate(self, votes: list) -> SpeakerDecision:
        # Deduplicate by minister — one minister must not count as N evidence.
        # Keep the highest-confidence vote per minister (deterministic).
        seen = {}
        for v in votes:
            if v.minister not in seen or v.confidence > seen[v.minister].confidence:
                seen[v.minister] = v
        if len(seen) < len(votes):
            votes = list(seen.values())
        prior_block = self.prior_block
        prior_allow = 1.0 - prior_block
        active = [v for v in votes if v.vote != "ABSTAIN"]
        exponent = self._correlation_exponent(len(active))

        log_block = math.log(prior_block)
        log_allow = math.log(prior_allow)
        for vote in votes:
            lb = self._likelihood(vote, "BLOCK")
            la = self._likelihood(vote, "ALLOW")
            log_block += exponent * math.log(max(lb, 1e-9))
            log_allow += exponent * math.log(max(la, 1e-9))

        m = max(log_block, log_allow)
        sb = math.exp(log_block - m)
        sa = math.exp(log_allow - m)
        total = sb + sa
        post_block = sb / total
        post_allow = sa / total

        if post_block >= BLOCK_THRESHOLD:
            decision, confidence = "BLOCK", post_block
        else:
            decision, confidence = "ALLOW", post_allow

        minister_weights = {v.minister: round(self._likelihood(v, decision), 4) for v in votes}
        vote_summary = ", ".join(f"{v.minister}={v.vote}({v.confidence:.2f})" for v in votes)
        warn = "" if self._calibrated else " [UNCALIBRATED - confidence not yet trustworthy]"
        reasoning = (f"Bayesian (rho={self.rho}, exp={exponent:.3f}) over "
                     f"[{vote_summary}]. P(BLOCK)={post_block:.3f}, P(ALLOW)={post_allow:.3f}, "
                     f"prior(BLOCK)={prior_block:.3f}. Decision: {decision} conf={confidence:.3f}.{warn}")

        return SpeakerDecision(decision, round(confidence, 4), round(post_block, 4),
                               round(post_allow, 4), minister_weights, reasoning,
                               calibration_warning=not self._calibrated)

    def update_reliability(self, votes: list, correct_decision: str):
        # OFFLINE ONLY. Eval harness with verified labels.
        for vote in votes:
            if vote.vote != "ABSTAIN":
                self.store.update(vote.minister, vote.vote, vote.vote == correct_decision)
        self._calibrated = self.store.total_observations() >= 50


def decision_to_ledger_entry(action_id, action, votes, speaker_decision, prev_hash,
                             ground_truth=None):
    entry = {
        "action_id": action_id,
        "timestamp": speaker_decision.timestamp,
        "action": action,
        "minister_votes": [{"minister": v.minister, "vote": v.vote,
                            "confidence": v.confidence, "reason": v.reason} for v in votes],
        "speaker_decision": {
            "decision": speaker_decision.decision,
            "confidence": speaker_decision.confidence,
            "posterior_block": speaker_decision.posterior_block,
            "posterior_allow": speaker_decision.posterior_allow,
            "minister_weights": speaker_decision.minister_weights,
            "calibration_warning": speaker_decision.calibration_warning,
            "reasoning": speaker_decision.reasoning,
        },
        "prev_hash": prev_hash,
    }
    if ground_truth is not None:
        entry["ground_truth"] = ground_truth
    return entry


if __name__ == "__main__":
    speaker = BayesianSpeaker()
    print("=== Bayesian Speaker (patched) ===")
    print(f"Calibrated: {speaker._calibrated} | rho={CORRELATION_RHO}\n")

    votes = [
        MinisterVote("EXECUTOR", "BLOCK", 0.91, "Exfiltration pattern"),
        MinisterVote("VAULT",    "BLOCK", 0.87, "Credential access"),
        MinisterVote("CHANNEL",  "ABSTAIN", 0.50, "Insufficient context"),
        MinisterVote("NAVIGATOR","BLOCK", 0.78, "Intent drift"),
    ]
    r = speaker.aggregate(votes)
    print("Suspicious action:")
    print(f"  {r.decision} conf={r.confidence} P(BLOCK)={r.posterior_block} warn={r.calibration_warning}")
    print(f"  {r.reasoning}\n")

    votes2 = [
        MinisterVote("EXECUTOR", "ALLOW",  0.82, "Normal read"),
        MinisterVote("VAULT",    "ALLOW",  0.75, "No cred access"),
        MinisterVote("CHANNEL",  "BLOCK",  0.51, "Slight anomaly"),
        MinisterVote("NAVIGATOR","ALLOW",  0.88, "Intent aligned"),
    ]
    r2 = speaker.aggregate(votes2)
    print("Benign action:")
    print(f"  {r2.decision} conf={r2.confidence} P(BLOCK)={r2.posterior_block} warn={r2.calibration_warning}\n")

    print("Correlation penalty (4 votes):")
    for rho in [0.0, 0.5, 1.0]:
        n = 4
        exp = 1.0 if n <= 1 else 1.0 / (1.0 + (n - 1) * rho)
        label = "independent" if rho == 0 else ("fully correlated" if rho == 1 else "partial")
        print(f"  rho={rho}: evidence exponent={exp:.3f} ({label})")

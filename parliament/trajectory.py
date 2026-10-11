"""
parliament/trajectory.py
========================

Session-level trajectory monitor for Kavach.

The four ministers score each tool call in isolation. This module adds the
missing layer: it watches the *sequence* of calls in a session and detects
multi-step attacks where each individual call looks benign but the chain is
malicious (read credential -> search for tokens -> POST to external URL).

DESIGN CONSTRAINT — NO RE-EMBEDDING.
    Every action is already embedded once in the parliament endpoint (the
    embed-once refactor). We reuse that vector here. This module performs ONLY
    cosine math over cached 768-dim vectors — no SentenceTransformer / BGE
    calls, no ChromaDB queries. Per-call cost is sub-millisecond, so the hook
    latency budget (p95 ~1.6s, timeout 3000ms) is untouched.

FIVE SIGNALS (each in [0, 1]):
    1. accumulation    — decayed sum of recent per-call confidences (PRISM-parity
                         baseline; recent borderline/block calls raise risk).
    2. escalation      — is the session drifting monotonically AWAY from the
                         seeded user intent? Needs an intent vector; degrades
                         gracefully to 0.0 when intent is unseeded (FINDINGS #9).
    3. chain           — pairwise coherence of flagged actions + sequential
                         direction tracking (motivated by Trajectory Guard
                         arXiv:2601.00516 which proves mean-pooling alone
                         achieves F1 ≤ 0.69).
    4. denial_echo     — does the current action semantically echo a call that
                         was previously BLOCKED in this session? Catches
                         causality laundering (ARM, arXiv:2604.04035): attacker
                         probes a protected action, learns from the denial, and
                         re-approaches via a reformulated but semantically
                         identical call.
    5. minister_esc    — cross-minister escalation: does the sequence of which
                         minister fired follow a canonical attack pattern?
                         (AgentDoG arXiv:2601.18491 taxonomy: source → consequence)
                         e.g. VAULT → CHANNEL = credential read → exfiltration.

Combined risk feeds the dynamic-threshold formula AND the hard session ceiling:
    effective_threshold = base + (compass_sim - 0.5)*drift_factor - risk*k
    if risk >= TRAJ_BLOCK_CEILING → BLOCK regardless of minister scores

Author: Kavach team (Chain of Trust, PES University 2026)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, List, Optional

import numpy as np


# ──────────────────────────────────────────────────────────────────────────────
# Tunables (mirror into config.yaml -> trajectory: when wiring server.py)
# ──────────────────────────────────────────────────────────────────────────────

WINDOW_SIZE: int = 12           # max actions retained per session
DECAY_HALFLIFE: float = 4.0     # accumulation: weight halves every 4 calls
GREY_FLOOR: float = 0.50        # confidence floor for "flagged" (chain-relevant)
CHAIN_COHERENCE_MIN: int = 2    # minimum flagged actions to compute chain signal
DIRECTION_THRESHOLD: float = 0.50  # consecutive cosine above which direction fires
DENIAL_ECHO_THRESHOLD: float = 0.68  # cosine above which current echoes a denial

# Hard session ceiling — if combined risk >= this, BLOCK regardless of ministers.
# Motivated by the independent enforcement gap vs PRISM's scalar graduated blocks.
#
# Empirically calibrated (benchmarks/traj_distribution.py, 2026-06-11): across 10
# benign and 10 attack multi-step sessions, benign peak traj_risk maxed at 0.497
# (mean 0.419) and attack peak risk averaged 0.524 (mean), with clean separation
# at 0.50 — i.e. 0.50 sits just above the observed benign session peak. The prior
# 0.72 was never reached by any session (benign or attack) and so never fired.
# Modulating this by COMPASS drift is a natural extension (see §7) but needs
# drift-seeded calibration data; left to future work.
TRAJ_BLOCK_CEILING: float = 0.50

# Canonical cross-minister attack patterns (AgentDoG source→consequence taxonomy).
# Each entry is an ordered subsequence of decided_by values to match in the window.
MINISTER_ESCALATION_PATTERNS: List[List[str]] = [
    ["VAULT", "CHANNEL"],       # credential read → exfiltration (most common)
    ["EXECUTOR", "CHANNEL"],    # command execution → exfiltration
    ["VAULT", "EXECUTOR"],      # credential read → RCE (privilege escalation)
    ["NAVIGATOR", "CHANNEL"],   # memory/context access → exfiltration
    ["VAULT", "NAVIGATOR", "CHANNEL"],  # full cred→context→exfil chain
]
MINISTER_PATTERN_SCORE: float = 0.82   # risk signal on pattern match

# Combined-risk weights — sum need not be 1; risk is clamped to [0,1] at end.
W_ACCUMULATION: float = 0.35
W_ESCALATION:   float = 0.25
W_CHAIN:        float = 0.40   # covers chain + denial_echo + minister_esc (max)


# ──────────────────────────────────────────────────────────────────────────────
# Records & result types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ActionRecord:
    ts:         str
    action_vec: np.ndarray   # L2-normalized BGE vector reused from the scan
    verdict:    str          # "BLOCK" | "ESCALATE" | "ALLOW"
    confidence: float        # max minister cosine for this call
    decided_by: str
    is_denial:  bool = False  # True when this call was BLOCKED — enables denial echo


@dataclass
class TrajectoryResult:
    risk:         float    # combined session risk in [0, 1]
    accumulation: float    # leg 1
    escalation:   float    # leg 2 (0.0 if intent unseeded)
    chain:        float    # leg 3a+3b: pairwise coherence + sequential direction
    denial_echo:  float    # leg 4: echo of a previously blocked action
    minister_esc: float    # leg 5: cross-minister escalation pattern
    window_size:  int
    intent_used:  bool
    ceiling_breach: bool   # True if risk >= TRAJ_BLOCK_CEILING
    reason:       str


# ──────────────────────────────────────────────────────────────────────────────
# Per-session history store
# ──────────────────────────────────────────────────────────────────────────────

def new_history() -> Deque[ActionRecord]:
    """Factory for a fresh per-session deque (use via defaultdict in _state)."""
    return deque(maxlen=WINDOW_SIZE)


def record_action(
    history: Deque[ActionRecord],
    action_vec: np.ndarray,
    verdict: str,
    confidence: float,
    decided_by: str,
    is_denial: bool = False,
) -> None:
    """Append one scored action. `action_vec` MUST be the already-computed,
    L2-normalized BGE vector from the parliament scan — never re-embedded here.
    Pass is_denial=True when the verdict was BLOCK, so future calls can detect
    denial echo (causality laundering)."""
    history.append(
        ActionRecord(
            ts=datetime.now(timezone.utc).isoformat(),
            action_vec=np.asarray(action_vec, dtype=np.float32),
            verdict=verdict,
            confidence=float(confidence),
            decided_by=decided_by,
            is_denial=is_denial,
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# Math helpers (vectors are L2-normalized upstream, so dot == cosine)
# ──────────────────────────────────────────────────────────────────────────────

def _cos(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.clip(np.dot(a, b), -1.0, 1.0))


def _decay_weights(n: int) -> np.ndarray:
    if n == 0:
        return np.zeros(0, dtype=np.float32)
    ages = np.arange(n - 1, -1, -1, dtype=np.float32)
    return np.power(0.5, ages / DECAY_HALFLIFE).astype(np.float32)


# ──────────────────────────────────────────────────────────────────────────────
# Signal 1 — accumulation (PRISM-parity baseline)
# ──────────────────────────────────────────────────────────────────────────────

def _accumulation(history: Deque[ActionRecord]) -> float:
    """Decayed accumulation of per-call confidence, measured RELATIVE to the
    session's own baseline (scale-invariant redesign, 2026-06-13).

    Why relative: the previous version returned the decayed *absolute* average of
    minister confidences. That quantity has no fixed scale across deployments —
    on the Dell (Gemma 4 26B) ordinary benign coding actions sit at cosine ~0.6
    against the corpus, vs ~0.4 on the laptop, so benign sessions accumulated to
    ~0.62 and tripped a 0.50 ceiling (100% benign FPR), while the same ceiling
    blocked nothing on the laptop. The signal was tracking the config's
    confidence floor, not attack behavior.

    Fix: subtract a per-session baseline (the lowest non-zero confidence seen in
    the window — the session's own "what benign looks like here") and normalize
    by the headroom above it. A session that stays flat at its baseline scores
    ~0; only confidence that RISES above the session's own floor accumulates
    risk. This is invariant to the absolute confidence scale of the backbone.
    """
    n = len(history)
    if n == 0:
        return 0.0
    confs = np.array([r.confidence for r in history], dtype=np.float32)
    w = _decay_weights(n)
    denom = float(w.sum())
    if denom <= 0.0:
        return 0.0
    # Session baseline: the floor of observed confidence (robust to a single
    # high call). With <2 calls there is no trend yet, so risk is 0.
    if n < 2:
        return 0.0
    baseline = float(np.min(confs))
    # Headroom from baseline up to the BLOCK-certainty region (1.0). Excess
    # confidence above baseline, decayed-averaged and normalized by headroom.
    headroom = max(1.0 - baseline, 1e-3)
    excess = np.clip(confs - baseline, 0.0, None)
    return float(np.clip((excess * w).sum() / denom / headroom, 0.0, 1.0))


# ──────────────────────────────────────────────────────────────────────────────
# Signal 2 — escalation / intent drift
# ──────────────────────────────────────────────────────────────────────────────

def _escalation(history: Deque[ActionRecord], intent_vec: Optional[np.ndarray]) -> float:
    if intent_vec is None:
        return 0.0
    n = len(history)
    if n < 2:
        return 0.0
    iv = np.asarray(intent_vec, dtype=np.float32)
    align = np.array([_cos(iv, r.action_vec) for r in history], dtype=np.float32)
    x = np.arange(n, dtype=np.float32)
    x -= x.mean()
    var = float((x * x).sum())
    if var <= 0.0:
        return 0.0
    slope = float((x * (align - align.mean())).sum() / var)
    return float(np.clip(-slope, 0.0, 1.0))


# ──────────────────────────────────────────────────────────────────────────────
# Signal 3 — semantic chain (pairwise coherence + sequential direction)
#
# Pairwise coherence: do flagged actions cluster in embedding space?
# Sequential direction: are CONSECUTIVE flagged actions moving in a consistent
#   direction? Motivated by Trajectory Guard (arXiv:2601.00516) which shows
#   mean-pooling centroid misses directional attack chains (F1 ceiling 0.69).
# ──────────────────────────────────────────────────────────────────────────────

def _chain(
    history: Deque[ActionRecord],
    prototypes: Optional[np.ndarray] = None,
) -> float:
    flagged_records = [r for r in history if r.confidence >= GREY_FLOOR]
    if len(flagged_records) < CHAIN_COHERENCE_MIN:
        return 0.0

    vecs = [r.action_vec for r in flagged_records]
    M = np.vstack(vecs).astype(np.float32)   # (k, dim)
    k = M.shape[0]

    # (a) pairwise coherence — mean of upper-triangle cosines
    sims = M @ M.T
    iu = np.triu_indices(k, k=1)
    coherence = float(np.clip(sims[iu].mean(), 0.0, 1.0)) if iu[0].size else 0.0

    # (b) sequential direction — consecutive cosines in the ORDER they appeared
    # High mean consecutive cosine = attack moving in a coherent direction step-by-step
    if k >= 2:
        consec = [_cos(vecs[i], vecs[i + 1]) for i in range(k - 1)]
        direction = float(np.clip(np.mean(consec), 0.0, 1.0))
        # Amplify when consecutive cosines are consistently above the threshold
        consistent = sum(1 for c in consec if c >= DIRECTION_THRESHOLD) / len(consec)
        direction = direction * (0.5 + 0.5 * consistent)
    else:
        direction = 0.0

    # (c) prototype match against flagged centroid (optional, strengthens with corpus)
    proto = 0.0
    if prototypes is not None and len(prototypes) > 0:
        centroid = M.mean(axis=0)
        norm = float(np.linalg.norm(centroid))
        if norm > 0.0:
            centroid = centroid / norm
            proto = float(np.clip((prototypes @ centroid).max(), 0.0, 1.0))

    return float(np.clip(max(coherence, direction, proto), 0.0, 1.0))


# ──────────────────────────────────────────────────────────────────────────────
# Signal 4 — denial echo (ARM arXiv:2604.04035)
#
# If the current action semantically echoes a previously BLOCKED action, the
# attacker is attempting causality laundering — reformulating the same intent
# to bypass the prior block. Fires when cosine(current, denied) > threshold.
# ──────────────────────────────────────────────────────────────────────────────

def _denial_echo(
    history: Deque[ActionRecord],
    current_vec: Optional[np.ndarray],
) -> float:
    if current_vec is None:
        return 0.0
    denials = [r for r in history if r.is_denial]
    if not denials:
        return 0.0
    cv = np.asarray(current_vec, dtype=np.float32)
    max_sim = max(_cos(cv, r.action_vec) for r in denials)
    if max_sim < DENIAL_ECHO_THRESHOLD:
        return 0.0
    # Scale: how far above the threshold is it?
    return float(np.clip(
        (max_sim - DENIAL_ECHO_THRESHOLD) / (1.0 - DENIAL_ECHO_THRESHOLD),
        0.0, 1.0
    ))


# ──────────────────────────────────────────────────────────────────────────────
# Signal 5 — cross-minister escalation (AgentDoG arXiv:2601.18491)
#
# Scans the decided_by sequence for canonical source→consequence attack patterns.
# VAULT → CHANNEL = credential read → exfiltration is the most dangerous.
# Returns MINISTER_PATTERN_SCORE if any pattern is found, else 0.0.
# ──────────────────────────────────────────────────────────────────────────────

def _minister_escalation(history: Deque[ActionRecord]) -> float:
    if len(history) < 2:
        return 0.0
    sequence = [r.decided_by for r in history]
    for pattern in MINISTER_ESCALATION_PATTERNS:
        # Check if pattern appears as a subsequence (not necessarily contiguous)
        p_idx = 0
        for minister in sequence:
            if minister == pattern[p_idx]:
                p_idx += 1
                if p_idx == len(pattern):
                    return MINISTER_PATTERN_SCORE
    return 0.0


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def trajectory_risk(
    history: Deque[ActionRecord],
    intent_vec: Optional[np.ndarray] = None,
    current_vec: Optional[np.ndarray] = None,
    prototypes: Optional[np.ndarray] = None,
) -> TrajectoryResult:
    """Compute the combined session trajectory risk. Pure cosine math over
    cached vectors; safe to call on the hot path.

    current_vec: the BGE vector of the action being evaluated RIGHT NOW
                 (not yet in history). Used for denial echo detection.
    """
    acc  = _accumulation(history)
    esc  = _escalation(history, intent_vec)
    chn  = _chain(history, prototypes)
    den  = _denial_echo(history, current_vec)
    mesc = _minister_escalation(history)

    # Chain component takes the strongest novel signal across the three legs
    chain_combined = float(np.clip(max(chn, den, mesc), 0.0, 1.0))

    risk = W_ACCUMULATION * acc + W_ESCALATION * esc + W_CHAIN * chain_combined
    risk = float(np.clip(risk, 0.0, 1.0))

    ceiling_breach = risk >= TRAJ_BLOCK_CEILING

    parts = [
        f"acc={acc:.2f}",
        f"esc={esc:.2f}",
        f"chain={chn:.2f}",
        f"denial={den:.2f}",
        f"mesc={mesc:.2f}",
    ]
    if intent_vec is None:
        parts.append("intent=unseeded")
    if ceiling_breach:
        parts.append("CEILING_BREACH")
    reason = f"trajectory risk {risk:.2f} ({', '.join(parts)}, window={len(history)})"

    return TrajectoryResult(
        risk=risk,
        accumulation=acc,
        escalation=esc,
        chain=chn,
        denial_echo=den,
        minister_esc=mesc,
        window_size=len(history),
        intent_used=intent_vec is not None,
        ceiling_breach=ceiling_breach,
        reason=reason,
    )


def modulate_threshold(
    base: float,
    compass_sim: Optional[float],
    traj_risk: float,
    drift_factor: float = 0.10,
    risk_factor: float = 0.15,
    floor: float = 0.30,
    ceil: float = 0.90,
) -> float:
    """Dynamic block threshold, trajectory-aware.
        effective = base + (compass_sim - 0.5)*drift_factor - traj_risk*risk_factor
    """
    eff = base
    if compass_sim is not None:
        eff += (compass_sim - 0.5) * drift_factor
    eff -= traj_risk * risk_factor
    return float(np.clip(eff, floor, ceil))


# ──────────────────────────────────────────────────────────────────────────────
# Smoke demo — python -m parliament.trajectory
# Tests all five signals including the new ones (A-D)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    rng = np.random.default_rng(0)

    def _unit(v):
        return (v / np.linalg.norm(v)).astype(np.float32)

    # In 768-dim space, jitter must be small relative to 1/sqrt(768)~0.036
    # to maintain high cosine similarity. Real BGE reformulations are similar.
    attack_dir = _unit(rng.standard_normal(768))

    def near(v, jitter=0.02):
        return _unit(v + jitter * rng.standard_normal(768))

    # intent drifts away from attack_dir — orthogonal region
    intent = _unit(rng.standard_normal(768))

    print("=== Demo A+B: chain coherence + sequential direction ===")
    h = new_history()
    for i, minister in enumerate(["VAULT", "VAULT", "EXECUTOR"]):
        vec = near(attack_dir, jitter=0.05 + i * 0.02)
        record_action(h, vec, "ESCALATE", 0.54 + i * 0.03, minister)
        print(f"  step {i+1}:", trajectory_risk(h, intent, near(attack_dir)).reason)

    print("\n=== Demo C: cross-minister escalation (VAULT → CHANNEL) ===")
    h2 = new_history()
    record_action(h2, near(attack_dir), "ESCALATE", 0.58, "VAULT")
    r1 = trajectory_risk(h2, intent, near(attack_dir))
    print(f"  after VAULT:   mesc={r1.minister_esc:.2f}  risk={r1.risk:.2f}")
    record_action(h2, near(attack_dir), "ESCALATE", 0.61, "CHANNEL")
    r2 = trajectory_risk(h2, intent, near(attack_dir))
    print(f"  after CHANNEL: mesc={r2.minister_esc:.2f}  risk={r2.risk:.2f}  "
          f"(VAULT->CHANNEL pattern fired)")

    print("\n=== Demo D: denial echo (causality laundering) ===")
    h3 = new_history()
    blocked_vec = near(attack_dir, jitter=0.02)
    record_action(h3, blocked_vec, "BLOCK", 0.78, "VAULT", is_denial=True)
    # Attacker reformulates: very similar intent, slightly different phrasing
    reformulated = near(blocked_vec, jitter=0.02)
    r3 = trajectory_risk(h3, intent, current_vec=reformulated)
    print(f"  denial_echo={r3.denial_echo:.2f}  risk={r3.risk:.2f}  "
          f"ceiling_breach={r3.ceiling_breach}")
    print(f"  (cosine blocked↔reformulated ≈ "
          f"{float(np.dot(blocked_vec, reformulated)):.2f})")

    print("\n=== Demo E: escalating session (ceiling approach — full breach needs #9) ===")
    # Demo: escalating session approaching ceiling (0.50). Full breach requires seed_intent
    # wired so esc signal contributes; this shows risk≈0.58 with threshold compressed.
    h4 = new_history()
    # Session: multiple high-confidence calls, VAULT→CHANNEL pattern, then denial
    calls = [
        (near(attack_dir, 0.03), "ESCALATE", 0.66, "VAULT",   False),
        (near(attack_dir, 0.03), "ESCALATE", 0.70, "VAULT",   False),
        (near(attack_dir, 0.03), "ESCALATE", 0.72, "CHANNEL", False),
        (near(attack_dir, 0.02), "BLOCK",    0.78, "CHANNEL", True),
    ]
    for vec, verdict, conf, minister, is_den in calls:
        record_action(h4, vec, verdict, conf, minister, is_denial=is_den)
    rf = trajectory_risk(h4, intent, current_vec=near(attack_dir, 0.02))
    print(f"  risk={rf.risk:.2f}  ceiling_breach={rf.ceiling_breach}  "
          f"(ceiling={TRAJ_BLOCK_CEILING})")
    print(f"  signals: acc={rf.accumulation:.2f}  esc={rf.escalation:.2f}  "
          f"chain={rf.chain:.2f}  denial={rf.denial_echo:.2f}  "
          f"mesc={rf.minister_esc:.2f}")
    base = 0.55
    print(f"  modulated threshold: {modulate_threshold(base, 0.38, rf.risk):.3f}  "
          f"(was {base})")
    if rf.ceiling_breach:
        print("  → Speaker would return BLOCK decided_by=TRAJECTORY")
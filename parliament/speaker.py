"""
parliament/speaker.py
=====================

The Speaker collects minister verdicts and combines them into a single
parliament verdict. Asymmetric: ONE confident BLOCK is enough to block.

v2.2 — Dynamic COMPASS-modulated thresholds
--------------------------------------------
Each minister's effective block threshold is modulated by the session's
COMPASS drift score:

    effective_threshold(minister) = base + alpha * (compass_sim - 0.5)

Where:
  - base       = per-minister threshold (or global fallback)
  - alpha      = drift_factor from config (default 0.3)
  - compass_sim = cosine similarity between user intent and proposed action

Effect:
  - High drift (compass_sim=0.10) → threshold drops ~0.12 → more aggressive
  - Well aligned (compass_sim=0.90) → threshold rises ~0.12 → fewer FPR

Anti-gaming constraint:
  - clip_upper = 0.0: alignment NEVER loosens threshold below base.
    An attacker who keeps actions superficially aligned cannot raise the
    threshold above base. Only the positive direction is clipped to zero.
  - clip_lower = -0.15: maximum tightening (prevents threshold collapse
    to near-zero on extreme drift).

This is applied BEFORE minister verdicts are finalized. The ministers'
raw similarity scores are re-evaluated against their effective thresholds
inside combine_verdicts(), so the MinisterScan verdicts from ministers.py
are overridden here when dynamic thresholds are active.

Design decisions (unchanged from v2.0):
  1. Any minister at confidence >= effective_block_threshold → BLOCK.
  2. COMPASS drift + any minister at >= grey_threshold → BLOCK (two signals).
  3. Any minister at >= grey_threshold → ESCALATE.
  4. COMPASS drift alone → ESCALATE.
  5. Otherwise → ALLOW.
  6. No score averaging. High confidence from one minister is meaningful.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ministers import MinisterScan
from .trajectory import TRAJ_BLOCK_CEILING


@dataclass
class SpeakerVerdict:
    verdict:    str          # "BLOCK" | "ESCALATE" | "ALLOW"
    decided_by: str          # minister name or "Speaker"
    confidence: float
    reason:     str
    blocks:     int          # count of ministers voting BLOCK
    escalates:  int          # count voting ESCALATE
    allows:     int          # count voting ALLOW
    dynamic_threshold_active: bool = False  # True when COMPASS modulation fired


# ──────────────────────────────────────────────────────────────────────────────
# Dynamic threshold computation
# ──────────────────────────────────────────────────────────────────────────────

def _effective_threshold(
    minister: str,
    compass_sim: float,
    thresholds: dict,
) -> float:
    """
    Compute the effective block threshold for a minister given the current
    COMPASS similarity score.

    Formula: effective = base + alpha * (compass_sim - 0.5)

    Clipping:
      - clip_upper: max upward adjustment (default 0.0 — alignment never loosens)
      - clip_lower: max downward adjustment (default -0.15)

    Config keys (all optional, with defaults):
      thresholds.drift_factor   (alpha)      default 0.3
      thresholds.clip_upper                  default 0.0
      thresholds.clip_lower                  default -0.15
      thresholds.per_minister.MINISTER       per-minister base (optional)
    """
    # Base: per-minister override or global fallback
    per_minister = thresholds.get("per_minister", {})
    base = per_minister.get(minister, thresholds["block"])

    alpha       = thresholds.get("drift_factor", 0.3)
    clip_upper  = thresholds.get("clip_upper",   0.0)
    clip_lower  = thresholds.get("clip_lower",  -0.15)

    # Raw adjustment
    adjustment = alpha * (compass_sim - 0.5)

    # Clip: positive adjustment (alignment loosening) capped at clip_upper (0.0)
    #       negative adjustment (drift tightening) floored at clip_lower
    adjustment = max(clip_lower, min(clip_upper, adjustment))

    effective = base + adjustment
    # Hard bounds: keep threshold in [0.05, 0.99]
    return round(max(0.05, min(0.99, effective)), 4)


def _dynamic_thresholds_active(thresholds: dict) -> bool:
    """Return True if dynamic threshold modulation is configured and enabled."""
    if not thresholds.get("drift_factor"):
        return False
    # Only active when compass_sim is meaningful (intent was seeded)
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Re-evaluate minister verdicts against dynamic thresholds
# ──────────────────────────────────────────────────────────────────────────────

def _reapply_thresholds(
    results: list[MinisterScan],
    compass_sim: float,
    thresholds: dict,
) -> list[MinisterScan]:
    """
    Re-evaluate each minister's raw confidence score against its effective
    (COMPASS-modulated) threshold. Returns a new list with updated verdicts.

    This is called when compass_sim is available (intent was seeded). When
    compass_sim is 1.0 (no intent stored), the effective threshold equals
    base (no modulation).
    """
    grey_threshold = thresholds["grey"]
    updated = []

    for r in results:
        eff = _effective_threshold(r.minister, compass_sim, thresholds)

        if r.confidence >= eff:
            new_verdict = "BLOCK"
        elif r.confidence >= grey_threshold:
            new_verdict = "ESCALATE"
        else:
            new_verdict = "ALLOW"

        # Only create a new object if verdict changed
        if new_verdict != r.verdict:
            from dataclasses import replace
            updated.append(replace(r, verdict=new_verdict))
        else:
            updated.append(r)

    return updated


# ──────────────────────────────────────────────────────────────────────────────
# Main combine function
# ──────────────────────────────────────────────────────────────────────────────

def combine_verdicts(
    minister_results: list[MinisterScan],
    compass_drift: bool,
    compass_sim: float,
    thresholds: dict,
    traj_risk: float = 0.0,
) -> SpeakerVerdict:
    """
    Combine minister scans + COMPASS drift + trajectory risk into a final verdict.

    Args:
      minister_results: scans from every activated minister
      compass_drift:    True if cosine(intent, action) < compass_drift threshold
      compass_sim:      the actual cosine value (1.0 if no intent seeded)
      thresholds:       dict with block, grey, compass_drift keys (block is the
                        already-modulated per-call value from server.py, which
                        applies COMPASS drift_factor + per_minister + clip)
      traj_risk:        combined session trajectory risk from trajectory.py
    """
    drift_threshold = thresholds["compass_drift"]
    grey_threshold  = thresholds["grey"]

    # ── Dynamic threshold modulation ─────────────────────────────────────────
    # Only apply when compass_sim is meaningful (< 1.0 means intent was seeded).
    # When no intent stored, compass_sim=1.0, adjustment=+0.15 but clip_upper=0
    # so effective = base exactly — no change.
    dynamic_active = (
        _dynamic_thresholds_active(thresholds)
        and compass_sim < 1.0  # intent was seeded
    )

    if dynamic_active:
        results = _reapply_thresholds(minister_results, compass_sim, thresholds)
    else:
        results = minister_results

    # Effective block threshold for reason strings (use COMPASS-modulated value
    # of the winning minister, or global if no winner yet)
    def _eff(minister: str) -> float:
        return _effective_threshold(minister, compass_sim, thresholds)

    # Tally
    blocks    = [r for r in results if r.verdict == "BLOCK"]
    escalates = [r for r in results if r.verdict == "ESCALATE"]
    allows    = [r for r in results if r.verdict == "ALLOW"]

    # ── Case 0: trajectory ceiling breach → session-level BLOCK ───────────
    # Fires when accumulated session risk crosses TRAJ_BLOCK_CEILING regardless
    # of whether any individual minister voted BLOCK. This is what makes Kavach
    # a live session monitor, not just a per-call guard. Catches causality
    # laundering (ARM arXiv:2604.04035) and cross-minister escalation patterns
    # (AgentDoG arXiv:2601.18491) that individually-benign calls build up to.
    if traj_risk >= TRAJ_BLOCK_CEILING:
        return SpeakerVerdict(
            verdict="BLOCK",
            decided_by="TRAJECTORY",
            confidence=round(traj_risk, 4),
            reason=(
                f"session trajectory risk {traj_risk:.3f} >= ceiling "
                f"{TRAJ_BLOCK_CEILING:.2f} — multi-step attack pattern detected "
                f"across session window (denial echo / minister escalation / "
                f"semantic chain coherence)"
            ),
            blocks=len(blocks),
            escalates=len(escalates),
            allows=len(allows),
        )

    # ── Case 1: any minister at BLOCK ─────────────────────────────────────
    if blocks:
        winner = max(blocks, key=lambda r: r.confidence)
        eff_thresh = _eff(winner.minister)
        if winner.matched_level == "deterministic":
            # Stage 1 pre-filter hit (regex/deny-list rule, not a
            # cosine-similarity match) — "at sim X" would misdescribe a
            # deterministic rule firing, so use accurate wording instead.
            reason = (
                f"{winner.minister} deterministic rule matched "
                f"{winner.matched_id or 'rule'} — {winner.matched_text or 'pattern hit'}"
            )
        else:
            reason = (
                f"{winner.minister} matched {winner.matched_id or 'pattern'} "
                f"({winner.matched_level or 'L?'}) at sim {winner.confidence:.3f} "
                f">= block threshold {eff_thresh:.3f}"
            )
        if dynamic_active:
            reason += (
                f" [dynamic: base={thresholds.get('per_minister', {}).get(winner.minister, thresholds['block']):.3f}"
                f", compass_sim={compass_sim:.3f}"
                f", alpha={thresholds.get('drift_factor', 0.3)}]"
            )
        if compass_drift:
            reason += (
                f"; COMPASS drift confirms (sim {compass_sim:.3f} "
                f"< {drift_threshold:.2f})"
            )
        return SpeakerVerdict(
            verdict="BLOCK",
            decided_by=winner.minister,
            confidence=winner.confidence,
            reason=reason,
            blocks=len(blocks),
            escalates=len(escalates),
            allows=len(allows),
            dynamic_threshold_active=dynamic_active,
        )

    # ── Case 2: COMPASS drift + at least one ESCALATE → BLOCK ────────────────
    if compass_drift and escalates:
        winner = max(escalates, key=lambda r: r.confidence)
        return SpeakerVerdict(
            verdict="BLOCK",
            decided_by=f"COMPASS+{winner.minister}",
            confidence=max(winner.confidence, 1.0 - compass_sim),
            reason=(
                f"COMPASS drift (sim {compass_sim:.3f} "
                f"< {drift_threshold:.2f}) corroborated by "
                f"{winner.minister} borderline match "
                f"({winner.matched_id} at {winner.confidence:.3f})"
            ),
            blocks=0,
            escalates=len(escalates),
            allows=len(allows),
            dynamic_threshold_active=dynamic_active,
        )

    # ── Case 3: any minister at ESCALATE ─────────────────────────────────────
    if escalates:
        winner = max(escalates, key=lambda r: r.confidence)
        global_block = thresholds["block"]
        return SpeakerVerdict(
            verdict="ESCALATE",
            decided_by=winner.minister,
            confidence=winner.confidence,
            reason=(
                f"{winner.minister} borderline match "
                f"({winner.matched_id} at {winner.confidence:.3f}, "
                f"between grey {grey_threshold:.2f} and block "
                f"{_eff(winner.minister):.3f}) — escalating to user"
            ),
            blocks=0,
            escalates=len(escalates),
            allows=len(allows),
            dynamic_threshold_active=dynamic_active,
        )

    # ── Case 4: COMPASS drift alone → ESCALATE ───────────────────────────────
    if compass_drift:
        return SpeakerVerdict(
            verdict="ESCALATE",
            decided_by="COMPASS",
            confidence=1.0 - compass_sim,
            reason=(
                f"COMPASS drift detected (sim {compass_sim:.3f} "
                f"< {drift_threshold:.2f}) without minister match — "
                f"user intent diverged from proposed action; escalating"
            ),
            blocks=0,
            escalates=0,
            allows=len(allows),
            dynamic_threshold_active=dynamic_active,
        )

    # ── Case 5: clean ALLOW ───────────────────────────────────────────────────
    avg = (
        sum(r.confidence for r in allows) / len(allows) if allows else 0.0
    )
    return SpeakerVerdict(
        verdict="ALLOW",
        decided_by="Speaker",
        confidence=round(avg, 4),
        reason=(
            f"no minister exceeded block threshold; "
            f"intent-action aligned (sim {compass_sim:.3f})"
        ),
        blocks=0,
        escalates=0,
        allows=len(allows),
        dynamic_threshold_active=dynamic_active,
    )

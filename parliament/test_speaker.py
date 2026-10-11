#!/usr/bin/env python3
"""
parliament/test_speaker.py
==========================

Pure unit tests for combine_verdicts() in speaker.py. No server, no
ChromaDB, no embedding model — just synthetic MinisterScan inputs.

These tests pin down the speaker's behavior so it cannot silently change.
The speaker logic is documented in speaker.py as five cases:

    1. Any minister BLOCK → BLOCK (highest-confidence reason wins)
    2. COMPASS drift + any minister ESCALATE → BLOCK
    3. Any minister ESCALATE → ESCALATE
    4. COMPASS drift alone → ESCALATE
    5. Otherwise → ALLOW

If any of these tests fail, the speaker is making different decisions than
the design says it should — and the InjecAgent and benign numbers will not
mean what we claim they mean. Run before merging any changes to speaker.py.

Usage:
    pytest parliament/test_speaker.py -v
or:
    python parliament/test_speaker.py
"""

from __future__ import annotations

from .ministers import MinisterScan
from .speaker  import combine_verdicts


THRESHOLDS = {
    "block":         0.65,
    "grey":          0.50,
    "compass_drift": 0.40,
    "router_min":    0.40,
}


def _scan(name: str, verdict: str, confidence: float,
          matched_id: str | None = None) -> MinisterScan:
    return MinisterScan(
        minister=name,
        verdict=verdict,
        confidence=confidence,
        matched_id=matched_id or f"{name[:4]}-001",
        matched_text=None,
        matched_level="L1",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Case 1 — any minister BLOCK → BLOCK
# ──────────────────────────────────────────────────────────────────────────────

def test_single_minister_block():
    scans = [
        _scan("EXECUTOR", "BLOCK", 0.81, "EXEC-001"),
        _scan("VAULT",    "ALLOW", 0.10),
        _scan("CHANNEL",  "ALLOW", 0.05),
        _scan("NAVIGATOR","ALLOW", 0.20),
    ]
    v = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    assert v.verdict    == "BLOCK"
    assert v.decided_by == "EXECUTOR"
    assert v.confidence == 0.81
    assert "EXEC-001" in v.reason


def test_multiple_blocks_highest_confidence_wins():
    scans = [
        _scan("EXECUTOR", "BLOCK", 0.70, "EXEC-001"),
        _scan("VAULT",    "BLOCK", 0.95, "VAULT-001"),
        _scan("CHANNEL",  "ALLOW", 0.05),
        _scan("NAVIGATOR","ALLOW", 0.20),
    ]
    v = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    assert v.verdict    == "BLOCK"
    assert v.decided_by == "VAULT"
    assert v.confidence == 0.95


def test_block_with_compass_drift_concomitant():
    """Drift confirms but the verdict is still BLOCK; reason mentions both."""
    scans = [
        _scan("EXECUTOR", "BLOCK", 0.80, "EXEC-007"),
        _scan("VAULT",    "ALLOW", 0.10),
        _scan("CHANNEL",  "ALLOW", 0.05),
        _scan("NAVIGATOR","ALLOW", 0.20),
    ]
    v = combine_verdicts(scans, compass_drift=True, compass_sim=0.20,
                         thresholds=THRESHOLDS)
    assert v.verdict    == "BLOCK"
    assert v.decided_by == "EXECUTOR"
    assert "COMPASS drift confirms" in v.reason


# ──────────────────────────────────────────────────────────────────────────────
# Case 2 — COMPASS drift + any minister ESCALATE → BLOCK
# ──────────────────────────────────────────────────────────────────────────────

def test_compass_drift_plus_escalate_becomes_block():
    scans = [
        _scan("EXECUTOR", "ESCALATE", 0.55, "EXEC-002"),
        _scan("VAULT",    "ALLOW",    0.10),
        _scan("CHANNEL",  "ALLOW",    0.05),
        _scan("NAVIGATOR","ALLOW",    0.20),
    ]
    v = combine_verdicts(scans, compass_drift=True, compass_sim=0.30,
                         thresholds=THRESHOLDS)
    assert v.verdict == "BLOCK"
    assert "COMPASS+" in v.decided_by
    assert "EXECUTOR" in v.decided_by
    assert "drift" in v.reason.lower()


def test_compass_drift_plus_escalate_picks_highest_confidence():
    scans = [
        _scan("EXECUTOR", "ESCALATE", 0.55, "EXEC-002"),
        _scan("VAULT",    "ESCALATE", 0.62, "VAULT-002"),
        _scan("CHANNEL",  "ALLOW",    0.05),
        _scan("NAVIGATOR","ALLOW",    0.20),
    ]
    v = combine_verdicts(scans, compass_drift=True, compass_sim=0.30,
                         thresholds=THRESHOLDS)
    assert v.verdict == "BLOCK"
    assert "VAULT" in v.decided_by


# ──────────────────────────────────────────────────────────────────────────────
# Case 3 — any minister ESCALATE (no drift) → ESCALATE
# ──────────────────────────────────────────────────────────────────────────────

def test_escalate_alone_returns_escalate():
    scans = [
        _scan("EXECUTOR", "ESCALATE", 0.55, "EXEC-002"),
        _scan("VAULT",    "ALLOW",    0.10),
        _scan("CHANNEL",  "ALLOW",    0.05),
        _scan("NAVIGATOR","ALLOW",    0.20),
    ]
    v = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    assert v.verdict    == "ESCALATE"
    assert v.decided_by == "EXECUTOR"
    assert v.confidence == 0.55


# ──────────────────────────────────────────────────────────────────────────────
# Case 4 — COMPASS drift alone → ESCALATE
# ──────────────────────────────────────────────────────────────────────────────

def test_compass_drift_alone_returns_escalate():
    scans = [
        _scan("EXECUTOR", "ALLOW", 0.10),
        _scan("VAULT",    "ALLOW", 0.10),
        _scan("CHANNEL",  "ALLOW", 0.05),
        _scan("NAVIGATOR","ALLOW", 0.20),
    ]
    v = combine_verdicts(scans, compass_drift=True, compass_sim=0.30,
                         thresholds=THRESHOLDS)
    assert v.verdict    == "ESCALATE"
    assert v.decided_by == "COMPASS"
    assert "drift detected" in v.reason.lower()


# ──────────────────────────────────────────────────────────────────────────────
# Case 5 — clean → ALLOW
# ──────────────────────────────────────────────────────────────────────────────

def test_all_allow_no_drift_returns_allow():
    scans = [
        _scan("EXECUTOR", "ALLOW", 0.15),
        _scan("VAULT",    "ALLOW", 0.10),
        _scan("CHANNEL",  "ALLOW", 0.05),
        _scan("NAVIGATOR","ALLOW", 0.20),
    ]
    v = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    assert v.verdict    == "ALLOW"
    assert v.decided_by == "Speaker"
    assert v.blocks == 0
    assert v.escalates == 0
    assert v.allows == 4


# ──────────────────────────────────────────────────────────────────────────────
# Edge cases
# ──────────────────────────────────────────────────────────────────────────────

def test_empty_minister_list_is_allow():
    """No ministers activated by router → fall through to ALLOW."""
    v = combine_verdicts([], compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    assert v.verdict == "ALLOW"


def test_block_priority_over_drift_when_no_drift():
    """Without drift, a block at minimum threshold still wins."""
    scans = [
        _scan("EXECUTOR", "BLOCK", 0.66, "EXEC-099"),
        _scan("VAULT",    "ESCALATE", 0.62),
        _scan("CHANNEL",  "ALLOW",    0.05),
        _scan("NAVIGATOR","ALLOW",    0.20),
    ]
    v = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    assert v.verdict == "BLOCK"
    assert v.decided_by == "EXECUTOR"


def test_drift_does_not_escalate_when_block_present():
    """Drift adds to a block reason but never escalates a block to a different verdict."""
    scans = [
        _scan("EXECUTOR", "BLOCK", 0.70, "EXEC-001"),
    ]
    v_no_drift = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                                  thresholds=THRESHOLDS)
    v_drift = combine_verdicts(scans, compass_drift=True, compass_sim=0.20,
                               thresholds=THRESHOLDS)
    # Both BLOCK; drift just changes the reason.
    assert v_no_drift.verdict == "BLOCK"
    assert v_drift.verdict    == "BLOCK"
    assert v_no_drift.decided_by == v_drift.decided_by
    assert v_drift.reason != v_no_drift.reason


def test_no_score_averaging_across_ministers():
    """One high score, three low scores → BLOCK (not averaged)."""
    scans = [
        _scan("EXECUTOR", "BLOCK", 0.92, "EXEC-001"),
        _scan("VAULT",    "ALLOW", 0.05),
        _scan("CHANNEL",  "ALLOW", 0.05),
        _scan("NAVIGATOR","ALLOW", 0.05),
    ]
    v = combine_verdicts(scans, compass_drift=False, compass_sim=0.95,
                         thresholds=THRESHOLDS)
    # If we were averaging, mean = (0.92 + 0.05*3) / 4 = 0.27 → ALLOW.
    # Asymmetric speaker says: one strong signal blocks.
    assert v.verdict == "BLOCK"
    assert v.confidence == 0.92


# ──────────────────────────────────────────────────────────────────────────────
# Runner (so this works without pytest)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import inspect
    import sys
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✓ {name}")
        except AssertionError as e:
            print(f"  ✗ {name}: {e}")
            failures += 1
        except Exception as e:
            print(f"  ✗ {name}: {type(e).__name__}: {e}")
            failures += 1
    print()
    if failures:
        print(f"FAILED — {failures} of {len(tests)} tests failed")
        sys.exit(1)
    print(f"ALL {len(tests)} SPEAKER TESTS PASSED ✓")

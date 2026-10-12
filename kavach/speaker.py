"""
kavach/speaker.py
=================

The Speaker: one deterministic final verdict from the four minister results.

Policy (fail-closed):
  1. Any BLOCK                                        -> BLOCK
  2. else any ESCALATE                                -> ESCALATE
  3. else any missing / duplicate / unexpected / malformed minister result
                                                      -> ESCALATE
  4. else (every required minister present, valid, ALLOW) -> ALLOW

A BLOCK from a well-formed result always wins, even if another minister's
result is missing or malformed. ALLOW is only reachable via rule 4.

Adapted from parliament/speaker.py: its COMPASS drift, trajectory-ceiling and
dynamic-threshold paths are dropped (out of MVP scope). Ministers now carry
their own verdicts; the Speaker does not re-threshold confidences.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Tuple

from .schemas import MINISTER_NAMES, VERDICTS, MinisterResult


@dataclass
class SpeakerVerdict:
    verdict: str
    decided_by: str
    reason: str


def _is_valid(r: Any) -> bool:
    return isinstance(r, MinisterResult) and r.verdict in VERDICTS


def _rank(r: MinisterResult):
    """Highest confidence wins; ties go to the earlier minister in MINISTER_NAMES,
    so the verdict never depends on the order results arrive in."""
    order = MINISTER_NAMES.index(r.minister) if r.minister in MINISTER_NAMES else len(MINISTER_NAMES)
    return (r.confidence or 0.0, -order)


def decide(results: Iterable[Any], required: Tuple[str, ...] = MINISTER_NAMES) -> SpeakerVerdict:
    items: List[Any] = list(results) if results is not None else []
    valid = [r for r in items if _is_valid(r)]
    malformed = len(items) - len(valid)

    blocks = [r for r in valid if r.verdict == "BLOCK"]
    if blocks:
        w = max(blocks, key=_rank)
        return SpeakerVerdict("BLOCK", w.minister, f"{w.minister} BLOCK: {w.reason}")

    escalates = [r for r in valid if r.verdict == "ESCALATE"]
    if escalates:
        w = max(escalates, key=_rank)
        return SpeakerVerdict("ESCALATE", w.minister, f"{w.minister} ESCALATE: {w.reason}")

    names = [r.minister for r in valid]
    problems = []
    missing = [n for n in required if n not in names]
    if missing:
        problems.append(f"missing result from {', '.join(missing)}")
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        problems.append(f"duplicate result from {', '.join(dupes)}")
    unexpected = sorted({n for n in names if n not in required})
    if unexpected:
        problems.append(f"unexpected minister {', '.join(unexpected)}")
    if malformed:
        problems.append(f"{malformed} malformed result(s)")
    if problems:
        return SpeakerVerdict("ESCALATE", "Speaker", "incomplete minister results, failing closed: " + "; ".join(problems))

    return SpeakerVerdict("ALLOW", "Speaker", "all four ministers returned ALLOW")

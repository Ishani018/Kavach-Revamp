"""Speaker policy tests. Minister results are synthetic here; that is the point."""

import pytest

from kavach.schemas import MINISTER_NAMES, MinisterResult
from kavach.speaker import decide


def mk(name, verdict, conf=None):
    return MinisterResult(minister=name, verdict=verdict, reason=f"{name} says {verdict}", confidence=conf)


def full(**verdicts):
    return [mk(n, verdicts.get(n, "ALLOW")) for n in MINISTER_NAMES]


def test_all_allow_is_allow():
    assert decide(full()).verdict == "ALLOW"


@pytest.mark.parametrize("who", MINISTER_NAMES)
def test_any_single_block_is_block(who):
    v = decide(full(**{who: "BLOCK"}))
    assert v.verdict == "BLOCK" and v.decided_by == who


def test_escalate_beats_allow():
    assert decide(full(CHANNEL="ESCALATE")).verdict == "ESCALATE"


def test_block_beats_escalate():
    assert decide(full(VAULT="ESCALATE", EXECUTOR="BLOCK")).verdict == "BLOCK"


def test_missing_minister_never_allows():
    r = full()[:3]
    v = decide(r)
    assert v.verdict == "ESCALATE" and "NAVIGATOR" in v.reason


def test_empty_and_none_never_allow():
    assert decide([]).verdict == "ESCALATE"
    assert decide(None).verdict == "ESCALATE"


@pytest.mark.parametrize("junk", [None, "ALLOW", {"minister": "VAULT", "verdict": "ALLOW"}, 42])
def test_malformed_entry_never_allows(junk):
    r = full()[:3] + [junk]
    assert decide(r).verdict == "ESCALATE"


def test_malformed_verdict_value_never_allows():
    bad = mk("NAVIGATOR", "ALLOW").model_copy(update={"verdict": "MAYBE"})  # bypasses validation
    assert decide(full()[:3] + [bad]).verdict == "ESCALATE"


def test_duplicate_and_unexpected_ministers_never_allow():
    assert decide(full() + [mk("VAULT", "ALLOW")]).verdict == "ESCALATE"
    assert decide(full()[:3] + [mk("STEWARD", "ALLOW")]).verdict == "ESCALATE"


def test_block_wins_even_if_another_result_is_missing():
    assert decide([mk("VAULT", "BLOCK")]).verdict == "BLOCK"


def test_deterministic():
    r = full(CHANNEL="ESCALATE", NAVIGATOR="ESCALATE")
    assert decide(r) == decide(list(reversed(r)))

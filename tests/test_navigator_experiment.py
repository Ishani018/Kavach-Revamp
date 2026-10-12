"""Protocol checks for NAVIGATOR's first experiment: criteria logic on synthetic data, and calibration-set integrity.
No NAVIGATOR logic is exercised here; the full identity run is the documented command, not a unit test."""
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

EXP = Path(__file__).resolve().parent.parent / "review" / "navigator-first-experiment"
spec = importlib.util.spec_from_file_location("run_experiment", EXP / "run_experiment.py")
rx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rx)

ROWS = [json.loads(l) for l in (EXP / "calibration_set.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def row(i, role, shape, verdict, conf=0.6, set_="s"):
    return {"cal_id": f"C{i}", "set": set_, "source_id": str(i), "role": role, "shape": shape,
            "baseline": {"navigator": {"verdict": verdict, "confidence": conf, "matched_id": "NAV-1"}, "VAULT": "ALLOW", "EXECUTOR": "ALLOW"}}


def new_of(rows, mapping=None):
    mapping = mapping or {}
    return [{"navigator": {"verdict": mapping.get(r["cal_id"], r["baseline"]["navigator"]["verdict"]),
                           "confidence": r["baseline"]["navigator"]["confidence"], "matched_id": "NAV-1"},
             "VAULT": "ALLOW", "EXECUTOR": "ALLOW"} for r in rows]


def synthetic():
    rows = [row(i, "benign", "shell", "ESCALATE") for i in range(100)]
    rows += [row(1000 + i, "attack", "shell", "BLOCK" if i < 5 else "ESCALATE", set_="atk") for i in range(40)]
    return rows


def test_mcnemar_exact():
    assert rx.mcnemar_exact_p(0, 0) == 1.0
    assert rx.mcnemar_exact_p(10, 0) == pytest.approx(2 / 1024)
    assert rx.mcnemar_exact_p(5, 5) == 1.0


def test_identity_is_rejected_for_lack_of_improvement():
    rows = synthetic()
    res = rx.evaluate(rows, new_of(rows))
    assert res["_decision"] == "REJECT" and not res["P1_benign_shell_escalation_falls"]["passed"]
    assert all(res[k]["passed"] for k in ("A1_no_lost_block", "A2_attack_catch_held", "M1_other_ministers_unchanged"))


def test_clear_improvement_advances():
    rows = synthetic()
    res = rx.evaluate(rows, new_of(rows, {f"C{i}": "ALLOW" for i in range(60)}), determinism=dict(passed=True))
    assert res["P1_benign_shell_escalation_falls"]["passed"]
    assert res["_decision"] == "ADVANCE"


def test_lost_block_is_fatal():
    rows = synthetic()
    m = {f"C{i}": "ALLOW" for i in range(60)}
    m["C1000"] = "ESCALATE"
    res = rx.evaluate(rows, new_of(rows, m), determinism=dict(passed=True))
    assert not res["A1_no_lost_block"]["passed"] and res["_decision"] == "REJECT"


def test_attack_catch_drop_is_fatal():
    rows = synthetic()
    m = {f"C{i}": "ALLOW" for i in range(60)}
    m.update({f"C{1005 + i}": "ALLOW" for i in range(10)})
    res = rx.evaluate(rows, new_of(rows, m), determinism=dict(passed=True))
    assert not res["A2_attack_catch_held"]["passed"]


def test_changed_other_minister_is_fatal():
    rows = synthetic()
    new = new_of(rows, {f"C{i}": "ALLOW" for i in range(60)})
    new[0]["VAULT"] = "BLOCK"
    assert not rx.evaluate(rows, new, determinism=dict(passed=True))["M1_other_ministers_unchanged"]["passed"]


def test_missing_criteria_are_reported():
    rows = synthetic()
    assert "D1_deterministic" in rx.evaluate(rows, new_of(rows))["_missing_criteria"]


# ---- calibration set integrity
def test_ids_and_calls_unique():
    assert len({r["cal_id"] for r in ROWS}) == len(ROWS)
    assert len({" ".join(r["call"].lower().split()) for r in ROWS}) == len(ROWS)


def test_hashes_match_and_labels_unverified():
    for r in ROWS:
        assert hashlib.sha256(r["call"].encode("utf-8")).hexdigest() == r["call_sha256"]
        assert r["label_status"] == "unverified_source_meaning"
        assert r["role"] in ("attack", "benign") and r["shape"] in ("shell", "non_shell")


def test_no_reserved_phase_a_rows():
    pa = EXP.parent / "phase-a-candidates"
    reserved = set()
    for f in ("tldr_security_items.jsonl", "swe_agent_items.jsonl", "redcode_bash_items.jsonl"):
        for l in (pa / f).read_text(encoding="utf-8").splitlines():
            if l.strip():
                r = json.loads(l)
                if r["split"] == "reserved":
                    reserved.add(r["transformation"]["call"])
    leaked = [r["cal_id"] for r in ROWS if r["call"] in reserved and not r["set"].startswith(("batch1", "kavach", "benign", "real", "atrium", "openclaw"))]
    assert leaked == []
    assert not any(r["set"].startswith("phase_a") and r["contamination"] != "diagnosis_split" for r in ROWS)


def test_summary_matches_file_and_declares_non_independence():
    s = json.loads((EXP / "calibration_set_summary.json").read_text())
    assert s["file_sha256"] == hashlib.sha256((EXP / "calibration_set.jsonl").read_bytes()).hexdigest()
    assert s["items"] == len(ROWS) and "not_independent" in s["status"]
    assert dict(Counter(r["role"] for r in ROWS)) == s["by_role"]


def test_criteria_file_is_complete():
    c = json.loads((EXP / "criteria.json").read_text())
    assert set(c["criteria"]) == {"P1_benign_shell_escalation_falls", "P2_non_shell_benign_not_worse", "A1_no_lost_block",
                                  "A2_attack_catch_held", "A3_pattern_canaries_held", "D1_deterministic",
                                  "M1_other_ministers_unchanged", "S1_separation_not_worse"}

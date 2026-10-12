#!/usr/bin/env python3
"""
Run the baseline-vs-candidate comparison for a NAVIGATOR experiment against the pre-registered criteria.

The calibration set (calibration_set.jsonl) already carries the BASELINE outputs of the unchanged NAVIGATOR, so the
baseline is never recomputed. The candidate is whatever NAVIGATOR the working tree currently contains (default) or a
standalone scoring module given with --candidate. With no change in place the run is an identity check and must
PASS with zero differences.

    python review/navigator-first-experiment/run_experiment.py [--candidate FILE.py] [--chroma-path DIR] [--sample N] [--out FILE]

A --candidate module must define   build(navigator) -> object with check(ToolCall) -> MinisterResult
so a scoring idea can be tried without editing the MVP.

Exit code 0 = every gating criterion holds (ADVANCE to the single reserved-split confirmation); 1 = REJECT.
This script never opens the Phase A reserved split. Results on this set are manipulation checks, not performance.
"""
import argparse
import importlib.util
import json
import math
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
BASE = ROOT / "review" / "navigator-baseline"

CRIT = json.loads((HERE / "criteria.json").read_text())["criteria"]
RANK = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}


# ------------------------------------------------------------------------------------ statistics
def mcnemar_exact_p(improved, worsened):
    """Two-sided exact binomial test on the discordant pairs."""
    n = improved + worsened
    if n == 0:
        return 1.0
    k = min(improved, worsened)
    p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, p)


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(c - h, 3), round(c + h, 3))


def auc(attack, benign):
    a, b = list(attack), list(benign)
    if not a or not b:
        return None
    gt = sum(x > y for x in a for y in b)
    eq = sum(x == y for x in a for y in b)
    return (gt + 0.5 * eq) / (len(a) * len(b))


# ------------------------------------------------------------------------------------ evaluation (pure)
def evaluate(rows, new, canary_old=None, canary_new=None, determinism=None):
    """rows: calibration rows with .baseline; new: same-length list of {'navigator': {...}, 'VAULT', 'EXECUTOR'}."""
    res, by = {}, {r["cal_id"]: n for r, n in zip(rows, new)}
    esc = lambda v: v != "ALLOW"

    ben = [r for r in rows if r["role"] == "benign"]
    shell = [r for r in ben if r["shape"] == "shell"]
    imp = sum(esc(r["baseline"]["navigator"]["verdict"]) and not esc(by[r["cal_id"]]["navigator"]["verdict"]) for r in shell)
    wor = sum((not esc(r["baseline"]["navigator"]["verdict"])) and esc(by[r["cal_id"]]["navigator"]["verdict"]) for r in shell)
    before = sum(esc(r["baseline"]["navigator"]["verdict"]) for r in shell) / max(1, len(shell))
    after = sum(esc(by[r["cal_id"]]["navigator"]["verdict"]) for r in shell) / max(1, len(shell))
    p = mcnemar_exact_p(imp, wor)
    c = CRIT["P1_benign_shell_escalation_falls"]
    res["P1_benign_shell_escalation_falls"] = dict(
        passed=(before - after) >= c["min_absolute_drop"] and p < c["exact_mcnemar_two_sided_p_below"],
        n=len(shell), before=round(before, 3), after=round(after, 3), ci_before=wilson(round(before * len(shell)), len(shell)),
        ci_after=wilson(round(after * len(shell)), len(shell)), improved=imp, worsened=wor, mcnemar_p=p)

    non = [r for r in ben if r["shape"] == "non_shell"]
    b0 = sum(esc(r["baseline"]["navigator"]["verdict"]) for r in non) / max(1, len(non))
    b1 = sum(esc(by[r["cal_id"]]["navigator"]["verdict"]) for r in non) / max(1, len(non))
    res["P2_non_shell_benign_not_worse"] = dict(passed=(b1 - b0) <= CRIT["P2_non_shell_benign_not_worse"]["max_absolute_increase"],
                                                n=len(non), before=round(b0, 3), after=round(b1, 3))

    atk = [r for r in rows if r["role"] == "attack"]
    lost_block = [r["cal_id"] for r in atk if r["baseline"]["navigator"]["verdict"] == "BLOCK" and by[r["cal_id"]]["navigator"]["verdict"] != "BLOCK"]
    res["A1_no_lost_block"] = dict(passed=len(lost_block) <= CRIT["A1_no_lost_block"]["max_lost"],
                                   baseline_blocks=sum(r["baseline"]["navigator"]["verdict"] == "BLOCK" for r in atk), lost=lost_block[:20], n_lost=len(lost_block))

    c2, sets, ok = CRIT["A2_attack_catch_held"], {}, True
    for s in sorted({r["set"] for r in atk}):
        rs = [r for r in atk if r["set"] == s]
        if len(rs) < c2["min_set_size"]:
            continue
        cb = sum(esc(r["baseline"]["navigator"]["verdict"]) for r in rs) / len(rs)
        ca = sum(esc(by[r["cal_id"]]["navigator"]["verdict"]) for r in rs) / len(rs)
        caught = [r for r in rs if esc(r["baseline"]["navigator"]["verdict"])]
        lost = [r["cal_id"] for r in caught if not esc(by[r["cal_id"]]["navigator"]["verdict"])]
        good = (cb - ca) <= c2["max_catch_drop"] and (len(lost) / max(1, len(caught))) <= c2["max_lost_detection_share"]
        ok &= good
        sets[s] = dict(n=len(rs), catch_before=round(cb, 3), catch_after=round(ca, 3), lost_detections=len(lost), lost_ids=lost[:10], passed=good)
    res["A2_attack_catch_held"] = dict(passed=ok, sets=sets)

    if canary_old is not None:
        own = lambda r, i: r["navigator"]["verdict"] != "ALLOW" and r["navigator"]["matched_id"] == i.split("_")[0]
        lost_c = [o["id"] for o, n in zip(canary_old, canary_new)
                  if (own(o, o["id"]) and not own(n, o["id"])) or (o["navigator"]["verdict"] != "ALLOW" and n["navigator"]["verdict"] == "ALLOW")]
        res["A3_pattern_canaries_held"] = dict(passed=len(lost_c) <= CRIT["A3_pattern_canaries_held"]["max_lost"], n=len(canary_old), lost=lost_c[:20])
    if determinism is not None:
        res["D1_deterministic"] = determinism

    chg = [r["cal_id"] for r in rows if (r["baseline"]["VAULT"], r["baseline"]["EXECUTOR"]) != (by[r["cal_id"]]["VAULT"], by[r["cal_id"]]["EXECUTOR"])]
    res["M1_other_ministers_unchanged"] = dict(passed=not chg, changed=chg[:20], n_changed=len(chg))

    sc = lambda src, role: [(src(r))["navigator"]["confidence"] for r in rows if r["role"] == role and r["shape"] == "shell"]
    a0, a1 = auc(sc(lambda r: r["baseline"], "attack"), sc(lambda r: r["baseline"], "benign")), auc(sc(lambda r: by[r["cal_id"]], "attack"), sc(lambda r: by[r["cal_id"]], "benign"))
    res["S1_separation_not_worse"] = dict(passed=a0 is None or a1 >= a0 - CRIT["S1_separation_not_worse"]["max_auc_drop"],
                                          auc_before=None if a0 is None else round(a0, 3), auc_after=None if a1 is None else round(a1, 3))

    changed = [(r["set"], r["source_id"], r["baseline"]["navigator"]["verdict"], by[r["cal_id"]]["navigator"]["verdict"]) for r in rows
               if r["baseline"]["navigator"]["verdict"] != by[r["cal_id"]]["navigator"]["verdict"]]
    res["_informational"] = dict(rows_changed_verdict=len(changed), by_transition=dict(Counter(f"{a}->{b}" for *_, a, b in changed)))
    gating = [k for k in res if not k.startswith("_")]
    res["_decision"] = "ADVANCE" if all(res[k]["passed"] for k in gating) else "REJECT"
    res["_missing_criteria"] = [k for k in CRIT if k not in res]
    return res


# ------------------------------------------------------------------------------------ running
def make_checker(navigator, candidate_path):
    if not candidate_path:
        return navigator
    spec = importlib.util.spec_from_file_location("candidate_mod", candidate_path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m.build(navigator)


def run_rows(checker, vault, executor, rows, with_others=True):
    from kavach.schemas import ToolCall
    out = []
    for r in rows:
        tc = ToolCall.model_validate({"text": r["call"], "session_id": "experiment"})
        n = checker.check(tc)
        o = {"navigator": {"verdict": n.verdict, "confidence": n.confidence, "matched_id": n.matched_id}}
        if with_others:
            o["VAULT"], o["EXECUTOR"] = vault.check(tc).verdict, executor.check(tc).verdict
        out.append(o)
    return out


def main():
    from kavach.ministers.executor import ExecutorMinister
    from kavach.ministers.navigator import NavigatorMinister
    from kavach.ministers.vault import VaultMinister
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate")
    ap.add_argument("--chroma-path", type=Path)
    ap.add_argument("--sample", type=int, help="use only the first N calibration rows (smoke run; criteria are then NOT valid)")
    ap.add_argument("--out", type=Path, default=HERE / "experiment_result.json")
    ap.add_argument("--criteria", type=Path, default=HERE / "criteria.json",
                     help="pre-registered criteria file for THIS experiment (must exist and be unchanged since before the run)")
    a = ap.parse_args()

    global CRIT
    CRIT = json.loads(a.criteria.read_text())["criteria"]

    rows = [json.loads(l) for l in (HERE / "calibration_set.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    if a.sample:
        rows = rows[: a.sample]
    nav = NavigatorMinister(chroma_path=a.chroma_path)
    checker = make_checker(nav, a.candidate)
    vault, executor = VaultMinister(), ExecutorMinister()

    new = run_rows(checker, vault, executor, rows)
    k = CRIT["D1_deterministic"]["sample_size"]
    again = run_rows(checker, vault, executor, rows[:k], with_others=False)
    tol = CRIT["D1_deterministic"]["tolerance"]
    same = all(x["navigator"]["verdict"] == y["navigator"]["verdict"] and x["navigator"]["matched_id"] == y["navigator"]["matched_id"]
               and abs((x["navigator"]["confidence"] or 0) - (y["navigator"]["confidence"] or 0)) <= tol for x, y in zip(new, again))
    sys.path.insert(0, str(BASE))
    import regression_guard as G
    canary_old = [r for r in G.load_rows() if r["set"] == "canary_doc"]
    canary_new = run_rows(checker, vault, executor, [{"call": r["call"]} for r in canary_old], with_others=False)
    canary_new = [{"navigator": c["navigator"]} for c in canary_new]
    res = evaluate(rows, new, canary_old, canary_new, dict(passed=same, compared=len(again)))
    res["_run"] = {"candidate": a.candidate or "current working tree (identity unless NAVIGATOR was changed)",
                   "rows": len(rows), "full_set": not a.sample,
                   "calibration_set_sha256": __import__("hashlib").sha256((HERE / "calibration_set.jsonl").read_bytes()).hexdigest(),
                   "note": "Manipulation check on inspected, non-independent data. A pass authorises ONE reserved-split confirmation; it is not a performance result."}
    a.out.write_text(json.dumps(res, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    for k_, v in res.items():
        if k_.startswith("_"):
            continue
        print(f"{'PASS' if v['passed'] else 'FAIL'}  {k_}  " + json.dumps({x: y for x, y in v.items() if x not in ('passed', 'sets', 'lost', 'lost_ids', 'changed')}, default=str)[:170])
    print(f"DECISION: {res['_decision']}   (rows changed verdict: {res['_informational']['rows_changed_verdict']})")
    sys.exit(0 if res["_decision"] == "ADVANCE" and not a.sample else 1)


if __name__ == "__main__":
    main()

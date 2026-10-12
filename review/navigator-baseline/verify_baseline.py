#!/usr/bin/env python3
"""
Replay the frozen inputs through the CURRENT NAVIGATOR and compare with the frozen outputs.
Exit 0 only if nothing differs beyond tolerance and the regression-guard rules hold.

    python verify_baseline.py [--chroma-path DIR] [--sample-only] [--tolerance 0.01]

After a deliberate change, run it to see exactly what the change did; then freeze a NEW baseline id with
freeze_baseline.py. Never edit the old baseline files.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import regression_guard as G                                              # noqa: E402
from kavach.ministers.executor import ExecutorMinister                    # noqa: E402
from kavach.ministers.navigator import NavigatorMinister                  # noqa: E402
from kavach.ministers.vault import VaultMinister                          # noqa: E402
from kavach.schemas import ToolCall                                       # noqa: E402


def calls_for(rows):
    """The frozen rows carry their own call text; check it against the recorded hash. No Phase A file is opened."""
    import hashlib
    out = {}
    for r in rows:
        if hashlib.sha256(r["call"].encode("utf-8")).hexdigest() != r["call_sha256"]:
            raise SystemExit(f"frozen input {r['set']}:{r['id']} no longer matches its recorded hash")
        out[(r["set"], r["id"])] = r["call"]
    return out


def replay(nav, rows, calls, vault=None, executor=None):
    vault, executor = vault or VaultMinister(), executor or ExecutorMinister()
    new = []
    for r in rows:
        tc = ToolCall.model_validate({"text": calls[(r["set"], r["id"])], "session_id": "verify"})
        n = nav.check(tc)
        new.append({"set": r["set"], "id": r["id"],
                    "navigator": {"verdict": n.verdict, "confidence": n.confidence, "matched_id": n.matched_id, "matched_level": n.diagnostics.get("level")},
                    "other_ministers": {"VAULT": vault.check(tc).verdict, "EXECUTOR": executor.check(tc).verdict}})
    return new


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chroma-path", type=Path)
    ap.add_argument("--sample-only", action="store_true")
    ap.add_argument("--tolerance", type=float, default=0.01)
    a = ap.parse_args()
    rows = G.load_rows()
    if a.sample_only:
        rows = [r for r in rows if r["test_sample"] or r["set"] in ("wrapper_probe", "canary_doc")]
    calls = calls_for(rows)
    new = replay(NavigatorMinister(chroma_path=a.chroma_path), rows, calls)
    rep = G.compare(rows, new)
    diffs = [(o["set"], o["id"], o["navigator"]["verdict"], n["navigator"]["verdict"]) for o, n in zip(rows, new)
             if o["navigator"]["verdict"] != n["navigator"]["verdict"] or abs((o["navigator"]["confidence"] or 0) - (n["navigator"]["confidence"] or 0)) > a.tolerance]
    print(json.dumps({"compared": rep["compared"], "differences_vs_baseline": len(diffs), "first": diffs[:5],
                      "guard_violations": G.violations(rep), "benign": rep["benign"], "attack_catch": rep["attack_catch"]}, indent=1))
    sys.exit(1 if diffs or G.violations(rep) else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Build the calibration set for NAVIGATOR's first controlled experiment, and record what the CURRENT (unchanged)
NAVIGATOR returns on it.

Every item here has already been inspected or is a Phase A candidate. None is independent, none is held out, and
every label is the source's own meaning, UNVERIFIED. The Phase A reserved split is discarded unread (the Phase A
files hold both splits, so the script must open them once; reserved rows are dropped on sight and never counted).

    python build_calibration_set.py [--chroma-path DIR]

Writes calibration_set.jsonl (one self-contained row per distinct call, with the baseline NAVIGATOR/VAULT/EXECUTOR
outputs) and calibration_set_summary.json.
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.registry import datasets, load_examples                  # noqa: E402
from kavach.ministers.executor import ExecutorMinister                   # noqa: E402
from kavach.ministers.navigator import NavigatorMinister                 # noqa: E402
from kavach.ministers.vault import VaultMinister                         # noqa: E402
from kavach.schemas import ToolCall                                      # noqa: E402

SHELL_TOOLS = {"bash", "sh", "powershell", "command_prompt", "exec", "zsh", "cmd"}
CONTAMINATION = {
    "diagnosis_split": "inspected: used to diagnose NAVIGATOR (Phase A diagnosis split)",
    "pilot_seen": "inspected: the full MVP was run on these in the test-suite roadmap pilot",
    "development": "overlaps rule or corpus development (documented), or hand-written by the project",
}


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def norm(s):
    return re.sub(r"\s+", " ", s.lower()).strip()


def parse(call):
    m = re.match(r"tool:(\S+)\s+args:(\{.*\})\s*$", call.strip(), re.S)
    return (m.group(1), json.loads(m.group(2))) if m else (None, None)


def phase_a_diagnosis():
    pa = ROOT / "review" / "phase-a-candidates"
    out = []
    for fname, set_, role, label in (
        ("tldr_security_items.jsonl", "phase_a_tldr", "benign", "documented legitimate usage (unreviewed)"),
        ("swe_agent_items.jsonl", "phase_a_swe", "benign", "agent-generated, assumed benign (unreviewed)"),
        ("redcode_bash_items.jsonl", "phase_a_redcode", "attack", "risky by scenario design (unreviewed)"),
    ):
        for line in (pa / fname).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["split"] != "diagnosis" or r["duplicate_of"] is not None:
                continue                      # reserved and duplicate rows are dropped unread
            out.append((set_, r["item_id"], r["transformation"]["call"], role, label, "diagnosis_split"))
    return out


def batch1():
    out = []
    for line in (ROOT / "review" / "heldout-candidates-batch-1" / "review_items.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        caldera = r["source_dataset"].startswith("MITRE")
        out.append(("batch1_caldera" if caldera else "batch1_tldr", r["item_id"], r["transformed_call"],
                    "attack" if caldera else "benign", r["proposed_label_meaning"], "pilot_seen"))
    return out


def evaluation_sets():
    out = []
    by_id = {e["id"]: e for e in datasets() if e.get("runnable")}
    spec = {"kavach_pb_attack": ("attack", "malicious by construction (Atomic Red Team / GTFOBins conversion; unreviewed)"),
            "kavach_pb_bfcl_benign": ("benign", "generic function call, benign (unreviewed)"),
            "benign_traces": ("benign", "hand-written benign developer action (unreviewed)"),
            "real_benign_sessions": ("benign", "benign banking-agent call from one run (unreviewed)"),
            "atriumos": (None, "author-assigned ground truth (unreviewed)"),
            "openclaw_native": (None, "hand-written expectation (unreviewed)")}
    for eid, (role, meaning) in spec.items():
        for ex in load_examples(by_id[eid]):
            if eid == "atriumos" and len(ex.calls) != 1:
                continue                      # two-call sessions test CHANNEL, not a single-call NAVIGATOR input
            for k, call in enumerate(ex.calls):
                out.append((eid, ex.example_id if len(ex.calls) == 1 else f"{ex.example_id}#{k}", call,
                            role or ex.label, meaning, "development"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chroma-path", type=Path)
    a = ap.parse_args()

    # priority order decides which set keeps a call that appears in several sets
    cands = phase_a_diagnosis() + batch1() + evaluation_sets()
    seen, rows, dropped = {}, [], 0
    for set_, sid, call, role, meaning, cont in cands:
        tool, args = parse(call)
        key = norm(call)
        if key in seen:
            seen[key]["also_in"].append(f"{set_}:{sid}")
            dropped += 1
            continue
        shell = tool in SHELL_TOOLS
        row = {"cal_id": f"CAL-{len(rows) + 1:05d}", "set": set_, "source_id": sid, "call": call, "call_sha256": sha(call),
               "role": role, "label_status": "unverified_source_meaning", "label_meaning": meaning,
               "contamination": cont, "shape": "shell" if shell else "non_shell", "also_in": []}
        seen[key] = row
        rows.append(row)

    nav = NavigatorMinister(chroma_path=a.chroma_path)
    vault, executor = VaultMinister(), ExecutorMinister()
    for r in rows:
        tc = ToolCall.model_validate({"text": r["call"], "session_id": "calibration"})
        n = nav.check(tc)
        r["baseline"] = {"navigator": {"verdict": n.verdict, "confidence": n.confidence, "matched_id": n.matched_id},
                         "VAULT": vault.check(tc).verdict, "EXECUTOR": executor.check(tc).verdict}
    with open(HERE / "calibration_set.jsonl", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    def cnt(f):
        return dict(sorted(Counter(f(r) for r in rows).items()))
    summary = {
        "status": "calibration_set_for_a_manipulation_check_not_independent_not_held_out",
        "items": len(rows), "duplicates_merged": dropped,
        "by_set": cnt(lambda r: r["set"]), "by_role": cnt(lambda r: r["role"]), "by_shape": cnt(lambda r: f"{r['role']}/{r['shape']}"),
        "by_contamination": cnt(lambda r: r["contamination"]),
        "baseline_navigator_verdicts": cnt(lambda r: f"{r['role']}/{r['baseline']['navigator']['verdict']}"),
        "contamination_meanings": CONTAMINATION,
        "reserved_split": "not read for any result",
        "file_sha256": hashlib.sha256((HERE / "calibration_set.jsonl").read_bytes()).hexdigest(),
    }
    (HERE / "calibration_set_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()

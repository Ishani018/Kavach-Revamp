#!/usr/bin/env python3
"""
Freeze a reproducible baseline of NAVIGATOR as it is NOW.

Records exactly what was tested (code, corpus, model, library versions, thresholds, indexed documents,
embeddings fingerprint) and what it produced on a fixed set of inputs, so a future change can be compared
against it. It changes nothing in the MVP.

Data discipline
  * Phase A items are read ONLY if split == "diagnosis" and each is dropped at once otherwise; the reserved split
    is neither counted nor analysed.
  * The development sets (BFCL benign, Kavach-PB attack) are included as descriptive material; they overlap with
    rule development and are not independent.
  * The diagnosis data is NOT held out: it has been inspected and used to understand the problem.

    python freeze_baseline.py [--chroma-path DIR]

The Phase A files hold both splits in one file, so this script must read them to freeze the diagnosis rows; reserved rows
are discarded unread and never counted. After freezing, replaying the baseline needs no Phase A file at all.

Outputs (this folder):
    navigator_baseline.json         configuration, versions, hashes, summary
    navigator_baseline_items.jsonl  one row per input: what the unmodified minister returned
    navigator_baseline_docs.jsonl   the 300 indexed documents with hashes
"""
import argparse
import hashlib
import importlib.util
import json
import platform
import re
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

from kavach.ministers import navigator as nav_mod                      # noqa: E402
from kavach.ministers import retrieval as R                             # noqa: E402
from kavach.ministers.executor import ExecutorMinister                  # noqa: E402
from kavach.ministers.navigator import NavigatorMinister, QUERY_PREFIX, THRESHOLDS, TOP_K  # noqa: E402
from kavach.ministers.vault import VaultMinister                        # noqa: E402
from kavach.schemas import ToolCall                                     # noqa: E402

BASELINE_ID = "navigator-baseline-v1"
TEST_SAMPLE = {"diag_benign_tldr": 30, "diag_benign_swe": 20, "diag_attack_redcode": 40, "dev_benign_bfcl": 20, "dev_attack_pb": 30}
WRAPPER_PROBES = [("bash", ""), ("sh", ""), ("powershell", ""), ("command_prompt", ""), ("bash", "ls"), ("bash", "pwd"), ("bash", "echo hello")]


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def wire_cmd(tool, cmd):
    return f"tool:{tool} args:{json.dumps({'command': cmd})}"


def load_inputs():
    """(set, id, call) triples. Reserved Phase A items are discarded the moment they are read."""
    pa = ROOT / "review" / "phase-a-candidates"
    out = []
    for fname, key in (("tldr_security_items.jsonl", "diag_benign_tldr"), ("swe_agent_items.jsonl", "diag_benign_swe"),
                       ("redcode_bash_items.jsonl", "diag_attack_redcode")):
        for line in (pa / fname).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if r["split"] != "diagnosis" or r["duplicate_of"] is not None:
                continue
            out.append((key, r["item_id"], r["transformation"]["call"]))
            del r
    ev = ROOT / "evaluation" / "datasets"
    for k, v in json.loads((ev / "kavach_pb_bfcl_benign" / "_kavach_pb_bfcl_general_purpose_checkpoint.json").read_text()).items():
        out.append(("dev_benign_bfcl", k, v["call_text"]))
    for k, v in json.loads((ev / "kavach_pb_attack" / "_kavach_pb_attack_checkpoint.json").read_text()).items():
        out.append(("dev_attack_pb", k, v["call_text"]))
    return out


def explainer_module():
    spec = importlib.util.spec_from_file_location("diag", ROOT / "review" / "phase-a-candidates" / "diagnose_navigator.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def model_info():
    base = Path.home() / ".cache/huggingface/hub/models--BAAI--bge-base-en-v1.5/snapshots"
    snaps = sorted(p for p in base.glob("*") if p.is_dir()) if base.exists() else []
    info = {"name": nav_mod.EMBED_MODEL, "snapshot": None, "weights_file": None, "weights_sha256_from_blob_name": None}
    if snaps:
        snap = snaps[-1]
        w = snap / "model.safetensors"
        info["snapshot"] = snap.name
        if w.exists():
            info["weights_file"] = "model.safetensors"
            info["weights_sha256_from_blob_name"] = Path(w.resolve()).name
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chroma-path", type=Path, default=None)
    a = ap.parse_args()
    nav = NavigatorMinister(chroma_path=a.chroma_path)
    diag = explainer_module()
    ex = diag.Explainer(nav)
    vault, executor = VaultMinister(), ExecutorMinister()

    # ---- indexed documents -------------------------------------------------------------------------------
    order = sorted(range(len(ex.ids)), key=lambda i: ex.ids[i])
    docs = []
    for i in order:
        docs.append({"doc_id": ex.ids[i], "pattern_id": ex.pid[i], "level": ex.level[i], "category": ex.meta[i]["category"],
                     "text_sha256": sha256_text(ex.docs[i]), "text": ex.docs[i]})
    with open(HERE / "navigator_baseline_docs.jsonl", "w", encoding="utf-8") as fh:
        for d in docs:
            fh.write(json.dumps(d, ensure_ascii=False, sort_keys=True) + "\n")
    emb = np.round(ex.E[order], 5).astype("<f4")
    emb_fp = hashlib.sha256(emb.tobytes()).hexdigest()

    # ---- inputs and outputs of the unmodified minister ----------------------------------------------------
    inputs = load_inputs()
    inputs += [("wrapper_probe", f"{t}|{c!r}", wire_cmd(t, c)) for t, c in WRAPPER_PROBES]
    inputs += [("wrapper_probe", "read_file_empty", "tool:read_file args:{}"), ("wrapper_probe", "weather", 'tool:get_weather args:{"city": "Paris"}')]
    inputs += [("canary_doc", d["doc_id"], wire_cmd("bash", d["text"])) for d in docs]

    in_sample = set()
    for key, n in TEST_SAMPLE.items():
        ids = sorted((i for s, i, _ in inputs if s == key), key=lambda i: sha256_text("sample:" + key + i))[:n]
        in_sample.update({(key, i) for i in ids})

    rows, mism = [], 0
    for s, iid, call in inputs:
        tc = ToolCall.model_validate({"text": call, "session_id": "baseline"})
        r = nav.check(tc)
        e = ex.score(call, tokens_text=call)
        if abs(round(e["final"], 4) - (r.confidence or 0.0)) > 1e-3:
            mism += 1
        v = vault.check(tc)
        x = executor.check(tc)
        rows.append({
            "set": s, "id": iid, "call_sha256": sha256_text(call), "test_sample": (s, iid) in in_sample,
            "call": call,          # stored so the baseline replays without re-reading any Phase A file
            "navigator": {"verdict": r.verdict, "confidence": r.confidence, "matched_id": r.matched_id,
                          "matched_level": r.diagnostics.get("level")},
            "replica": {"final": round(e["final"], 4), "dense_selected": round(e["dense_sel"], 4), "gate": round(e["gate"], 4),
                        "selected_doc": ex.ids[e["best"]], "selected_doc_if_other_tie_order": ex.ids[e["best_alt_tiebreak"]],
                        "dense_top1": round(e["top1_sim"], 4)},
            "other_ministers": {"VAULT": v.verdict, "EXECUTOR": x.verdict},
        })
    with open(HERE / "navigator_baseline_items.jsonl", "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    # ---- summary -----------------------------------------------------------------------------------------------------
    by_set = {}
    for s in sorted({r["set"] for r in rows}):
        rs = [r for r in rows if r["set"] == s]
        by_set[s] = {"n": len(rs), "verdicts": dict(sorted(Counter(r["navigator"]["verdict"] for r in rs).items()))}
    canary = [r for r in rows if r["set"] == "canary_doc"]
    own = sum(1 for r in canary if r["navigator"]["verdict"] != "ALLOW" and r["navigator"]["matched_id"] == r["id"].split("_")[0])

    def fsha(rel):
        return sha256_file(ROOT / rel)

    pa_manifest = json.loads((ROOT / "review/phase-a-candidates/phase_a_manifest.json").read_text())
    cfg = {"thresholds": THRESHOLDS, "top_k": TOP_K, "gate_floor": R._GATE_FLOOR, "rrf_k": R._RRF_K,
           "query_prefix": QUERY_PREFIX, "embed_model": nav_mod.EMBED_MODEL,
           "wire_format_example": ToolCall(tool_name="bash", arguments={"command": "ls"}).to_wire_text(),
           "bm25_tokenizer_drops": ["tool", "args"], "bm25_tie_order": "np.argsort(scores)[::-1] over BM25 positions (ties ranked in reverse index order)"}
    out = {
        "baseline_id": BASELINE_ID,
        "status": "frozen_snapshot_of_current_behaviour_not_a_specification",
        "data_policy": "Phase A reserved split never read. Diagnosis data has been inspected and is NOT held out. dev_* sets overlap with rule development.",
        "mvp": {"git_head": ROOT and __import__("subprocess").run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
                "note": "The working tree contains uncommitted work; the file hashes below are what was actually tested.",
                "file_sha256": {rel: fsha(rel) for rel in ("kavach/ministers/navigator.py", "kavach/ministers/retrieval.py",
                                                          "kavach/data/kavach_corpus_v1.json", "kavach/schemas.py",
                                                          "kavach/ministers/vault.py", "kavach/ministers/executor.py",
                                                          "kavach/ministers/prefilters.py")}},
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "packages": {p: metadata.version(p) for p in ("sentence-transformers", "chromadb", "numpy", "rank-bm25", "torch", "transformers", "tokenizers", "chroma-hnswlib")}},
        "model": model_info(),
        "configuration": cfg,
        "corpus_and_index": {"patterns": len({d["pattern_id"] for d in docs}), "documents": len(docs),
                             "by_level": dict(Counter(d["level"] for d in docs)),
                             "collection_count": nav._collection.count(), "bm25_corpus_size": nav._bm25["bm25"].corpus_size,
                             "doc_ids_sha256": sha256_text("\n".join(d["doc_id"] for d in docs)),
                             "doc_texts_sha256": sha256_text("\n".join(d["text_sha256"] for d in docs)),
                             "embeddings_fingerprint": {"method": "sha256 of float32 embeddings rounded to 5 decimals, documents sorted by id", "sha256": emb_fp, "shape": list(emb.shape)}},
        "inputs": {"phase_a_manifest_sha256": fsha("review/phase-a-candidates/phase_a_manifest.json"),
                   "phase_a_files": {n: pa_manifest["files"][n] for n in ("redcode_bash_items.jsonl", "tldr_security_items.jsonl", "swe_agent_items.jsonl")},
                   "phase_a_split": {"salt": pa_manifest["config"]["split_salt"], "diagnosis_percent": pa_manifest["config"]["split_diagnosis_percent"]},
                   "evaluation_dataset_blobs": {rel: fsha(rel) for rel in ("evaluation/datasets/kavach_pb_bfcl_benign/_kavach_pb_bfcl_general_purpose_checkpoint.json",
                                                                          "evaluation/datasets/kavach_pb_attack/_kavach_pb_attack_checkpoint.json")},
                   "ids_sha256": sha256_text("\n".join(f"{r['set']}:{r['id']}:{r['call_sha256']}" for r in rows))},
        "diagnostic_results": {"navigator_diagnosis_results.json": fsha("review/phase-a-candidates/navigator_diagnosis_results.json"),
                               "navigator_diagnosis_items.jsonl": fsha("review/phase-a-candidates/navigator_diagnosis_items.jsonl")},
        "summary": {"by_set": by_set, "canary_docs_retrieving_own_pattern_at_or_above_grey": f"{own}/{len(canary)}",
                    "replica_vs_real_mismatches": mism, "test_sample_size": sum(1 for r in rows if r["test_sample"])},
        "files": {"navigator_baseline_items.jsonl": sha256_file(HERE / "navigator_baseline_items.jsonl"),
                  "navigator_baseline_docs.jsonl": sha256_file(HERE / "navigator_baseline_docs.jsonl")},
    }
    (HERE / "navigator_baseline.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(out["summary"], indent=1))


if __name__ == "__main__":
    main()

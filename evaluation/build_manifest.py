#!/usr/bin/env python3
"""
Build evaluation/manifest.json from evaluation/registry.json and the dataset files.

Everything countable is computed here, not typed by hand: example counts, label
breakdown, unique counts, duplicate counts, cross-dataset exact overlap, and whether
each local copy is byte-identical to its recorded source (git blob SHA-1).
Curated fields (role, provenance, licence, overlap with rule development) are copied
from the registry unchanged. The output is deterministic (no timestamps).

    python -m evaluation.build_manifest           # write evaluation/manifest.json
    python -m evaluation.build_manifest --check   # exit 1 if the committed manifest is stale
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List

from .registry import MANIFEST_PATH, ROOT, datasets, load_examples, load_registry


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def dataset_stats(entry: Dict[str, Any]) -> Dict[str, Any]:
    ex = load_examples(entry)
    labels = Counter(e.label for e in ex)
    uniq = {}
    for e in ex:
        uniq.setdefault((e.label, e.unique_key), 0)
        uniq[(e.label, e.unique_key)] += 1
    per_label = {}
    for lab in sorted(labels):
        keys = [k for (l, k) in uniq if l == lab]
        n = labels[lab]
        per_label[lab] = {"examples": n, "unique": len(keys), "duplicates": n - len(keys)}
    all_keys = {e.unique_key for e in ex}
    # unique keys that appear under both labels inside this dataset
    by_key = defaultdict(set)
    for e in ex:
        by_key[e.unique_key].add(e.label)
    return {
        "examples": len(ex),
        "unique": len(all_keys),
        "duplicates": len(ex) - len(all_keys),
        "labels": per_label,
        "label_conflicts_within_dataset": sum(1 for v in by_key.values() if len(v) > 1),
        "calls": sum(len(e.calls) for e in ex),
        "multi_call_sessions": sum(1 for e in ex if len(e.calls) > 1),
        "sendable_examples": sum(1 for e in ex if e.calls),
        "context": {
            "examples_with_any_context": sum(1 for e in ex if any(e.contexts)),
            "examples_without_context": sum(1 for e in ex if e.calls and not any(e.contexts)),
            "examples_with_user_instruction": sum(1 for e in ex if "user_instruction" in e.context_fields()),
            "examples_with_tool_output": sum(1 for e in ex if "tool_output" in e.context_fields()),
            "examples_with_account_email": sum(1 for e in ex if "account_email" in e.context_fields()),
            "unique_including_context": len({(e.unique_key, e.context_fingerprint()) for e in ex}),
        },
    }


def test_suites() -> List[Dict[str, Any]]:
    out = []
    for p in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        n = sum(1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))
        out.append({"path": f"tests/{p.name}", "test_functions": n,
                    "role": "unit_test_fixture",
                    "note": "pytest-collected" if n else "script-style: run with `python -m tests.%s`" % p.stem})
    return out


def build() -> Dict[str, Any]:
    reg = load_registry()
    entries = []
    examples_by_ds = {}
    for e in datasets(reg):
        rec = {k: v for k, v in e.items()}
        if "format" in e:  # has a local copy and a loader
            path = ROOT / e["path"]
            data = path.read_bytes()
            rec["local_file"] = {
                "path": e["path"],
                "bytes": len(data),
                "git_blob_sha1": git_blob_sha1(data),
                "identical_to_recorded_source": git_blob_sha1(data) == e["source"]["git_blob_sha1"],
            }
            rec["stats"] = dataset_stats(e)
            examples_by_ds[e["id"]] = load_examples(e)
        entries.append(rec)

    # exact overlap between datasets that have sendable calls
    overlap: Dict[str, Dict[str, Any]] = {}
    keys = {d: {e.unique_key: e.label for e in ex if e.calls} for d, ex in examples_by_ds.items()}
    ids = sorted(keys)
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            shared = set(keys[a]) & set(keys[b])
            if shared:
                overlap[f"{a} <-> {b}"] = {
                    "shared_unique_examples": len(shared),
                    "label_disagreements": sum(1 for k in shared if keys[a][k] != keys[b][k]),
                }
    # overlap at the level of individual calls (sessions can share calls without sharing a whole sequence)
    call_sets = {d: {c for e in ex for c in e.calls} for d, ex in examples_by_ds.items()}
    call_overlap: Dict[str, int] = {}
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            n = len(call_sets[a] & call_sets[b])
            if n:
                call_overlap[f"{a} <-> {b}"] = n
    held_out = [e["id"] for e in entries if e.get("role") == "held_out_evaluation"]
    verified = [e["id"] for e in entries if e.get("held_out_status") == "verified_held_out"]
    return {
        "schema_version": 1,
        "registry_sha256": hashlib.sha256((ROOT / "evaluation" / "registry.json").read_bytes()).hexdigest(),
        "pinned_source": reg["pinned_source"],
        "role_definitions": reg["role_definitions"],
        "held_out_datasets": held_out,
        "datasets_verified_held_out": verified,
        "held_out_summary": "NONE. No registered dataset is verified as held out from rule/corpus/threshold development. All runnable datasets are development or author-written data; results on them are smoke tests.",
        "datasets": entries,
        "unit_test_suites": test_suites(),
        "cross_dataset_exact_overlap": overlap,
        "cross_dataset_shared_individual_calls": call_overlap,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the committed manifest is out of date")
    args = ap.parse_args(argv)
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        current = MANIFEST_PATH.read_text(encoding="utf-8") if MANIFEST_PATH.exists() else ""
        if current != text:
            print("evaluation/manifest.json is out of date; run: python -m evaluation.build_manifest", file=sys.stderr)
            return 1
        print("manifest is up to date")
        return 0
    MANIFEST_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {MANIFEST_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

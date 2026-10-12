#!/usr/bin/env python3
"""Checks that candidate_triage.jsonl is complete, bound to the unchanged originals, and honest about its status."""
import hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
items = {json.loads(l)["item_id"]: json.loads(l) for l in (HERE / "review_items.jsonl").read_text(encoding="utf-8").splitlines()}
rows = [json.loads(l) for l in (HERE / "candidate_triage.jsonl").read_text(encoding="utf-8").splitlines()]
summary = json.loads((HERE / "candidate_triage_summary.json").read_text())
sha = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()
bad = []
chk = lambda c, m: bad.append(m) if not c else None

chk(len(rows) == 256 and {r["item_id"] for r in rows} == set(items), "triage does not cover exactly the 256 items")
chk(summary["input_sha256"]["review_items.jsonl"] == hashlib.sha256((HERE / "review_items.jsonl").read_bytes()).hexdigest(), "review_items.jsonl changed since triage")
for r in rows:
    i = items[r["item_id"]]
    sid = r["item_id"]
    chk(r["source"]["original_command_sha256"] == sha(i["original_command"]), f"{sid}: original command changed")
    chk(r["source"]["transformed_call_sha256"] == sha(i["transformed_call"]), f"{sid}: transformed call changed")
    chk(r["source"]["source_label_meaning"] == i["proposed_label_meaning"], f"{sid}: source label meaning altered")
    chk(r["status"] == r["proposed_classification"]["status"] == r["mvp_test_value"]["status"] == r["triage"]["status"] == "automated_proposal_not_verified", f"{sid}: missing unverified status")
    chk(not any(k in r for k in ("verified_label", "ground_truth", "label")), f"{sid}: looks like a ground-truth field")
    p = r["proposed_classification"]
    chk(p["label"] in {"likely_malicious", "likely_benign", "dual_use"}, f"{sid}: label value")
    chk(p["confidence"] in {"high", "medium", "low"} and p["rationale"].strip(), f"{sid}: confidence/rationale")
    chk(isinstance(p["unresolved_concerns"], list), f"{sid}: concerns")
    chk(r["triage"]["decision"] in {"retain", "exclude", "further_review"} and r["triage"]["reason"].strip(), f"{sid}: decision/reason")
    chk((r["triage"]["tier"] is not None) == (r["triage"]["decision"] == "retain"), f"{sid}: tier/decision mismatch")
    chk(r["mvp_test_value"]["minister_tests"]["CHANNEL"] == "not_testable_standalone", f"{sid}: CHANNEL must not be marked testable")
    chk(p["label"] != "likely_malicious" or r["source"]["dataset"].startswith("MITRE"), f"{sid}: documented-legitimate source auto-labelled malicious")
if bad:
    print("FAILED"); [print(" -", b) for b in bad[:25]]; sys.exit(1)
print("OK: 256 records; originals bound by SHA-256; every classification marked unverified; CHANNEL never marked testable")

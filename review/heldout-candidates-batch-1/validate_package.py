#!/usr/bin/env python3
"""
Consistency checks for the review package. Reads the package only; judges no label.

    python validate_package.py
Exit code 0 if every check passes.
"""
import csv, hashlib, json, re, sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVIEWER_FIELDS = ["first_impression_from_command_only", "verified_label", "agent_security_relevance", "rationale",
                   "uncertainty", "uncertainty_notes", "dual_use_notes", "exclude_reason", "needs_second_opinion",
                   "reviewer_id", "review_date"]
# Words that would indicate a detector output leaked into the reviewer-facing files.
LEAK = re.compile(r"\b(BLOCK|ESCALATE|ALLOW)\b|parliament|minister|navigator|speaker|\bpilot\b|detector (said|output|result)", re.I if False else 0)
LEAK_I = re.compile(r"parliament|minister|navigator|speaker|\bpilot\b", re.I)
failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    items = [json.loads(l) for l in (HERE / "review_items.jsonl").read_text(encoding="utf-8").splitlines()]
    rows = list(csv.DictReader(open(HERE / "review_sheet.csv", encoding="utf-8", newline="")))
    manifest = json.loads((HERE / "batch_manifest.json").read_text())
    sel = json.loads((HERE / "selection_ids.json").read_text())

    check(len(items) == 256 and len(rows) == 256, f"expected 256 items, got {len(items)} / {len(rows)}")
    check(len({i["item_id"] for i in items}) == 256, "item_id not unique")
    check(len({(i["source_dataset"], i["source_item_id"]) for i in items}) == 256, "source items not unique")
    check(Counter(i["source_dataset"] for i in items) == Counter({"tldr-pages": 150, "MITRE Caldera stockpile plugin": 106}), "source counts differ from the plan")
    check({i["source_item_id"] for i in items if i["source_dataset"] == "tldr-pages"} == set(sel["tldr_pages"]), "tldr selection mismatch")
    check({i["source_item_id"] for i in items if i["source_dataset"].startswith("MITRE")} == set(sel["caldera_stockpile"]), "Caldera selection mismatch")
    check(all(r == {k: v for k, v in i.items()} for r, i in zip(rows, items)), "CSV and JSONL differ")

    for i in items:
        sid = i["item_id"]
        args = json.loads(i["transformed_args_json"])
        check(i["transformed_call"] == f"tool:{i['transformed_tool']} args:{i['transformed_args_json']}", f"{sid}: call does not match its parts")
        if i["source_dataset"] == "tldr-pages":
            check(args["command"] == re.sub(r"\{\{(.*?)\}\}", r"\1", i["original_command"]), f"{sid}: tldr transformation not reproducible")
            check(i["transformed_tool"] == "bash", f"{sid}: unexpected tool")
        else:
            check(args["command"] == i["original_command"].strip(), f"{sid}: Caldera transformation not reproducible")
            check(i["transformed_tool"] in {"sh", "powershell", "command_prompt"}, f"{sid}: unexpected tool")
        check(re.fullmatch(r"[0-9a-f]{40}", i["pinned_version"]) and re.fullmatch(r"[0-9a-f]{40}", i["source_file_git_blob"]), f"{sid}: bad version/blob")
        check(i["source_permalink"].startswith(i["source_repo"]) and i["pinned_version"] in i["source_permalink"], f"{sid}: permalink")
        check("unreviewed" in i["proposed_label_meaning"], f"{sid}: label meaning must say unreviewed")
        check(all(i[f] == "" for f in REVIEWER_FIELDS), f"{sid}: reviewer field already filled")
        gen = json.dumps({k: v for k, v in i.items() if k in ('proposed_label_meaning', 'transformation', 'prep_flags', 'licence')})
        check(not LEAK.search(gen) and not LEAK_I.search(gen), f"{sid}: possible detector wording in a generated column")

    readme = (HERE / "README.md").read_text(encoding="utf-8")
    # The README is allowed to tell reviewers NOT to look at detector output; it must not contain any.
    check(not re.search(r"\b(BLOCK|ESCALATE|ALLOW)\b|\bpilot\b", readme), "README contains verdict wording or results")
    check(manifest["held_out_status"] == "not_verified" and manifest["in_evaluation_registry"] is False, "manifest status")
    for name, digest in manifest["files"].items():
        check(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest, f"{name}: checksum differs from manifest")

    if failures:
        print("FAILED"); [print(" -", f) for f in failures[:30]]; return 1
    print("OK: 256 items; sources 106 + 150; transformations reproducible; reviewer fields blank; no detector wording; checksums match")
    return 0


if __name__ == "__main__":
    sys.exit(main())

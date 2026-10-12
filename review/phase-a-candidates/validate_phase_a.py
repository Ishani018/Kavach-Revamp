#!/usr/bin/env python3
"""Consistency checks for the Phase A candidate files. Reads only; judges no label; executes nothing."""
import hashlib, json, re, sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sha = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()
rd = lambda n: [json.loads(l) for l in (HERE / n).read_text(encoding="utf-8").splitlines() if l.strip()]
man = json.loads((HERE / "phase_a_manifest.json").read_text())
red, tl, swe = rd("redcode_bash_items.jsonl"), rd("tldr_security_items.jsonl"), rd("swe_agent_items.jsonl")
hints = {h["item_id"]: h for h in rd("phase_a_hints.jsonl")}
bad = []
chk = lambda c, m: bad.append(m) if not c else None

chk(len(red) == 600, f"RedCode must have 600 scripts, has {len(red)}")
chk(len(tl) == 200, f"tldr sample expected 200, has {len(tl)}")
chk(len(swe) == 786, f"SWE-agent expected 786, has {len(swe)}")
allitems = red + tl + swe
chk(len({i["item_id"] for i in allitems}) == len(allitems), "item_id not unique")
chk(set(hints) == {i["item_id"] for i in allitems}, "hints do not cover exactly the items")
chk(len({i["source"]["source_item_id"] for i in red}) == 600, "RedCode ids not unique")
chk(len({i["source"]["source_item_id"] for i in tl}) == 200, "tldr ids not unique")
chk(len({i["source"]["source_item_id"] for i in swe}) == 786, "SWE ids not unique")

by_id = {i["item_id"]: i for i in allitems}
for it in allitems:
    s, t, sid = it["source"], it["transformation"], it["item_id"]
    chk(re.fullmatch(r"[0-9a-f]{40}", s["pinned_version"]) and s["licence"] and s["licence_url"].startswith("https://"), f"{sid}: provenance incomplete")
    chk(t["call"] == f"tool:{t['tool']} args:{t['args_json']}" and json.loads(t["args_json"])["command"] == it["command"], f"{sid}: call does not match command")
    chk(it["call_sha256"] == sha(t["call"]), f"{sid}: call hash")
    chk(it["original_sha256"] == sha(json.dumps(it["original"], sort_keys=True, ensure_ascii=False)), f"{sid}: original hash")
    chk(it["label"]["status"] == "unreviewed" and "unreviewed" in it["label"]["source_label_meaning"], f"{sid}: label must be marked unreviewed")
    chk(it["batch"] == "phase-a" and it["split"] in ("diagnosis", "reserved"), f"{sid}: batch/split")
    chk(not any(k in it for k in ("verified_label", "ground_truth", "held_out")), f"{sid}: ground-truth-like field")
    d = it["duplicate_of"]
    chk((d is not None) == ("duplicate_in_source" in it["flags"]), f"{sid}: duplicate flag mismatch")
    if d:
        chk(d["item_id"] in by_id and by_id[d["item_id"]]["split"] == it["split"], f"{sid}: duplicate must share its representative's split")
        chk(by_id[d["item_id"]]["duplicate_of"] is None, f"{sid}: representative is itself a duplicate")
    chk((it["overlap_with_data_we_hold"] is not None) == ("overlaps_data_we_hold" in it["flags"]), f"{sid}: overlap flag mismatch")

for it in red:
    c = it["original"]["Code"]
    chk(it["command"] == c, f"{it['item_id']}: RedCode command differs from the original Code field")
    chk(("multi_line" in it["flags"]) == ("\n" in c.strip()), f"{it['item_id']}: multi_line flag")
for it in tl:
    o = it["original"]["command"]
    chk(it["command"] == re.sub(r"\{\{(.*?)\}\}", r"\1", o), f"{it['item_id']}: tldr transformation not reproducible")
    chk(("placeholders_replaced" in it["flags"]) == ("{{" in o), f"{it['item_id']}: placeholder flag")
    chk(not {"option_syntax_not_literal", "contains_ellipsis"} & set(it["flags"]), f"{it['item_id']}: fragment slipped into the sample")
for it in swe:
    chk(it["original"]["command"] == it["command"] and "\n" not in it["command"], f"{it['item_id']}: SWE command")
    chk(it["command"].split()[0] not in man["config"]["swe_builtins"], f"{it['item_id']}: built-in command in sample")

chk(man["held_out_status"] == "not_verified" and man["in_evaluation_registry"] is False and not man["executed_any_example"] and not man["ran_kavach_mvp"], "manifest status")
for n, d in man["files"].items():
    chk(sha((HERE / n).read_text(encoding="utf-8")) == d, f"{n}: checksum differs from manifest")

if bad:
    print("FAILED"); [print(" -", b) for b in bad[:25]]; sys.exit(1)
sp = Counter(i["split"] for i in allitems)
print(f"OK: {len(allitems)} items (600 + 200 + 786); provenance complete; originals bound by hash; labels unreviewed; "
      f"duplicates share splits; split diagnosis={sp['diagnosis']} reserved={sp['reserved']}; checksums match")

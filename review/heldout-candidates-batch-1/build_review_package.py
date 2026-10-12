#!/usr/bin/env python3
"""
Build the human-review package for the first held-out candidate batch.

Inputs: selection_ids.json (the selected source items) and local checkouts of the two source
repositories at the pinned commits. Nothing is modified in the sources, and the original
command of every item is carried through unchanged; the transformed command is derived from it
by the stated rule.

    python build_review_package.py --stockpile PATH --tldr PATH [--out DIR]
"""
import argparse, csv, hashlib, json, random, re, subprocess, sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
STOCKPILE = {"name": "MITRE Caldera stockpile plugin", "repo": "https://github.com/mitre/stockpile",
             "commit": "996ec41cd1c5d1c7cc09e620fc55dabe5aefd9cc", "licence": "Apache-2.0", "licence_path": "LICENSE"}
TLDR = {"name": "tldr-pages", "repo": "https://github.com/tldr-pages/tldr",
        "commit": "3b04259a58d0bfecaa31c3179b3d349a81ef7893", "licence": "CC BY 4.0", "licence_path": "LICENSE.md"}
SHUFFLE_SEED = 20261012

TOOL_BY_EXECUTOR = {"sh": "sh", "psh": "powershell", "pwsh": "powershell", "psh,pwsh": "powershell",
                    "pwsh,psh": "powershell", "cmd": "command_prompt", "cmd,psh": "command_prompt",
                    "psh,cmd": "powershell"}
CALDERA_MEANING = ("attack_emulation_action (unreviewed): a command from a MITRE Caldera adversary-emulation ability "
                   "in the tactic '{tactic}'. It does not by itself prove the command is malicious in every context.")
TLDR_MEANING = ("documented_legitimate_usage (unreviewed): an example from the tldr-pages community cheat sheet for "
                "'{page}'. It does not by itself prove the command is harmless in every context.")
CALDERA_RULE = ("tool from executor ({executor} -> '{tool}'; first listed executor wins); arguments {{\"command\": <original command with "
                "leading/trailing whitespace trimmed>}}; Caldera #{{...}} variables left literal; multi-line kept as is")
TLDR_RULE = ("tool 'bash'; arguments {\"command\": <original command with each {{placeholder}} replaced by its inner text>}")


def run(*a, cwd=None):
    return subprocess.run(a, cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def blob_sha(repo, commit, path):
    return run("git", "rev-parse", f"{commit}:{path}", cwd=repo)


def wire(tool, command):
    return f"tool:{tool} args:{json.dumps({'command': command})}", json.dumps({"command": command})


def caldera_items(repo, ids):
    abilities = {}
    for f in sorted((repo / "data" / "abilities").glob("*/*.yml")):
        docs = yaml.safe_load(f.read_text(encoding="utf-8"))
        for a in (docs if isinstance(docs, list) else [docs]):
            abilities[a["id"]] = (a, f.relative_to(repo).as_posix())
    out = []
    for key in ids:
        aid, platform, executor = key.split("|")
        a, path = abilities[aid]
        spec = a["platforms"][platform][executor]
        original = spec["command"]                      # exactly as parsed from the YAML block scalar
        tool = TOOL_BY_EXECUTOR[executor]
        call, args_json = wire(tool, original.strip())
        tech = a.get("technique") or {}
        flags = []
        if "#{" in original: flags.append("unresolved_runtime_variable")
        if "\n" in original.strip(): flags.append("multi_line")
        if "," in executor: flags.append("executor_chosen_among_several")
        if "," in platform: flags.append("platform_list")
        if spec.get("payloads") or a.get("payloads"): flags.append("needs_payload_file")
        if len(original) > 1500: flags.append("very_long")
        out.append(dict(
            source_dataset=STOCKPILE["name"], source_item_id=key, source_file=path,
            source_file_git_blob=blob_sha(repo, STOCKPILE["commit"], path),
            source_permalink=f"{STOCKPILE['repo']}/blob/{STOCKPILE['commit']}/{path}",
            source_location=f"ability {aid}: platforms.{platform}.{executor}.command",
            original_command=original, transformed_tool=tool, transformed_args_json=args_json, transformed_call=call,
            transformation=CALDERA_RULE.format(executor=executor, tool=tool),
            proposed_label_meaning=CALDERA_MEANING.format(tactic=a.get("tactic")),
            prep_flags=";".join(flags),
            ctx_name=a.get("name", ""), ctx_description=(a.get("description") or "").strip(),
            ctx_tactic=a.get("tactic", ""), ctx_technique_id=tech.get("attack_id", ""), ctx_technique_name=tech.get("name", ""),
            ctx_platform=platform, ctx_executor=executor,
            ctx_extra=json.dumps({k: a[k] for k in ("privilege", "requirements", "repeatable", "singleton") if k in a}, sort_keys=True)
            + (" payloads=" + json.dumps(spec.get("payloads") or a.get("payloads")) if (spec.get("payloads") or a.get("payloads")) else ""),
        ))
    return out


def tldr_items(repo, ids):
    out = []
    for key in ids:
        plat_page, n = key.rsplit("#", 1)
        plat, page = plat_page.split("/", 1)
        path = f"pages/{plat}/{page}.md"
        count, desc, found = 0, None, None
        for ln, line in enumerate((repo / path).read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("- "):
                desc = line[2:].rstrip(":")
            elif line.startswith("`") and line.endswith("`") and len(line) > 2:
                count += 1
                if count == int(n):
                    found = (ln, line[1:-1], desc)
                    break
        if found is None:
            raise SystemExit(f"cannot locate {key}")
        ln, original, desc = found
        transformed = re.sub(r"\{\{(.*?)\}\}", r"\1", original)
        call, args_json = wire("bash", transformed)
        flags = []
        if "{{" in original: flags.append("placeholders_replaced")
        if re.search(r"\[-[^\]]*\|[^\]]*\]|\[--", original): flags.append("option_syntax_not_literal")
        if "..." in original: flags.append("contains_ellipsis")
        if plat == "common": flags.append("shell_unspecified")
        out.append(dict(
            source_dataset=TLDR["name"], source_item_id=key, source_file=path,
            source_file_git_blob=blob_sha(repo, TLDR["commit"], path),
            source_permalink=f"{TLDR['repo']}/blob/{TLDR['commit']}/{path}?plain=1#L{ln}",
            source_location=f"line {ln}", original_command=original, transformed_tool="bash",
            transformed_args_json=args_json, transformed_call=call, transformation=TLDR_RULE,
            proposed_label_meaning=TLDR_MEANING.format(page=page), prep_flags=";".join(flags),
            ctx_name=page, ctx_description=desc or "", ctx_tactic="", ctx_technique_id="", ctx_technique_name="",
            ctx_platform=plat, ctx_executor="", ctx_extra="",
        ))
    return out


REVIEWER_FIELDS = ["first_impression_from_command_only", "verified_label", "agent_security_relevance", "rationale",
                   "uncertainty", "uncertainty_notes", "dual_use_notes", "exclude_reason", "needs_second_opinion",
                   "reviewer_id", "review_date"]
COLUMNS = ["item_id", "source_dataset", "source_repo", "pinned_version", "source_item_id", "source_file", "source_file_git_blob",
           "source_location", "source_permalink", "licence", "licence_url", "original_command", "transformation",
           "transformed_tool", "transformed_args_json", "transformed_call", "proposed_label_meaning", "prep_flags",
           "ctx_name", "ctx_description", "ctx_tactic", "ctx_technique_id", "ctx_technique_name", "ctx_platform",
           "ctx_executor", "ctx_extra"] + REVIEWER_FIELDS


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_manifest(out, items):
    from collections import Counter
    flags = Counter()
    for it in items:
        for f in (it["prep_flags"].split(";") if it["prep_flags"] else ["(none)"]):
            flags[(it["source_dataset"], f)] += 1
    manifest = {
        "batch_id": "heldout-candidates-batch-1",
        "status": "candidate_unreviewed",
        "held_out_status": "not_verified",
        "in_evaluation_registry": False,
        "do_not_use_for": "any detection, precision, recall, false-positive or accuracy claim, until labels and independence are reviewed",
        "reviewer_blind": "reviewer-facing files contain no output of any detector",
        "plan": "docs/heldout-dataset-plan.md",
        "sources": [dict(STOCKPILE, selected=sum(1 for i in items if i["source_dataset"] == STOCKPILE["name"]),
                         label_meaning="attack_emulation_action (unreviewed)"),
                    dict(TLDR, selected=sum(1 for i in items if i["source_dataset"] == TLDR["name"]),
                         label_meaning="documented_legitimate_usage (unreviewed)")],
        "total_items": len(items),
        "shuffle_seed": SHUFFLE_SEED,
        "item_id_scheme": "HC1-<position in the shuffled order>; the original id is in source_item_id",
        "preparation_flag_counts": {f"{k[0]} :: {k[1]}": v for k, v in sorted(flags.items())},
        "files": {n: sha256(out / n) for n in ("review_sheet.csv", "review_items.jsonl", "selection_ids.json")},
    }
    (out / "batch_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stockpile", required=True, type=Path)
    ap.add_argument("--tldr", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=HERE)
    args = ap.parse_args()
    for repo, meta in ((args.stockpile, STOCKPILE), (args.tldr, TLDR)):
        head = run("git", "rev-parse", "HEAD", cwd=repo)
        if head != meta["commit"]:
            sys.exit(f"{meta['name']}: checkout is at {head}, expected pinned {meta['commit']}")
    sel = json.loads((HERE / "selection_ids.json").read_text())
    items = caldera_items(args.stockpile, sel["caldera_stockpile"]) + tldr_items(args.tldr, sel["tldr_pages"])
    random.Random(SHUFFLE_SEED).shuffle(items)
    for i, it in enumerate(items, 1):
        meta = STOCKPILE if it["source_dataset"] == STOCKPILE["name"] else TLDR
        it.update(item_id=f"HC1-{i:04d}", source_repo=meta["repo"], pinned_version=meta["commit"],
                  licence=meta["licence"], licence_url=f"{meta['repo']}/blob/{meta['commit']}/{meta['licence_path']}")
        for f in REVIEWER_FIELDS:
            it[f] = ""
    with open(args.out / "review_sheet.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for it in items:
            w.writerow({c: it[c] for c in COLUMNS})
    with open(args.out / "review_items.jsonl", "w", encoding="utf-8") as fh:
        for it in items:
            fh.write(json.dumps({c: it[c] for c in COLUMNS}, ensure_ascii=False, sort_keys=True) + "\n")
    write_manifest(args.out, items)
    print(f"wrote {len(items)} items")


if __name__ == "__main__":
    main()

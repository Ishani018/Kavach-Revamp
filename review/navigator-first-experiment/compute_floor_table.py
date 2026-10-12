#!/usr/bin/env python3
"""
Step 0 of NAVIGATOR experiment H1c (docs/navigator-experiment-h1c.md): measure, once and deterministically, how much
of NAVIGATOR's score each tool's own empty wrapper contributes on its own, with no argument content.

This is NOT a fit to calibration outcomes: no label, no calibration row and no calibration result is read here. The
only inputs are the unchanged NAVIGATOR corpus/embeddings and a fixed canonical "empty" payload per tool name
(`docs/navigator-experiment-h1c.md` Step 0). It uses the live, unmodified `run_minister_hybrid` — the same scoring
function NAVIGATOR uses today — so this script does not need, and must not gain, any new scoring logic of its own.

    python compute_floor_table.py --tool-names bash,sh,powershell,... [--chroma-path DIR] [--out floor_table.json]

Writes floor_table.json: {"bash": 0.xxx, ...}. This script is authored as part of the H1c protocol but is NOT run as
part of preparing that document; floor_table.json does not exist until someone explicitly runs this.
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

SHELL_TOOLS = {"bash", "sh", "powershell", "command_prompt", "exec", "zsh", "cmd"}

DEFAULT_TOOLS = sorted(SHELL_TOOLS | {
    # non-shell tool names already present in the calibration set's `by_set` sources (kavach_pb_bfcl_benign,
    # atriumos, openclaw_native, kavach_pb_attack non_shell rows); kept as a fixed, documented list rather than
    # discovered from calibration rows at run time, so the floor table does not depend on reading calibration data.
    "read_file", "write_file", "list_directory", "search_files", "http_request",
    "send_email", "query_database", "delete_file", "move_file", "create_calendar_event",
})


def canonical_text(tool: str) -> str:
    args = {"command": ""} if tool in SHELL_TOOLS else {}
    return f"tool:{tool} args:{json.dumps(args)}"


def main():
    from kavach.ministers import navigator as navmod
    from kavach.ministers.navigator import NavigatorMinister
    from kavach.ministers.retrieval import run_minister_hybrid

    ap = argparse.ArgumentParser()
    ap.add_argument("--tool-names", default=",".join(DEFAULT_TOOLS))
    ap.add_argument("--chroma-path", type=Path)
    ap.add_argument("--out", type=Path, default=HERE / "floor_table.json")
    a = ap.parse_args()

    nav = NavigatorMinister(chroma_path=a.chroma_path)
    table = {}
    for tool in sorted(set(a.tool_names.split(","))):
        text = canonical_text(tool)
        scan = run_minister_hybrid("NAVIGATOR", text, nav._collection, nav._bm25, nav._embed_query, dict(navmod.THRESHOLDS), navmod.TOP_K)
        table[tool] = round(float(scan.confidence), 6)

    a.out.write_text(json.dumps({"_method": "docs/navigator-experiment-h1c.md Step 0; no calibration labels or outcomes read",
                                 "_canonical_text_rule": "shell tools: tool:T args:{'command': ''}; others: tool:T args:{}",
                                 "floor": table}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(table, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

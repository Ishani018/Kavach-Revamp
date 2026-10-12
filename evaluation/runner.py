#!/usr/bin/env python3
"""
Reproducible smoke-evaluation runner for the Kavach MVP.

Sends the registered, labelled examples through the real MVP coordinator (VAULT,
EXECUTOR, CHANNEL, NAVIGATOR + Speaker) and reports BLOCK, ESCALATE, ALLOW (and
ERROR) separately for attack and benign examples, with sample and unique counts.

What the output is NOT: every registered dataset overlaps with rule/corpus
development or was written by the rule authors, and none is verified as held out,
so every result is labelled SMOKE TEST. The runner prints no recall, FPR or accuracy
headline, and never merges ESCALATE into ALLOW or into "detected". A result is only
labelled "held-out evaluation" if the registry marks the dataset `verified_held_out`,
which no dataset currently is.

    python -m evaluation.runner --list
    python -m evaluation.runner                          # all runnable datasets
    python -m evaluation.runner --datasets atriumos,openclaw_native --json out.json
    python -m evaluation.runner --context none           # ignore any context the datasets carry

Context: the MVP reads `user_instruction`, `tool_output` and `account_email` from the request's
`context` (only CHANNEL uses them). With `--context auto` (default) the runner sends exactly the
context a dataset itself carries and nothing else; with `--context none` it sends none. Missing
context is never invented, and every report says which examples had context and which did not.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .loaders import Example
from .registry import HELD_OUT_VERIFIED, ROOT, datasets, load_examples, load_registry

VERDICTS = ("BLOCK", "ESCALATE", "ALLOW")
SEVERITY = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}
SMOKE_DISCLAIMER = (
    "SMOKE TEST. This dataset overlaps with, or was written by the people who developed, "
    "the rules/corpus/thresholds, and is not verified as held out. These counts show that the "
    "MVP runs on this data and how it behaves; they are not a measure of generalization, "
    "precision, recall, false-positive rate or real-world accuracy."
)
HELD_OUT_NOTE = "Registry marks this dataset as verified held out (see evaluation/README.md for the evidence required)."


def evaluation_kind(entry: Dict[str, Any]) -> str:
    return "held_out_evaluation" if entry.get("held_out_status") == HELD_OUT_VERIFIED else "smoke_test"


CONTEXT_MODES = ("auto", "none")


def contexts_to_send(ex: Example, context_mode: str) -> List[Dict[str, str]]:
    """Per-call context actually sent. Only what the example itself carries; never invented."""
    if context_mode not in CONTEXT_MODES:
        raise ValueError(f"context_mode must be one of {CONTEXT_MODES}")
    if context_mode == "none":
        return [{} for _ in ex.calls]
    return [ex.context_for(i) for i in range(len(ex.calls))]


def run_example(coordinator, ex: Example, session_prefix: str = "eval", context_mode: str = "auto") -> Dict[str, Any]:
    """Send one example's calls, in order, in one fresh session. The example's verdict is the most
    severe verdict across its calls (so a benign session counts as ESCALATE if any call escalated).
    Malformed input or a failed request is reported as ERROR, never as ALLOW."""
    sid = f"{session_prefix}/{ex.dataset}/{ex.example_id}"
    worst = None
    for call, ctx in zip(ex.calls, contexts_to_send(ex, context_mode)):
        request = {"text": call, "session_id": sid}
        if ctx:
            request["context"] = ctx          # only keys the dataset carried
        try:
            d = coordinator.evaluate(request)
        except Exception as e:  # malformed input or a failed request: reported, never counted as ALLOW
            return {"verdict": "ERROR", "decided_by": None, "error": type(e).__name__}
        if worst is None or SEVERITY[d.verdict] > SEVERITY[worst.verdict]:
            worst = d
    if worst is None:
        return {"verdict": "ERROR", "decided_by": None, "error": "no calls"}
    return {"verdict": worst.verdict, "decided_by": None if worst.verdict == "ALLOW" else worst.decided_by, "error": None}


def _tally(outcomes: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    c = Counter(o["verdict"] for o in outcomes)
    return {v: c.get(v, 0) for v in (*VERDICTS, "ERROR")}


def context_summary(rows: Sequence[Example], context_mode: str) -> Dict[str, Any]:
    """What context was sent for these examples (counts of examples; tool_output also per call)."""
    sent = [contexts_to_send(e, context_mode) for e in rows]
    has = lambda ctxs, k: any(k in c for c in ctxs)
    return {
        "examples": len(rows),
        "examples_with_any_context": sum(1 for c in sent if any(c)),
        "examples_without_context": sum(1 for c in sent if not any(c)),
        "examples_with_user_instruction": sum(1 for c in sent if has(c, "user_instruction")),
        "examples_with_tool_output": sum(1 for c in sent if has(c, "tool_output")),
        "examples_with_account_email": sum(1 for c in sent if has(c, "account_email")),
        "calls": sum(len(c) for c in sent),
        "calls_with_tool_output": sum(1 for c in sent for x in c if "tool_output" in x),
    }


def run_dataset(entry: Dict[str, Any], coordinator, limit: Optional[int] = None, context_mode: str = "auto") -> Dict[str, Any]:
    examples = [e for e in load_examples(entry) if e.calls]
    if limit:
        examples = examples[:limit]
    outcomes = [run_example(coordinator, e, context_mode=context_mode) for e in examples]
    ukey = lambda e: (e.unique_key, e.context_fingerprint() if context_mode == "auto" else "")

    labels: Dict[str, Any] = {}
    for lab in ("attack", "benign"):
        rows = [(e, o) for e, o in zip(examples, outcomes) if e.label == lab]
        if not rows:
            continue
        first: Dict[Any, Dict[str, Any]] = {}
        inconsistent = 0
        for e, o in rows:
            f = first.setdefault(ukey(e), o)
            if f["verdict"] != o["verdict"]:
                inconsistent += 1
        labels[lab] = {
            "samples": len(rows),
            "unique_examples": len(first),
            "context": context_summary([e for e, _ in rows], context_mode),
            "verdicts_over_samples": _tally([o for _, o in rows]),
            "verdicts_over_unique_examples": _tally(list(first.values())),
            "inconsistent_duplicate_verdicts": inconsistent,
            "decided_by_non_allow": dict(sorted(Counter(o["decided_by"] for _, o in rows if o["decided_by"]).items())),
        }
    kind = evaluation_kind(entry)
    return {
        "dataset": entry["id"],
        "title": entry["title"],
        "role": entry["role"],
        "held_out_status": entry.get("held_out_status"),
        "evaluation_kind": kind,
        "disclaimer": SMOKE_DISCLAIMER if kind == "smoke_test" else HELD_OUT_NOTE,
        "overlap_with_rule_development": entry["overlap_with_rule_development"]["status"],
        "sent_examples": len(examples),
        "context_mode": context_mode,
        "context_fields_available_in_dataset": entry.get("context", {}).get("fields_available", []),
        "labels": labels,
    }


def format_report(results: List[Dict[str, Any]]) -> str:
    out = ["Kavach MVP smoke evaluation", "=" * 27, ""]
    for r in results:
        out.append(f"[{r['evaluation_kind'].upper().replace('_', ' ')}] {r['dataset']} - {r['title']}")
        out.append(f"  role={r['role']}  overlap_with_rule_development={r['overlap_with_rule_development']}  held_out={r['held_out_status']}")
        out.append(f"  {r['disclaimer']}")
        for lab, d in r["labels"].items():
            v, u = d["verdicts_over_samples"], d["verdicts_over_unique_examples"]
            n = d["samples"]
            pct = lambda k: f"{k} ({100 * k / n:.1f}%)" if n else str(k)
            out.append(f"  {lab.upper():7} samples={n} unique={d['unique_examples']}")
            out.append(f"     over samples : BLOCK {pct(v['BLOCK'])} | ESCALATE {pct(v['ESCALATE'])} | ALLOW {pct(v['ALLOW'])} | ERROR {v['ERROR']}")
            out.append(f"     over unique  : BLOCK {u['BLOCK']} | ESCALATE {u['ESCALATE']} | ALLOW {u['ALLOW']} | ERROR {u['ERROR']}")
            c = d["context"]
            if c["examples_with_any_context"] == 0:
                out.append(f"     context sent : NONE for all {c['examples']} examples (mode={r['context_mode']}"
                           + ("; the dataset carries none)" if not r["context_fields_available_in_dataset"] else "; dataset context suppressed)"))
            else:
                out.append(f"     context sent : user_instruction {c['examples_with_user_instruction']}/{c['examples']} examples | "
                           f"tool_output {c['examples_with_tool_output']}/{c['examples']} examples ({c['calls_with_tool_output']}/{c['calls']} calls) | "
                           f"account_email {c['examples_with_account_email']}/{c['examples']} | no context at all: {c['examples_without_context']}")
            if d["decided_by_non_allow"]:
                out.append(f"     decided by   : {d['decided_by_non_allow']}")
            if d["inconsistent_duplicate_verdicts"]:
                out.append(f"     WARNING: {d['inconsistent_duplicate_verdicts']} duplicate examples got different verdicts")
        out.append("")
    out.append("ESCALATE is reported separately everywhere; it is not counted as ALLOW or as a detection.")
    out.append("Context: only fields a dataset itself carries are sent; none are invented. Where 'context sent' says NONE or lacks a field, "
               "CHANNEL's provenance check could not see a user-supplied destination or a prior tool output, which can add ESCALATEs. "
               "Compare with --context none to see the effect on a dataset that has context (see evaluation/README.md).")
    return "\n".join(out)


def build_default_coordinator(chroma_path: Optional[str] = None):
    from kavach.coordinator import Coordinator
    from kavach.ministers.channel import ChannelMinister
    from kavach.ministers.executor import ExecutorMinister
    from kavach.ministers.navigator import NavigatorMinister
    from kavach.ministers.vault import VaultMinister

    return Coordinator([VaultMinister(), ExecutorMinister(), ChannelMinister(),
                        NavigatorMinister(chroma_path=Path(chroma_path) if chroma_path else None)])


def run(selected: Optional[Sequence[str]], coordinator_factory: Callable[[], Any], limit: Optional[int] = None,
        context_mode: str = "auto") -> Dict[str, Any]:
    reg = load_registry()
    entries = [e for e in datasets(reg) if e.get("runnable")]
    if selected:
        unknown = set(selected) - {e["id"] for e in entries}
        if unknown:
            raise SystemExit(f"unknown or non-runnable dataset(s): {sorted(unknown)}")
        entries = [e for e in entries if e["id"] in selected]
    coordinator = coordinator_factory()
    results = [run_dataset(e, coordinator, limit, context_mode) for e in entries]
    return {"schema_version": 1, "pinned_source": reg["pinned_source"], "context_mode": context_mode, "results": results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="list datasets and exit")
    ap.add_argument("--datasets", help="comma-separated dataset ids (default: all runnable)")
    ap.add_argument("--limit", type=int, help="send only the first N examples of each dataset (quick check)")
    ap.add_argument("--context", choices=CONTEXT_MODES, default="auto",
                    help="auto: send the context a dataset carries (default); none: send no context")
    ap.add_argument("--json", metavar="PATH", help="also write the full results as JSON")
    ap.add_argument("--chroma-path", help="NAVIGATOR ChromaDB directory (default: the MVP default)")
    args = ap.parse_args(argv)

    if args.list:
        for e in datasets():
            print(f"{e['id']:32} {e['role']:28} {'runnable' if e.get('runnable') else 'not runnable'}")
        return 0
    selected = args.datasets.split(",") if args.datasets else None
    report = run(selected, lambda: build_default_coordinator(args.chroma_path), args.limit, args.context)
    print(format_report(report["results"]))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

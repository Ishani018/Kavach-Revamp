"""
Candidate H1a for NAVIGATOR experiment 1: score only the argument VALUES of a tool call.

The tool name and the JSON keys are left out of both the dense query and the BM25 query. Everything else is the live
NAVIGATOR, reused as is: corpus, embeddings, collection, query prefix, thresholds, TOP_K, RRF, lexical gate, and the
result mapping. Only the string handed to the retrieval function differs.

Values are taken in the order the arguments appear, recursively (lists and nested objects included); strings are used
as they are and other scalars via str(). Fixed rule, no parameters. If a call has no arguments the query is the empty
string (not replaced by a fallback, which would be a second hypothesis).

This file does not modify the MVP. Use with:  run_experiment.py --candidate review/navigator-first-experiment/candidate_h1a.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from kavach.ministers import scan_to_result                       # noqa: E402
from kavach.ministers import navigator as nav                      # noqa: E402
from kavach.ministers.retrieval import run_minister_hybrid         # noqa: E402


def argument_text(arguments):
    parts = []

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        elif v is not None:
            parts.append(v if isinstance(v, str) else str(v))

    walk(arguments)
    return " ".join(parts)


class ArgumentOnlyNavigator:
    name = "NAVIGATOR"

    def __init__(self, base):
        self._base = base

    def check(self, call):
        b = self._base
        text = argument_text(call.arguments)
        scan = run_minister_hybrid(self.name, text, b._collection, b._bm25, b._embed_query, dict(nav.THRESHOLDS), nav.TOP_K)
        result = scan_to_result(scan, self.name)
        result.reason = f"H1a candidate: {scan.verdict} score {scan.confidence:.3f}"
        return result


def build(navigator):
    return ArgumentOnlyNavigator(navigator)

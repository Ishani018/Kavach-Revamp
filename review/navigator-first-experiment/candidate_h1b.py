"""
Candidate H1b for NAVIGATOR experiment 2: keep the tool name, drop JSON key names and punctuation.

Registered in docs/navigator-experiment-h1b.md before this candidate was run. Reuses the live NAVIGATOR's corpus,
embeddings, collection, query prefix, thresholds, TOP_K, RRF fusion and lexical gate unchanged; only the text handed
to retrieval differs from the live minister.

Query text = "<tool_name> <argument values, depth-first, keys and JSON punctuation dropped>" (a single leading space
is avoided when there are no arguments; the tool name alone is then the whole query). Same depth-first value walk as
candidate_h1a.py's argument_text: dict values and list items are visited in order, strings used as-is, other scalars
via str(), joined with single spaces.

Use with:  run_experiment.py --candidate review/navigator-first-experiment/candidate_h1b.py \
                              --criteria review/navigator-first-experiment/criteria_h1b.json
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from kavach.ministers import scan_to_result                       # noqa: E402
from kavach.ministers import navigator as nav                      # noqa: E402
from kavach.ministers.retrieval import run_minister_hybrid         # noqa: E402

from candidate_h1a import argument_text                            # noqa: E402  (same depth-first value walk)


def query_text(tool_name, arguments):
    tail = argument_text(arguments)
    return f"{tool_name} {tail}".rstrip() if tail else tool_name


class ToolNamePlusArgumentsNavigator:
    name = "NAVIGATOR"

    def __init__(self, base):
        self._base = base

    def check(self, call):
        b = self._base
        text = query_text(call.tool_name, call.arguments)
        scan = run_minister_hybrid(self.name, text, b._collection, b._bm25, b._embed_query, dict(nav.THRESHOLDS), nav.TOP_K)
        result = scan_to_result(scan, self.name)
        result.reason = f"H1b candidate: {scan.verdict} score {scan.confidence:.3f}"
        return result


def build(navigator):
    return ToolNamePlusArgumentsNavigator(navigator)

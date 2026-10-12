"""
Candidate H1c for NAVIGATOR experiment 3: floor-normalized confidence.

Registered in docs/navigator-experiment-h1c.md before this candidate is run. Computes the SAME full-wire-text score
NAVIGATOR already computes (nothing is withheld from retrieval: tool name, JSON keys, quoting, everything stays in
the query), then recalibrates the confidence number against a per-tool baseline F(tool) measured once by
compute_floor_table.py (content-free, no calibration labels read). matched_id/matched_level/reason continue to come
from the unchanged full-text retrieval; only the confidence value (and therefore the verdict) is adjusted.

adjusted = 0                                  if S_full <= F(tool)
adjusted = clamp((S_full - F(tool)) / (1 - F(tool)), 0, 1)   otherwise

This file does NOT modify the live NAVIGATOR. It is authored as part of the H1c protocol and has not been executed;
it refuses to run without a pre-built floor_table.json (see compute_floor_table.py), so loading it cannot silently
perform the Step 0 measurement itself.

Use with:  run_experiment.py --candidate review/navigator-first-experiment/candidate_h1c.py \
                              --criteria review/navigator-first-experiment/criteria_h1c.json
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from kavach.ministers import scan_to_result                       # noqa: E402
from kavach.ministers import navigator as nav                      # noqa: E402
from kavach.ministers.retrieval import run_minister_hybrid         # noqa: E402

HERE = Path(__file__).resolve().parent
FLOOR_TABLE_PATH = HERE / "floor_table.json"


def _verdict(adjusted, thresholds):
    if adjusted >= thresholds["block"]:
        return "BLOCK"
    if adjusted >= thresholds["grey"]:
        return "ESCALATE"
    return "ALLOW"


class FloorNormalizedNavigator:
    name = "NAVIGATOR"

    def __init__(self, base, floor):
        self._base = base
        self._floor = floor

    def check(self, call):
        b = self._base
        text = call.to_wire_text()                     # unchanged: the full wrapper stays the query
        scan = run_minister_hybrid(self.name, text, b._collection, b._bm25, b._embed_query, dict(nav.THRESHOLDS), nav.TOP_K)
        f = self._floor.get(call.tool_name, 0.0)        # unseen tool name: no adjustment, falls back to live behaviour
        s_full = scan.confidence
        if s_full <= f:
            adjusted = 0.0
        else:
            adjusted = min(1.0, max(0.0, (s_full - f) / (1.0 - f))) if f < 1.0 else 0.0
        result = scan_to_result(scan, self.name)
        result.verdict = _verdict(adjusted, nav.THRESHOLDS)
        result.confidence = adjusted
        result.reason = (f"H1c candidate: {result.verdict} adjusted={adjusted:.3f} "
                         f"(full={s_full:.3f}, floor[{call.tool_name}]={f:.3f})")
        return result


def build(navigator):
    if not FLOOR_TABLE_PATH.exists():
        raise FileNotFoundError(
            "floor_table.json not found: run compute_floor_table.py first (docs/navigator-experiment-h1c.md Step 0). "
            "This candidate must not silently measure its own floor at scoring time."
        )
    floor = json.loads(FLOOR_TABLE_PATH.read_text())["floor"]
    return FloorNormalizedNavigator(navigator, floor)

"""
kavach/ministers/navigator2/eval_runner.py
=============================================

Runs the task-level episode suite (episodes.py) through Navigator2 and
reports per-step and per-episode outcomes as a machine-readable dict.

Two modes:
  - run_suite() / run_episode(): the FAST path. Legacy minister verdicts are
    the hand-specified fixtures each EpisodeStep carries. No embedding model,
    no ChromaDB, no real EXECUTOR/VAULT/CHANNEL run. This is what
    tests/test_navigator2_episodes.py uses -- deterministic, no external
    dependency, runs in well under a second for all 16 episodes.
  - run_through_real_coordinator(): the SLOW, end-to-end smoke-check path.
    Builds the REAL kavach.coordinator.Coordinator (real VAULT/EXECUTOR/
    CHANNEL/legacy-NAVIGATOR, ~20s to load the BGE embedding model) via
    ShadowRunner, and runs a handful of episodes through it to prove the
    actual wiring works end to end, not just against fixtures. Legacy
    minister results here are whatever the real ministers actually say
    (ignoring each EpisodeStep.legacy_results fixture), so the expected
    per-step dispositions are NOT asserted exactly in this mode -- only that
    nothing crashes and that specialist hard BLOCKs are preserved.

Nothing in this module executes any command, script, or decoded payload --
every "tool call" here is a Python dict passed straight to Navigator2.check().
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...schemas import MinisterResult, ToolCall
from .contract import TaskContractStore
from .core import Navigator2
from .episodes import EPISODES, Episode, EpisodeStep

RESULTS_PATH = Path(__file__).resolve().parent / "eval_results.json"


def _fixture_minister_result(name: str, verdict: str) -> MinisterResult:
    return MinisterResult(
        minister=name, verdict=verdict,
        reason=f"[episode fixture] synthetic {name} {verdict}, not a real minister run",
        confidence=0.0 if verdict == "ALLOW" else 0.8,
    )


def run_episode(episode: Episode, *, navigator2: Optional[Navigator2] = None) -> Dict[str, Any]:
    nav2 = navigator2 or Navigator2(contract_store=TaskContractStore())
    session_id = f"episode-{episode.id}"
    nav2.contract_store.start_session(
        session_id, goal=episode.goal, workspace_scope=episode.workspace_scope,
        approved_destinations=episode.approved_destinations,
        high_impact_categories_requiring_approval=episode.high_impact_categories_requiring_approval,
        denied_categories=episode.denied_categories,
    )

    step_results: List[Dict[str, Any]] = []
    mismatches: List[str] = []
    for i, step in enumerate(episode.steps):
        call = ToolCall(tool_name=step.tool_name, arguments=step.arguments, session_id=session_id, context=step.context)
        legacy = {name: _fixture_minister_result(name, v) for name, v in step.legacy_results.items()}
        verdict = nav2.check(call, legacy_results=legacy, parent_event_ids=step.parent_event_ids, source_kind=step.source_kind)

        ok_disposition = step.expected_disposition is None or verdict.disposition == step.expected_disposition
        ok_approval = step.expected_requires_approval is None or verdict.requires_approval == step.expected_requires_approval
        if not ok_disposition:
            mismatches.append(f"step {i} ({step.tool_name}): expected disposition {step.expected_disposition!r}, got {verdict.disposition!r}")
        if not ok_approval:
            mismatches.append(f"step {i} ({step.tool_name}): expected requires_approval={step.expected_requires_approval}, got {verdict.requires_approval}")

        step_results.append({
            "index": i, "tool_name": step.tool_name, "note": step.note,
            "expected_disposition": step.expected_disposition, "actual_disposition": verdict.disposition,
            "expected_requires_approval": step.expected_requires_approval, "actual_requires_approval": verdict.requires_approval,
            "policy_decisions": [d.policy_id for d in verdict.policy_decisions],
            "reasoner_invoked": verdict.reasoner_invoked, "reasoner_capped": verdict.reasoner_capped,
            "reason": verdict.reason,
        })

    return {
        "episode_id": episode.id, "title": episode.title, "category": episode.category, "label": episode.label,
        "passed": not mismatches, "mismatches": mismatches, "steps": step_results,
    }


def run_suite(episodes: Optional[List[Episode]] = None) -> Dict[str, Any]:
    episodes = episodes if episodes is not None else EPISODES
    results = [run_episode(e, navigator2=Navigator2(contract_store=TaskContractStore())) for e in episodes]
    passed = sum(1 for r in results if r["passed"])
    by_label: Dict[str, Dict[str, int]] = {}
    for r in results:
        d = by_label.setdefault(r["label"], {"total": 0, "passed": 0})
        d["total"] += 1
        d["passed"] += int(r["passed"])
    return {
        "schema_version": 1, "mode": "fast_fixture_legacy_results",
        "episode_count": len(results), "passed": passed, "failed": len(results) - passed,
        "by_label": by_label, "episodes": results,
    }


def run_through_real_coordinator(episode_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Slow, end-to-end smoke check against the REAL Coordinator (real VAULT/
    EXECUTOR/CHANNEL/legacy NAVIGATOR). Uses ShadowRunner -- the production
    Decision path is untouched; only its already-computed ministers dict is
    reused for Navigator2's input, exactly as shadow.py documents."""
    from .shadow import ShadowRunner
    from ...api import build_default_coordinator

    coordinator = build_default_coordinator()
    episodes = [e for e in EPISODES if episode_ids is None or e.id in episode_ids]
    results = []
    for ep in episodes:
        nav2 = Navigator2(contract_store=TaskContractStore())
        session_id = f"real-episode-{ep.id}"
        nav2.contract_store.start_session(
            session_id, goal=ep.goal, workspace_scope=ep.workspace_scope,
            approved_destinations=ep.approved_destinations,
            high_impact_categories_requiring_approval=ep.high_impact_categories_requiring_approval,
            denied_categories=ep.denied_categories,
        )
        runner = ShadowRunner(coordinator, navigator2=nav2)
        step_results = []
        for step in ep.steps:
            call = ToolCall(tool_name=step.tool_name, arguments=step.arguments, session_id=session_id, context=step.context)
            shadow = runner.evaluate_shadow(call)
            step_results.append({
                "tool_name": step.tool_name,
                "production_decision": shadow.decision.verdict,
                "production_decided_by": shadow.decision.decided_by,
                "navigator2_disposition": shadow.navigator2_verdict.disposition if shadow.navigator2_verdict else None,
                "navigator2_error": shadow.navigator2_error,
            })
        results.append({"episode_id": ep.id, "title": ep.title, "steps": step_results})
    return {"schema_version": 1, "mode": "real_coordinator_shadow", "episodes": results}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", metavar="PATH", default=str(RESULTS_PATH), help="where to write the results JSON")
    ap.add_argument("--real-coordinator", action="store_true", help="also run the slow real-Coordinator smoke check")
    args = ap.parse_args(argv)

    report = run_suite()
    print(f"NAVIGATOR 2.0 task-level episodes: {report['passed']}/{report['episode_count']} passed")
    for r in report["episodes"]:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['episode_id']} {r['title']} ({r['label']})")
        for m in r["mismatches"]:
            print(f"         - {m}")

    if args.real_coordinator:
        report["real_coordinator_smoke"] = run_through_real_coordinator()

    Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {args.json}")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

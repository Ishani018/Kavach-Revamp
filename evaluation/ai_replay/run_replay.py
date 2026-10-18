"""
Replay the AI-evidence scenarios through the real ministers.

    python -m evaluation.ai_replay.run_replay --check            # replay the committed record, compare
    python -m evaluation.ai_replay.run_replay --write-expected   # replay, then rewrite expected.json
    KAVACH_AI=live python -m evaluation.ai_replay.run_replay --record   # ask the real model, rewrite record
    KAVACH_AI=live KAVACH_AI_PROVIDER=groq python -m evaluation.ai_replay.run_replay --record
    python -m evaluation.ai_replay.run_replay --record --scripted       # rewrite record from the scripted provider

Every scenario runs twice per mode in a fresh coordinator. The run fails if:
  * two replays of the same record disagree (AI evidence must be repeatable),
  * any step is more lenient with AI evidence than without it (AI may only
    add caution or verified findings), or
  * --check is given and the replay differs from expected.json.

The committed record.jsonl was produced by the *scripted* provider below, a
small rule-based stand-in, because no model credentials were available when
it was generated. It exercises the plumbing and the safety properties, not
model quality. Re-record with KAVACH_AI=live to capture real model answers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

from kavach.ai import AIEvidence, from_env
from kavach.coordinator import Coordinator
from kavach.ministers.channel import ChannelMinister
from kavach.ministers.executor import ExecutorMinister
from kavach.ministers.navigator import NavigatorMinister
from kavach.ministers.vault import VaultMinister

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE / "scenarios.json"
RECORD = HERE / "record.jsonl"
EXPECTED = HERE / "expected.json"
SEVERITY = {"ALLOW": 0, "ESCALATE": 1, "BLOCK": 2}


class ScriptedProvider:
    """Rule-based stand-in for a model, for recording without credentials."""

    model = "claude-opus-5-5"

    def complete(self, task, payload):
        return getattr(self, task.name.replace(".", "_"))(payload)

    @staticmethod
    def executor_deobfuscate(p):
        cmd = p["command"]
        values = dict(re.findall(r"(\w+)='([^']*)'", cmd))
        order = re.findall(r"\$(\w+)", cmd.split("eval", 1)[1]) if "eval" in cmd else []
        parts = [values[v] for v in order if v in values]
        if len(parts) < 2:
            return {"found": False, "steps": [], "decoded": ""}
        return {"found": True, "steps": [{"transform": "concat", "inputs": parts}], "decoded": "".join(parts)}

    @staticmethod
    def channel_tool_role(p):
        name = p["tool_name"].lower()
        keys = list(p["argument_types"])
        sends = any(w in name for w in ("relay", "post", "send", "upload", "share"))
        return {
            "reads_private_data": any(w in name for w in ("fetch", "read", "records", "export")),
            "sends_externally": sends,
            "recipient_arguments": [k for k in keys if k in ("handle", "to", "recipient", "target", "channel", "url")] if sends else [],
        }

    @staticmethod
    def vault_secret_candidates(p):
        hits = [c for c in p["candidates"] if c["assigned_to"] and re.search(r"pass|secret|token|key", c["assigned_to"], re.I)]
        return {"secrets": [{"id": c["id"], "kind": "password" if "PASS" in c["assigned_to"].upper() else "credential"}
                            for c in hits]}

    @staticmethod
    def navigator_intent(p):
        words = {w for w in re.findall(r"[a-z]{4,}", p["task"].lower())}
        action = " ".join(filter(None, [p["tool"], p.get("command") or "", " ".join(p["writes"])])).lower()
        fits = any(w in action for w in words)
        return {"fits_task": fits, "reason": "shares the task's subject" if fits else "unrelated to the task"}

    @staticmethod
    def navigator_reasoner(p):
        return {
            "assessment": "insufficient_evidence", "supporting_event_ids": [p["action"]["event_id"]],
            "observed_facts": ["deterministic policy flagged this action"],
            "applicable_policy_clauses": [], "potential_impact": "unknown",
            "recommended_disposition": "escalate", "uncertainty": 0.7,
            "explanation": "The action needs review before it runs.",
        }


def record_model() -> str:
    """The model the committed record was made with (keys include it)."""
    for line in RECORD.read_text().splitlines() if RECORD.is_file() else []:
        model = json.loads(line).get("model")
        if model:
            return model
    return ScriptedProvider.model


def coordinator(ai: AIEvidence) -> Coordinator:
    return Coordinator([VaultMinister(ai=ai), ExecutorMinister(ai=ai), ChannelMinister(ai=ai),
                        NavigatorMinister(ai=ai)])


def run(ai_factory) -> Dict[str, List[Dict[str, Any]]]:
    os.environ["KAVACH_TERMINAL_DIALECT"] = "zsh"
    scenarios = json.loads(SCENARIOS.read_text())["scenarios"]
    out = {}
    for sc in scenarios:
        c = coordinator(ai_factory())
        steps = []
        for i, step in enumerate(sc["steps"]):
            body = {"session_id": "replay-" + sc["id"], **step["body"]}
            d = c.evaluate(body) if step["kind"] == "check" else c.observe(body)
            steps.append({
                "step": i, "kind": step["kind"], "verdict": d.verdict, "decided_by": d.decided_by,
                "ministers": {n: [r.verdict, r.matched_id] for n, r in d.ministers.items()},
            })
        out[sc["id"]] = steps
    return out


def compare(off, on) -> List[str]:
    problems = []
    for sid, steps in on.items():
        for a, b in zip(off[sid], steps):
            if SEVERITY[b["verdict"]] < SEVERITY[a["verdict"]]:
                problems.append(f"{sid} step {a['step']}: AI-on {b['verdict']} is more lenient than AI-off {a['verdict']}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--scripted", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write-expected", action="store_true")
    args = ap.parse_args(argv)

    if args.record:
        RECORD.unlink(missing_ok=True)
        if args.scripted:
            make = lambda: AIEvidence("live", provider=ScriptedProvider(), record_path=RECORD, intent_checks=True)
        else:
            os.environ["KAVACH_AI_RECORD"] = str(RECORD)
            os.environ["KAVACH_AI_INTENT"] = "on"
            make = from_env
            if make().mode != "live":
                print("set KAVACH_AI=live (and credentials) to record from the model", file=sys.stderr)
                return 2
        run(make)

    off = run(lambda: AIEvidence("off"))
    replay = lambda: AIEvidence("replay", record_path=RECORD, model=record_model(), intent_checks=True)
    first, second = run(replay), run(replay)
    problems = [] if first == second else ["two replays of the same record disagree"]
    problems += compare(off, first)
    if args.write_expected:
        EXPECTED.write_text(json.dumps({"ai_off": off, "ai_replay": first}, indent=2, sort_keys=True) + "\n")
    if args.check and json.loads(EXPECTED.read_text()) != {"ai_off": off, "ai_replay": first}:
        problems.append("replay differs from expected.json")

    for sid in first:
        for a, b in zip(off[sid], first[sid]):
            mark = "  " if a["verdict"] == b["verdict"] else "->"
            print(f"{sid:38} step {a['step']} {a['verdict']:8} {mark} {b['verdict']:8} ({b['decided_by']})")
    for p in problems:
        print("FAIL:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Normalize each registered dataset's native format into `Example`s.

Loaders only read the files as they are; they never modify, relabel or filter them.
The label of an example is the one the dataset itself carries or implies (the
rule is stated per loader). Classifying a label is not the same as verifying it.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

LABELS = ("attack", "benign")


# The only context keys the MVP reads (kavach/ministers/channel.py, `_opt_str`). It reads them from
# ToolCall.context and ignores non-string values silently, so this module only ever produces strings.
CONTEXT_KEYS = ("user_instruction", "tool_output", "account_email")


@dataclass(frozen=True)
class Example:
    dataset: str
    example_id: str
    label: str                      # "attack" | "benign"
    calls: Tuple[str, ...]          # wire-format calls `tool:NAME args:{json}`, sent in order in one session
    unique_key: str                 # what counts as "the same example" (calls, or a text field for count-only data)
    meta: Dict[str, str] = field(default_factory=dict, compare=False, hash=False)
    # One dict per call (same length as `calls`) holding ONLY context the dataset itself carries.
    # Empty tuple = the dataset has no context for this example. Nothing is ever filled in or guessed.
    contexts: Tuple[Dict[str, str], ...] = field(default=(), compare=False, hash=False)

    @property
    def runnable(self) -> bool:
        return bool(self.calls)

    def context_for(self, i: int) -> Dict[str, str]:
        return dict(self.contexts[i]) if self.contexts else {}

    def context_fields(self) -> frozenset:
        return frozenset(k for c in self.contexts for k in c)

    def context_fingerprint(self) -> str:
        """Identity of the context that would be sent (empty string when there is none)."""
        return json.dumps(list(self.contexts), sort_keys=True) if any(self.contexts) else ""


def wire(tool: str, args: dict) -> str:
    return f"tool:{tool} args:{json.dumps(args)}"


def _single(ds: str, ex_id: str, label: str, call: str, **meta) -> Example:
    return Example(ds, ex_id, label, (call,), call, {k: str(v) for k, v in meta.items()})


def _jsonl(path: Path) -> List[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_pb_checkpoint(ds: str, path: Path, label: str) -> List[Example]:
    """Kavach-PB checkpoint: {case_id: {call_text, ...}}. Only `call_text` is used; the
    verdicts recorded in the file (from the pre-MVP pipeline) are ignored. The label is the
    one the registry assigns to the whole file (the file holds only one class)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [_single(ds, case_id, label, rec["call_text"]) for case_id, rec in data.items()]


def load_atriumos(ds: str, path: Path, _label: str = "") -> List[Example]:
    """`ground_truth` ATTACK -> attack, BENIGN -> benign. `calls` are a session."""
    out = []
    for r in _jsonl(path):
        calls = tuple(r["calls"])
        out.append(Example(ds, r["case_id"], r["ground_truth"].lower(), calls, "\n".join(calls),
                           {"target_minister": r["target_minister"]}))
    return out


def load_openclaw(ds: str, path: Path, _label: str = "") -> List[Example]:
    """`expected` BLOCK -> attack, ALLOW -> benign."""
    return [_single(ds, r["id"], "attack" if r["expected"] == "BLOCK" else "benign", r["text"],
                    category=r["category"]) for r in _jsonl(path)]


def _nonempty_str(v) -> Optional[str]:
    return v if isinstance(v, str) and v.strip() else None


def load_benign_sessions(ds: str, path: Path, label: str = "benign") -> List[Example]:
    """List of {source_file, user_task_text, calls:[{tool,args,tool_output}]}; one example per session.

    Context mapping (exactly what the file carries, nothing added):
      session `user_task_text` -> `user_instruction` on every call of the session
      call `tool_output`       -> `tool_output` on that call
    An empty or null field is simply absent. There is no account_email in this data."""
    out = []
    for i, s in enumerate(json.loads(path.read_text(encoding="utf-8"))):
        calls = tuple(wire(c["tool"], c["args"]) for c in s["calls"])
        instr = _nonempty_str(s.get("user_task_text"))
        ctxs = []
        for c in s["calls"]:
            ctx = {}
            if instr:
                ctx["user_instruction"] = instr
            out_text = _nonempty_str(c.get("tool_output"))
            if out_text:
                ctx["tool_output"] = out_text
            ctxs.append(ctx)
        out.append(Example(ds, f"session-{i:02d}", label, calls, "\n".join(calls),
                           {"source_file": s.get("source_file", "")}, tuple(ctxs)))
    return out


def load_benign_v0_rows(ds: str, path: Path, label: str = "benign") -> List[Example]:
    """benign_v0.json: rows {bucket, source_file, user_task_text, tool, args, why_legitimate}; one call each.
    `user_task_text` -> `user_instruction`. The file has no tool outputs and no account_email."""
    out = []
    for i, r in enumerate(json.loads(path.read_text(encoding="utf-8"))):
        call = wire(r["tool"], r["args"])
        instr = _nonempty_str(r.get("user_task_text"))
        out.append(Example(ds, f"row-{i:02d}", label, (call,), call,
                           {"bucket": r.get("bucket", "")}, ({"user_instruction": instr},) if instr else ({},)))
    return out


def load_benign_traces(ds: str, path: Path, label: str = "benign") -> List[Example]:
    """`BENIGN_TRACES` list literal inside a Python source file. Parsed with ast.literal_eval;
    the file is never imported or executed."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    traces = None
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "BENIGN_TRACES":
            traces = ast.literal_eval(node.value)
    if traces is None:
        raise ValueError("BENIGN_TRACES not found")
    out = []
    for t in traces:
        calls = tuple(wire(tool, args) for tool, args in t["actions"])
        out.append(Example(ds, t["id"], label, calls, "\n".join(calls), {"category": t.get("category", "")}))
    return out


def load_injecagent_attackers(ds: str, path: Path, label: str = "attack") -> List[Example]:
    """Count-only: InjecAgent attacker cases need the legacy two-step dispatch to become calls."""
    return [Example(ds, f"case-{i:03d}", label, (), r["Attacker Instruction"],
                    {"attack_type": r.get("Attack Type", "")}) for i, r in enumerate(_jsonl(path))]


def load_injecagent_user_cases(ds: str, path: Path, label: str = "benign") -> List[Example]:
    """Count-only: benign user tasks that the legacy runner pairs with each attacker case."""
    return [Example(ds, f"user-{i:02d}", label, (), r["User Instruction"], {"user_tool": r.get("User Tool", "")})
            for i, r in enumerate(_jsonl(path))]


LOADERS: Dict[str, Callable[..., List[Example]]] = {
    "pb_checkpoint": load_pb_checkpoint,
    "atriumos_jsonl": load_atriumos,
    "openclaw_jsonl": load_openclaw,
    "benign_sessions_json": load_benign_sessions,
    "benign_v0_rows_json": load_benign_v0_rows,
    "benign_traces_py": load_benign_traces,
    "injecagent_attackers_jsonl": load_injecagent_attackers,
    "injecagent_user_cases_jsonl": load_injecagent_user_cases,
}

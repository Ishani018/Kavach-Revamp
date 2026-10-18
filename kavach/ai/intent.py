"""Per-action intent evidence for NAVIGATOR (opt-in: KAVACH_AI_INTENT=on).

The model answers one question: does this consequential action fit the task
the user gave? A "no" becomes a fact for policy POL-011, which escalates; a
"yes" or no answer changes nothing. So the check can only add caution, and
the decision is still made by the deterministic policy set.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from . import tasks
from .evidence import AIEvidence

_CODE_KEYS = ("command", "cmd", "script", "code")


def is_consequential(event, call) -> bool:
    """Actions worth a model question: they run code, write, or reach out."""
    args = call.arguments or {}
    return bool(event.destinations or event.artifacts_written
                or any(isinstance(args.get(k), str) and args[k].strip() for k in _CODE_KEYS))


class AIIntentChecker:
    def __init__(self, ai: AIEvidence) -> None:
        self.ai = ai

    def __call__(self, contract, event, call) -> Optional[Tuple[bool, str, Dict[str, Any]]]:
        """(mismatch, reason, provenance), or None when no question was asked
        or no valid answer came back."""
        if not contract.goal.strip() or not is_consequential(event, call):
            return None
        args = call.arguments or {}
        command = next((args[k] for k in _CODE_KEYS if isinstance(args.get(k), str) and args[k].strip()), None)
        payload = {
            "task": tasks.clip(contract.goal, 2000),
            "tool": event.tool_name,
            "arguments": event.arg_summary,
            "command": tasks.clip(command, 2000) if command else None,
            "writes": event.artifacts_written[:10],
            "destinations": event.destinations[:10],
        }
        answer = self.ai.ask(tasks.INTENT, payload)
        if answer is None:
            return None
        return (not answer.data["fits_task"], answer.data["reason"][:300], answer.provenance())

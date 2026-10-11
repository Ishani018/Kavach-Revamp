"""TRAJECTORY: reviews sessions that combine multiple high-impact action types.

This is a small heuristic over observed tool calls, not a learned risk model.
"""
import re
from collections import defaultdict, deque

from ..models import ActionEvent, Vote, VoteKind


_CATEGORIES = (
    ("sensitive_read", re.compile(r"(view|get|search|list|download|access).*(credential|secret|password|payment|address|health|location)", re.I)),
    ("execution", re.compile(r"(shell|terminal|execute|run_command|powershell)", re.I)),
    ("external_send", re.compile(r"(send|share|upload|post|email|message)", re.I)),
    ("destructive", re.compile(r"(delete|remove|drop|destroy|format)", re.I)),
)


class TrajectoryMinister:
    name = "TRAJECTORY"

    def __init__(self, window: int = 5) -> None:
        self._history = defaultdict(lambda: deque(maxlen=window))

    def evaluate(self, event: ActionEvent) -> Vote:
        action = f"{event.tool_name} {event.operation} {event.arguments}"
        categories = {name for name, pattern in _CATEGORIES if pattern.search(action)}
        history = self._history[event.session_id]
        recent = set().union(*history) if history else set()
        combined = recent | categories
        history.append(categories)

        if len(combined) >= 3:
            return Vote(self.name, VoteKind.REVIEW, "MULTIPLE_HIGH_IMPACT_ACTION_TYPES_IN_SESSION")
        return Vote(self.name, VoteKind.ALLOW, "NO_MULTI_STEP_RISK_PATTERN")

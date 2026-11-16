"""Provenance reviewer: where did each argument of this action come from?

Deterministic and model-free. It knows nothing about attacks; it only traces values.
The matching rule below is fixed before any measurement and must not be tuned on benchmark results.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from .types import Action, Opinion, Origin, Session, Verdict

MIN_TRACEABLE_CHARS = 3  # shorter values ("1", "no") match by accident too often to mean anything


def _leaves(value: Any, path: str) -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _leaves(v, f"{path}[{i}]")
    else:
        yield path, value


def _appears(value: str, text: str) -> bool:
    """Whole-value match, case-insensitive, not inside a longer word or number."""
    pattern = r"(?<!\w)" + re.escape(value.casefold()) + r"(?!\w)"
    return re.search(pattern, text.casefold()) is not None


_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?!\w)")


def _number_appears(value: float, text: str) -> bool:
    """Numbers are compared by value, so 120.5 matches '120.50'."""
    return any(float(token) == value for token in _NUMBER.findall(text))


def contains(value: Any, text: str) -> bool:
    """Does this argument value appear in this text? Numbers by value, text as a whole value."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _number_appears(float(value), text)
    return _appears(str(value).strip(), text)


def traceable(value: Any) -> bool:
    """Is this value specific enough that finding it in a text means something?

    Not traced: booleans, empty values, values shorter than three characters, and a single lowercase word
    ("summary", "general"), which turns up in ordinary text by coincidence. The single-word rule was added
    after the first gateway test held an honest email for its subject "summary"; the benchmark results
    before and after are both reported in the README.
    """
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    if len(text) < MIN_TRACEABLE_CHARS:
        return False
    return not (isinstance(value, str) and text.isalpha() and text.islower())


def origin_of(value: Any, session: Session) -> Origin:
    if not traceable(value):
        return Origin.UNTRACED
    if contains(value, session.user_request):
        return Origin.USER
    if any(contains(value, seen) for seen in session.observations):
        return Origin.READ
    return Origin.NEW


def origins(action: Action, session: Session) -> dict[str, Origin]:
    """Origin of every leaf argument, keyed by its path (for example 'recipients[0]')."""
    return {path: origin_of(value, session) for path, value in _leaves(action.args, "")}


class ProvenanceReviewer:
    """Asks the human when arguments came only from something the agent read.

    strict   : ask if ANY argument came only from tool output.
    anchored : ask only if some argument came from tool output AND no argument came from the user's
               request. The idea: if the user named part of the action (the recipient, the file), the
               action is tied to their request. Weaker by design: an attacker who reuses a value from the
               user's request gets through.
    """

    def __init__(self, mode: str = "strict"):
        if mode not in ("strict", "anchored"):
            raise ValueError(f"unknown mode: {mode}")
        self.mode = mode
        self.name = "provenance" if mode == "strict" else "provenance-anchored"

    def review(self, action: Action, session: Session) -> Opinion:
        traced = origins(action, session)
        from_read = sorted(p for p, o in traced.items() if o is Origin.READ)
        from_user = sorted(p for p, o in traced.items() if o is Origin.USER)
        if not from_read:
            return Opinion(self.name, Verdict.ALLOW, "no argument came only from tool output")
        if self.mode == "anchored" and from_user:
            return Opinion(self.name, Verdict.ALLOW,
                           "the user named " + ", ".join(from_user) + "; from tool output: " + ", ".join(from_read))
        return Opinion(self.name, Verdict.ASK,
                       "argument(s) taken from tool output, not from the user: " + ", ".join(from_read))

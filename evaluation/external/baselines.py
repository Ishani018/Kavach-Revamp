"""Reference monitors to compare Kavach against.

`none` allows everything. `denylist` is the kind of short pattern list a
developer might write in an afternoon; it exists to show what the four
ministers add over a naive filter, and is deliberately not tuned on any
benchmark.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_DENY = [
    r"\brm\s+-[a-z]*r[a-z]*f?\s+/(\s|$)", r"\bmkfs\b", r"\bdd\s+if=.*of=/dev/",
    r":\(\)\s*\{\s*:\|:&\s*\};:", r"\b(curl|wget)\b[^|\n]*\|\s*(ba|z|)sh\b",
    r"\bnc\b.*\s-e\s", r"/dev/tcp/", r"\bchmod\s+(-R\s+)?777\s+/", r"\bsudo\s+rm\b",
    r">\s*/etc/(passwd|shadow|sudoers)", r"\bshutdown\b|\breboot\b",
]
_DENY_RE = [re.compile(p, re.I) for p in _DENY]


def _text(calls: List[Dict[str, Any]]) -> str:
    return "\n".join(str(v) for call in calls for v in call["arguments"].values())


def none_monitor(calls: List[Dict[str, Any]]) -> str:
    return "ALLOW"


def denylist_monitor(calls: List[Dict[str, Any]]) -> str:
    text = _text(calls)
    return "BLOCK" if any(r.search(text) for r in _DENY_RE) else "ALLOW"

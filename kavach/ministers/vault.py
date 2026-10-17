"""VAULT: credential and secret detection (rules live in prefilters.py).

Rules recognise known secret formats. A token in no known format can still be
a live credential (a custom API key, a password assigned to PASSWORD=). When
AI evidence is enabled, VAULT extracts such candidates deterministically
(long high-entropy tokens, values assigned to secret-like names) and asks a
model which look like live credentials. The model sees a masked preview, never
the value, and a positive answer can only raise the verdict to ESCALATE.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from . import prefilters, scan_to_result
from ..ai import AIEvidence
from ..schemas import MinisterResult, Observation, ToolCall

MAX_CANDIDATES = 10

_TOKEN = re.compile(r"[A-Za-z0-9_\-+/.~]{20,}={0,2}")
_ASSIGNED = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.-]{0,48})\s*[:=]\s*[\"']?([^\s\"'`,;]{8,})", re.IGNORECASE)
_SECRET_NAME = re.compile(r"secret|token|passw(or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth", re.IGNORECASE)
_HEX_OR_UUID = re.compile(r"^(?:[0-9a-fA-F]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")


def _entropy(token: str) -> float:
    counts = Counter(token)
    return -sum(c / len(token) * math.log2(c / len(token)) for c in counts.values())


def _classes(token: str) -> str:
    return "".join(label for label, test in (("a", str.islower), ("A", str.isupper), ("0", str.isdigit))
                   if any(test(ch) for ch in token)) + ("_" if any(not ch.isalnum() for ch in token) else "")


@dataclass(frozen=True)
class Candidate:
    token: str
    assigned_to: Optional[str]

    def masked(self, index: int) -> Dict[str, object]:
        return {
            "id": index,
            "preview": self.token[:4] + "…",
            "length": len(self.token),
            "character_classes": _classes(self.token),
            "entropy_bits_per_char": round(_entropy(self.token), 2),
            "assigned_to": self.assigned_to,
        }


def secret_candidates(text: str) -> List[Candidate]:
    """Tokens worth a second look: assigned to a secret-like name, or long,
    mixed-class and high-entropy. Known formats (content rules), plain hex
    digests and UUIDs are excluded."""
    if not isinstance(text, str) or not text:
        return []
    known = {m.group(0) for _, p, _ in prefilters.VAULT_CONTENT_PATTERNS for m in p.finditer(text)}
    found: Dict[str, Candidate] = {}
    for m in _ASSIGNED.finditer(text):
        name, value = m.group(1), m.group(2)
        if _SECRET_NAME.search(name) and value not in known and not value.startswith(("$", "%", "{")):
            found.setdefault(value, Candidate(value, name))
    for m in _TOKEN.finditer(text):
        token = m.group(0)
        if token in found or token in known or _HEX_OR_UUID.match(token) or "/" in token.strip("/"):
            continue
        if len(_classes(token).replace("_", "")) >= 3 and _entropy(token) >= 3.5:
            found.setdefault(token, Candidate(token, None))
    return list(found.values())[:MAX_CANDIDATES]


def _strings(value) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


class VaultMinister:
    name = "VAULT"

    def __init__(self, ai: Optional[AIEvidence] = None) -> None:
        self.ai = ai or AIEvidence("off")

    def check(self, call: ToolCall) -> MinisterResult:
        parsed = prefilters.ParsedCall(tool=call.tool_name, args=call.arguments, raw_text=call.to_wire_text())
        result = scan_to_result(prefilters.check_vault(parsed), self.name, redact_match=True)
        if result.verdict == "ALLOW" and self.ai.enabled:
            return self._ai_candidates("\n".join(_strings(call.arguments)), "tool call") or result
        return result

    _WHERE = {"UserPromptSubmit": "prompt", "PostToolUse": "tool output",
              "SubagentStop": "sub-agent report", "Stop": "final answer"}

    def observe(self, obs: Observation, prior_results: Dict[str, MinisterResult]) -> Optional[MinisterResult]:
        """Secret values in a prompt, a tool's output, a sub-agent's report or
        the final answer. BLOCK on a prompt means "do not send this to the
        model"; elsewhere it means "credential material is now in an agent's
        context". Matched values are never returned."""
        where = self._WHERE.get(obs.event)
        if where is None:
            return None
        hits = prefilters.scan_vault_content(obs.text)
        if not hits:
            if self.ai.enabled:
                flagged = self._ai_candidates(obs.text, where)
                if flagged is not None:
                    return flagged
            return MinisterResult(minister=self.name, verdict="ALLOW", reason="VAULT: no secret value found")
        names = [name for name, _ in hits]
        return MinisterResult(
            minister=self.name,
            verdict="BLOCK",
            reason=f"VAULT found secret material in the {where} (match text withheld)",
            matched_id=f"VAULT-CONTENT:{names[0]}",
            confidence=1.0,
            diagnostics={"level": "deterministic", "rules": names, "source": hits[0][1]},
        )

    def _ai_candidates(self, text: str, where: str) -> Optional[MinisterResult]:
        from ..ai import tasks
        candidates = secret_candidates(text)
        if not candidates:
            return None
        answer = self.ai.ask(tasks.SECRET_CANDIDATES,
                             {"candidates": [c.masked(i) for i, c in enumerate(candidates)]})
        if answer is None:
            return None
        kinds = [item["kind"][:64] for item in answer.data["secrets"] if 0 <= item["id"] < len(candidates)]
        if not kinds:
            return None
        return MinisterResult(
            minister=self.name,
            verdict="ESCALATE",
            reason=f"VAULT: AI evidence flags {len(kinds)} token(s) in the {where} as likely credentials (values withheld)",
            matched_id="VAULT-AI-CANDIDATE:" + re.sub(r"[^a-z0-9_-]+", "-", kinds[0].lower()).strip("-"),
            diagnostics={"level": "ai-evidence", "kinds": kinds, **answer.provenance()},
        )

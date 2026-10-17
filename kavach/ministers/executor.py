"""EXECUTOR: dangerous-execution detection (rules in prefilters.py, parsing in ast_parse.py / struct_parse.py).

Commands can hide what they run behind encoding. After the direct rules,
EXECUTOR decodes encoded-looking runs deterministically (deobfuscate.py) and
checks the decoded text with the same EXECUTOR and VAULT rules. When AI
evidence is enabled and a command still shows obfuscation signals, a model
may propose how to decode it; the proposal is used only if replaying it with
pure transforms reproduces the claimed text from text actually present in the
command. Decoding can only add a BLOCK, never remove one.
"""

from __future__ import annotations

from typing import List, Optional

from . import deobfuscate, prefilters, scan_to_result
from ..ai import AIEvidence
from ..schemas import MinisterResult, ToolCall

_CODE_KEYS = ("command", "cmd", "script", "code")


def _code_texts(call: ToolCall) -> List[str]:
    args = call.arguments or {}
    return [v for k in _CODE_KEYS if isinstance(v := args.get(k), str) and v.strip()]


def _rule_hit(text: str) -> Optional[str]:
    parsed = prefilters.ParsedCall(tool="bash", args={"command": text}, raw_text=text)
    scan = prefilters.check_executor(parsed) or prefilters.check_vault(parsed)
    return scan.matched_id if scan is not None else None


class ExecutorMinister:
    name = "EXECUTOR"

    def __init__(self, ai: Optional[AIEvidence] = None) -> None:
        self.ai = ai or AIEvidence("off")

    def check(self, call: ToolCall) -> MinisterResult:
        parsed = prefilters.ParsedCall(tool=call.tool_name, args=call.arguments, raw_text=call.to_wire_text())
        scan = prefilters.check_executor(parsed)
        if scan is not None:
            return scan_to_result(scan, self.name)
        notes = {}
        for text in _code_texts(call):
            hit, note = self._hidden_payload(text)
            if hit is not None:
                return hit
            if note:
                notes.update(note)
        result = scan_to_result(None, self.name)
        if notes:
            result.diagnostics["deobfuscation"] = notes
        return result

    def _hidden_payload(self, text: str):
        for decoded in deobfuscate.decode_candidates(text):
            rule = _rule_hit(decoded.text)
            if rule:
                return self._block(rule, decoded.transforms, {"via": "deterministic"}), None
        if not (self.ai.enabled and deobfuscate.OBFUSCATION_SIGNALS.search(text)):
            return None, None

        from ..ai import tasks
        shown = tasks.clip(text)
        answer = self.ai.ask(tasks.DEOBFUSCATE, {"command": shown})
        if answer is None:
            return None, {"ai": "no answer"}
        if not answer.data.get("found"):
            return None, {"ai": "nothing hidden", **answer.provenance()}
        try:
            decoded = deobfuscate.verify_chain(shown, answer.data["steps"], answer.data["decoded"])
        except deobfuscate.ChainRejected as exc:
            return None, {"ai": "rejected: " + str(exc)[:120], **answer.provenance()}
        for candidate in [decoded] + deobfuscate.decode_candidates(decoded.text):
            rule = _rule_hit(candidate.text)
            if rule:
                return self._block(rule, decoded.transforms + candidate.transforms[len(decoded.transforms):],
                                   {"via": "ai-verified", **answer.provenance()}), None
        return None, {"ai": "verified, decoded text matched no rule", **answer.provenance()}

    def _block(self, inner_rule: str, transforms, via: dict) -> MinisterResult:
        return MinisterResult(
            minister=self.name,
            verdict="BLOCK",
            reason=f"EXECUTOR decoded a hidden payload ({' > '.join(transforms)}) that matches {inner_rule}",
            matched_id=f"EXECUTOR-DEOBFUSCATED:{inner_rule}",
            confidence=1.0,
            diagnostics={"level": "deterministic", "transforms": list(transforms), "inner_rule": inner_rule, **via},
        )

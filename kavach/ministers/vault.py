"""VAULT: credential and secret detection (rules live in prefilters.py)."""

from __future__ import annotations

from typing import Dict, Optional

from . import prefilters, scan_to_result
from ..schemas import MinisterResult, Observation, ToolCall


class VaultMinister:
    name = "VAULT"

    def check(self, call: ToolCall) -> MinisterResult:
        parsed = prefilters.ParsedCall(tool=call.tool_name, args=call.arguments, raw_text=call.to_wire_text())
        return scan_to_result(prefilters.check_vault(parsed), self.name, redact_match=True)

    def observe(self, obs: Observation, prior_results: Dict[str, MinisterResult]) -> Optional[MinisterResult]:
        """Secret values in a submitted prompt or a tool's output. BLOCK on a
        prompt means "do not send this to the model"; on a tool output it means
        "credential material is now in the agent's context". Matched values are
        never returned."""
        hits = prefilters.scan_vault_content(obs.text)
        if not hits:
            return MinisterResult(minister=self.name, verdict="ALLOW", reason="VAULT: no secret value found")
        where = "prompt" if obs.event == "UserPromptSubmit" else "tool output"
        names = [name for name, _ in hits]
        return MinisterResult(
            minister=self.name,
            verdict="BLOCK",
            reason=f"VAULT found secret material in the {where} (match text withheld)",
            matched_id=f"VAULT-CONTENT:{names[0]}",
            confidence=1.0,
            diagnostics={"level": "deterministic", "rules": names, "source": hits[0][1]},
        )

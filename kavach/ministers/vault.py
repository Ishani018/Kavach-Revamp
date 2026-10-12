"""VAULT: credential and secret detection (rules live in prefilters.py)."""

from __future__ import annotations

from . import prefilters, scan_to_result
from ..schemas import MinisterResult, ToolCall


class VaultMinister:
    name = "VAULT"

    def check(self, call: ToolCall) -> MinisterResult:
        parsed = prefilters.ParsedCall(tool=call.tool_name, args=call.arguments, raw_text=call.to_wire_text())
        return scan_to_result(prefilters.check_vault(parsed), self.name, redact_match=True)

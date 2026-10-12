"""EXECUTOR: dangerous-execution detection (rules in prefilters.py, parsing in ast_parse.py / struct_parse.py)."""

from __future__ import annotations

from . import prefilters, scan_to_result
from ..schemas import MinisterResult, ToolCall


class ExecutorMinister:
    name = "EXECUTOR"

    def check(self, call: ToolCall) -> MinisterResult:
        parsed = prefilters.ParsedCall(tool=call.tool_name, args=call.arguments, raw_text=call.to_wire_text())
        return scan_to_result(prefilters.check_executor(parsed), self.name)

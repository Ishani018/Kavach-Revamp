"""
kavach/schemas.py
=================

The MVP data contract: a proposed tool call in, a Decision out.

Wire compatibility: the legacy `/hook/parliament` request shape
({"text": "tool:NAME args:{json}", "session_id": ..., "context": {...}}) is
still accepted and converted to a ToolCall, so the OpenClaw plugin's request
keeps working. Responses keep the legacy `verdict` and `ministers` keys.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

VERDICTS = ("BLOCK", "ESCALATE", "ALLOW")
MINISTER_NAMES = ("VAULT", "EXECUTOR", "CHANNEL", "NAVIGATOR")

# Same grammar the ministers' parsers use: `tool:{name} args:{json}`.
_WIRE_RE = re.compile(r"^tool:(?P<tool>\S+)\s+args:(?P<args>\{.*\})\s*$", re.DOTALL)


class ToolCall(BaseModel):
    """A proposed tool call, as submitted for a verdict."""

    tool_name: str = Field(min_length=1)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    session_id: str = Field(default="default", min_length=1)
    # Optional CHANNEL inputs (same keys the legacy `context` carried):
    # account_email, user_instruction, tool_output.
    context: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _from_legacy_text(cls, data: Any) -> Any:
        if isinstance(data, dict) and "text" in data and "tool_name" not in data:
            m = _WIRE_RE.match(str(data["text"]).strip())
            if not m:
                raise ValueError("`text` must look like: tool:NAME args:{json}")
            try:
                args = json.loads(m.group("args"))
            except json.JSONDecodeError:
                raise ValueError("`text` args are not valid JSON")
            data = {k: v for k, v in data.items() if k != "text"}
            data["tool_name"] = m.group("tool")
            data["arguments"] = args
        return data

    @field_validator("tool_name")
    @classmethod
    def _no_whitespace(cls, v: str) -> str:
        if re.search(r"\s", v):
            raise ValueError("tool_name must not contain whitespace")
        return v

    @field_validator("arguments")
    @classmethod
    def _json_serializable(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        try:
            json.dumps(v)
        except (TypeError, ValueError):
            raise ValueError("arguments must be JSON-serializable")
        return v

    def to_wire_text(self) -> str:
        """Render as the `tool:NAME args:{json}` string the ministers parse."""
        return f"tool:{self.tool_name} args:{json.dumps(self.arguments)}"


class MinisterResult(BaseModel):
    minister: str
    verdict: str
    reason: str
    matched_id: Optional[str] = None
    confidence: Optional[float] = None
    diagnostics: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("verdict")
    @classmethod
    def _valid_verdict(cls, v: str) -> str:
        if v not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        return v


class Decision(BaseModel):
    verdict: str
    reason: str
    decided_by: str
    session_id: str
    ministers: Dict[str, MinisterResult]

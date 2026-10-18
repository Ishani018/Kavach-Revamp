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
from typing import Any, Dict, List, Optional

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
    # Which agent proposed the call: the host's sub-agent id, if any. State is
    # shared across the agent tree (see kavach/agents.py); this is attribution.
    agent_id: Optional[str] = Field(default=None, max_length=256)
    agent_type: Optional[str] = Field(default=None, max_length=256)
    # Depth in the agent tree (0 = the session's main agent). Set by the
    # Coordinator from its own registry; any caller-supplied value is replaced.
    agent_depth: int = Field(default=0, ge=0)

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
    # Agent attribution: the domain is the root session whose state was used.
    agent_id: Optional[str] = None
    domain_id: Optional[str] = None
    agent_depth: int = 0


# Hook events that report something that already happened rather than proposing
# an action. Content events carry text the ministers inspect (a prompt, a tool's
# output, a sub-agent's report, the final answer); lifecycle events only update
# the agent tree. Nothing here can un-run a tool.
CONTENT_EVENTS = ("UserPromptSubmit", "PostToolUse", "SubagentStop", "Stop")
LIFECYCLE_EVENTS = ("SessionStart", "SubagentStart", "PreCompact")
OBSERVATION_EVENTS = CONTENT_EVENTS + LIFECYCLE_EVENTS
MAX_OBSERVED_TEXT_CHARS = 2_000_000


class Observation(BaseModel):
    event: str
    session_id: str = Field(min_length=1)
    # The prompt (UserPromptSubmit), tool output (PostToolUse), sub-agent report
    # (SubagentStop) or final answer (Stop). Empty for lifecycle events.
    text: str = Field(default="", max_length=MAX_OBSERVED_TEXT_CHARS)
    # PostToolUse only: the call that produced `text`.
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    agent_id: Optional[str] = Field(default=None, max_length=256)
    agent_type: Optional[str] = Field(default=None, max_length=256)
    # SessionStart only: link this session under another session's agent tree.
    parent_session_id: Optional[str] = Field(default=None, max_length=512)
    parent_agent_id: Optional[str] = Field(default=None, max_length=256)

    @field_validator("event")
    @classmethod
    def _known_event(cls, v: str) -> str:
        if v not in OBSERVATION_EVENTS:
            raise ValueError(f"event must be one of {OBSERVATION_EVENTS}")
        return v

    @model_validator(mode="after")
    def _event_fields(self) -> "Observation":
        if self.event == "PostToolUse" and not (self.tool_name and self.tool_name.strip()):
            raise ValueError("PostToolUse observations need tool_name")
        if self.event in ("SubagentStart", "SubagentStop") and not self.agent_id:
            raise ValueError(f"{self.event} observations need agent_id")
        if self.parent_session_id and self.event != "SessionStart":
            raise ValueError("parent_session_id is only accepted at SessionStart")
        return self


class SessionSummary(BaseModel):
    """Privacy-safe facts about a domain, for re-injecting into an agent's
    context (session start, sub-agent start, after compaction). Rule IDs and
    counts only; never prompt text, arguments, outputs or secret values."""

    domain_id: str
    agents: int = 1
    checks: int = 0
    blocked: int = 0
    escalated: int = 0
    secret_observations: int = 0
    holds_sensitive_data: bool = False
    recent_denials: List[Dict[str, Any]] = Field(default_factory=list)


class ObservationDecision(BaseModel):
    """Same shape as Decision, plus the event. `ministers` holds only the
    ministers that inspect this event type; ALLOW means none of them found
    anything, not that all four were consulted."""

    event: str
    verdict: str
    reason: str
    decided_by: str
    session_id: str
    ministers: Dict[str, MinisterResult]
    agent_id: Optional[str] = None
    domain_id: Optional[str] = None
    agent_depth: int = 0
    summary: Optional[SessionSummary] = None

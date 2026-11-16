from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol


class Verdict(str, Enum):
    ALLOW = "allow"
    ASK = "ask"      # stop and ask the human
    BLOCK = "block"

    @property
    def severity(self) -> int:
        return {"allow": 0, "ask": 1, "block": 2}[self.value]


class Origin(str, Enum):
    USER = "user"          # the value appears in the user's request
    READ = "read"          # the value appears only in something the agent read from a tool
    NEW = "new"            # the value appears in neither (the agent composed it)
    UNTRACED = "untraced"  # too short or not text-like to trace reliably


@dataclass(frozen=True)
class Action:
    """One tool call the agent wants to make."""
    tool: str
    args: dict[str, Any]
    # Declared by the tool itself (for example MCP's readOnlyHint), never by a list we maintain.
    # None means the tool declares nothing; it is then treated as state-changing.
    changes_state: Optional[bool] = None


@dataclass
class Session:
    """What a reviewer may know: the user's request and the text the agent has read so far."""
    user_request: str
    observations: list[str] = field(default_factory=list)

    def observe(self, tool_output: str) -> None:
        self.observations.append(tool_output)


@dataclass(frozen=True)
class Opinion:
    reviewer: str
    verdict: Verdict
    reason: str


class Reviewer(Protocol):
    name: str

    def review(self, action: Action, session: Session) -> Opinion: ...

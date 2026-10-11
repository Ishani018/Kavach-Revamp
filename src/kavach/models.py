"""Shared types used by every minister and the Speaker."""
from dataclasses import dataclass
from enum import Enum
from typing import Any


class VoteKind(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    ABSTAIN = "ABSTAIN"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class ActionEvent:
    """The proposed tool action visible to Kavach at its interception point."""
    tool_name: str
    operation: str
    arguments: dict[str, Any]
    session_id: str = "unknown"


@dataclass(frozen=True)
class Vote:
    minister: str
    kind: VoteKind
    reason: str

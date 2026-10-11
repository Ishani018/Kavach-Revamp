"""Versioned event and decision contracts. No runtime-specific dependencies."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Visibility(str, Enum):
    PRESENT = "present"
    REDACTED = "redacted"
    SANITIZED = "sanitized"
    OMITTED = "omitted"
    NOT_AVAILABLE = "not_available"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class RuntimeInfo:
    name: str
    interception_point: str


@dataclass(frozen=True)
class Action:
    tool_name: str
    operation: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionEvent:
    schema_version: str
    event_id: str
    session_id: str
    runtime: RuntimeInfo
    action: Action
    visibility: dict[str, Visibility]
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyFinding:
    policy_id: str
    decision: Decision
    reason_code: str
    message: str
    required_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class MonitorResult:
    event_id: str
    decision: Decision
    reason_codes: tuple[str, ...]
    policy_ids: tuple[str, ...]
    findings: tuple[PolicyFinding, ...] = ()

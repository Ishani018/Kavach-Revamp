"""
kavach/ministers/navigator2
============================

NAVIGATOR 2.0 prototype: Intent & Trajectory Intelligence.

**This package is shadow-mode only.** Nothing here is imported by
`kavach/coordinator.py`, `kavach/api.py`, or `kavach/ministers/navigator.py`.
It cannot affect a production `Decision` unless a caller explicitly
constructs `ShadowRunner` (see `shadow.py`) and reads its second return value.

See `docs/navigator2-architecture.md` for the full design and
`docs/navigator2-research.md` for the sources it draws on.
"""

from __future__ import annotations

from .schemas import (
    ConfidentialityLabel,
    ContractRevision,
    EvidenceFinding,
    IntegrityLabel,
    Navigator2Verdict,
    PolicyDecision,
    ReasonerRequest,
    ReasonerResponse,
    SessionEvent,
    TaskContract,
)
from .core import Navigator2
from .shadow import ShadowRunner

__all__ = [
    "ConfidentialityLabel",
    "ContractRevision",
    "EvidenceFinding",
    "IntegrityLabel",
    "Navigator2Verdict",
    "PolicyDecision",
    "ReasonerRequest",
    "ReasonerResponse",
    "SessionEvent",
    "TaskContract",
    "Navigator2",
    "ShadowRunner",
]

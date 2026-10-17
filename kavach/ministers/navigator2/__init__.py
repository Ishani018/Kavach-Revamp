"""
kavach/ministers/navigator2
============================

NAVIGATOR 2.0: intent and trajectory policy engine.

On the navigator-invariant-runtime branch, NavigatorMinister activates
Navigator2 through kavach/ministers/navigator.py. ShadowRunner remains
available as an isolated regression/evaluation harness.

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

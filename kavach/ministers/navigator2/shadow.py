"""
kavach/ministers/navigator2/shadow.py
========================================

The ONLY integration point between NAVIGATOR 2.0 and the real Coordinator.
This module imports kavach.coordinator.Coordinator and kavach.schemas for
READING ONLY -- it never edits those files, never subclasses Coordinator,
and never feeds a Navigator2Verdict back into a Decision.

`ShadowRunner.evaluate_shadow(call)`:
  1. Calls `self.coordinator.evaluate(call)` EXACTLY as kavach/api.py does.
     This line is the entire "production path" and is byte-for-byte what
     already ran before this package existed.
  2. Separately builds a Navigator2 assessment from the SAME call and the
     Decision's own `ministers` dict (no second embed, no second EXECUTOR/
     VAULT run -- it reuses the real results the Coordinator just computed).
  3. If step 2 raises for any reason, the exception is caught here and
     recorded; the production Decision from step 1 is returned unchanged.

Because step 1 is simply "call the existing method," the production path is
trivially byte-for-byte identical whether or not this module is imported,
used, or even present at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Union

from ...coordinator import Coordinator
from ...schemas import Decision, ToolCall
from .core import Navigator2
from .schemas import Navigator2Verdict


@dataclass
class ShadowResult:
    decision: Decision                       # the real, unmodified production Decision
    navigator2_verdict: Optional[Navigator2Verdict]
    navigator2_error: Optional[str] = None   # set if Navigator2 itself raised; decision is still valid


class ShadowRunner:
    def __init__(self, coordinator: Coordinator, navigator2: Optional[Navigator2] = None) -> None:
        self.coordinator = coordinator
        self.navigator2 = navigator2 or Navigator2()

    def evaluate_shadow(self, call: Union[ToolCall, Mapping[str, Any]]) -> ShadowResult:
        decision = self.coordinator.evaluate(call)  # unchanged production path

        if not isinstance(call, ToolCall):
            call = ToolCall.model_validate(call)

        try:
            verdict = self.navigator2.check(call, legacy_results=decision.ministers)
            return ShadowResult(decision=decision, navigator2_verdict=verdict)
        except Exception as e:  # a shadow-mode failure can NEVER affect the returned Decision
            return ShadowResult(decision=decision, navigator2_verdict=None, navigator2_error=f"{type(e).__name__}: {e}")

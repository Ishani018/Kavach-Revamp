"""The four ministers. Each exposes name and check(ToolCall) -> MinisterResult."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from ..schemas import MinisterResult

if TYPE_CHECKING:
    from .retrieval import MinisterScan

MAX_REASON = 300


def scan_to_result(scan: Optional[MinisterScan], name: str, *, redact_match: bool = False) -> MinisterResult:
    """Normalize a legacy MinisterScan (None means the rule set found nothing)
    into a MinisterResult.

    redact_match: omit the matched text from the reason. VAULT uses this so a
    detected secret is never echoed back in a response or log."""
    if scan is None:
        return MinisterResult(minister=name, verdict="ALLOW", reason=f"{name}: no rule matched")
    if redact_match:
        reason = f"{name} rule {scan.matched_id} matched (match text withheld)"
    else:
        reason = (scan.matched_text or f"{name} matched {scan.matched_id}")[:MAX_REASON]
    return MinisterResult(
        minister=name,
        verdict=scan.verdict,
        reason=reason,
        matched_id=scan.matched_id,
        confidence=scan.confidence,
        diagnostics={
            "level": scan.matched_level,
            "source": scan.source,
            "mode": scan.retrieval_mode,
        },
    )


def __getattr__(name: str):
    """Load the legacy embedding/BM25 result type only when explicitly requested."""
    if name == "MinisterScan":
        from .scan import MinisterScan
        return MinisterScan
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""Lightweight shared minister result type; intentionally has no retrieval dependencies."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MinisterScan:
    minister: str
    verdict: str
    confidence: float
    matched_id: str | None
    matched_text: str | None
    matched_level: str | None
    source: str | None = None
    retrieval_mode: str = "dense"

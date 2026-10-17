"""
kavach/ministers/navigator2/ledger.py
========================================

Component 2 -- Session Event Ledger / Action Graph.

Plain in-memory dict[session_id, list[SessionEvent]], matching the
per-session-state convention ChannelMinister already uses
(kavach/ministers/channel.py's self._taint / self._provenance). One
session's events can never be read as another session's evidence because the
ledger is keyed by session_id and every lookup method takes one.

Explicit behaviour for missing/truncated/unavailable history (required by the
task brief): an unknown session or an empty history returns `[]`, never an
error and never an inferred "nothing happened." Consumers (evidence modules,
policies) must treat an empty or gapped history as REDUCED evidence, not as
proof of safety -- see policy.py's POL-007.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .schemas import SessionEvent


class SessionEventLedger:
    def __init__(self) -> None:
        self._events: Dict[str, List[SessionEvent]] = {}
        self._by_id: Dict[str, SessionEvent] = {}
        self._seq_counters: Dict[str, int] = {}

    def next_seq(self, session_id: str) -> int:
        n = self._seq_counters.get(session_id, 0)
        self._seq_counters[session_id] = n + 1
        return n

    def make_event_id(self, session_id: str, seq: int) -> str:
        return f"{session_id}:{seq:06d}"

    def check_parents(self, session_id: str, parent_event_ids: List[str]) -> bool:
        """Returns True if every named parent is actually in the ledger for
        THIS session. An empty parent list is trivially fine (first event)."""
        if not parent_event_ids:
            return True
        session_ids = {e.event_id for e in self._events.get(session_id, [])}
        return all(p in session_ids for p in parent_event_ids)

    def append(self, event: SessionEvent) -> None:
        self._events.setdefault(event.session_id, []).append(event)
        self._by_id[event.event_id] = event

    def get(self, event_id: str) -> Optional[SessionEvent]:
        return self._by_id.get(event_id)

    def all_events(self, session_id: str) -> List[SessionEvent]:
        """Full history for this session only. Never raises on an unknown
        session_id -- returns []."""
        return list(self._events.get(session_id, []))

    def recent(self, session_id: str, n: int = 20) -> List[SessionEvent]:
        events = self._events.get(session_id, [])
        return list(events[-n:]) if events else []

    def session_count(self, session_id: str) -> int:
        return len(self._events.get(session_id, []))

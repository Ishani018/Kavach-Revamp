"""
kavach/ministers/navigator2/contract.py
==========================================

Component 1 -- Trusted Task Contract.

The CaMeL-derived trust boundary (docs/navigator2-research.md SS B) lives
here: `TaskContractStore.revise()` is the ONLY way to change a contract, and
it refuses any revision whose source event is not IntegrityLabel.TRUSTED_INSTRUCTION.
A tool result, file, webpage, or model-generated summary can never reach this
path successfully -- it can only ever become evidence handed to the reasoner.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .schemas import ContractRevision, IntegrityLabel, SessionEvent, TaskContract

# Fields a revision is allowed to touch. Anything else is rejected even from a
# trusted source -- session_id, version, and history are store-managed, not
# user-settable.
_REVISABLE_FIELDS = frozenset({
    "goal",
    "workspace_scope",
    "permitted_categories",
    "denied_categories",
    "approved_destinations",
    "high_impact_categories_requiring_approval",
    "unresolved_ambiguities",
})


class UntrustedRevisionAttempt(Exception):
    """Raised when something other than a trusted instruction tries to
    change a TaskContract. Callers should treat this as security-relevant
    evidence (see policy.py POL-003), not merely swallow it."""

    def __init__(self, session_id: str, event_id: Optional[str], integrity: IntegrityLabel, changed_fields: Dict[str, Any]):
        self.session_id = session_id
        self.event_id = event_id
        self.integrity = integrity
        self.changed_fields = changed_fields
        super().__init__(
            f"session {session_id}: refused contract revision from event {event_id} "
            f"(integrity={integrity.value}, needs {IntegrityLabel.TRUSTED_INSTRUCTION.value}); "
            f"fields={sorted(changed_fields)}"
        )


class TaskContractStore:
    """In-memory, per-session_id store -- same scoping convention
    ChannelMinister already uses for its own per-session state
    (kavach/ministers/channel.py)."""

    def __init__(self) -> None:
        self._contracts: Dict[str, TaskContract] = {}

    def get(self, session_id: str) -> Optional[TaskContract]:
        return self._contracts.get(session_id)

    def get_or_create(self, session_id: str) -> TaskContract:
        """Auto-creates a version-0, deliberately UNSCOPED contract if none
        exists. Empty permitted_categories/approved_destinations means
        positive-authorization policies (POL-001/002/006) cannot find
        authorization and lean toward escalate -- this is not the same as a
        maximally permissive default."""
        c = self._contracts.get(session_id)
        if c is not None:
            return c
        c = TaskContract(
            session_id=session_id,
            version=0,
            unresolved_ambiguities=["no explicit task contract provided; defaulting to a minimal, unscoped contract"],
        )
        self._contracts[session_id] = c
        return c

    def start_session(
        self,
        session_id: str,
        *,
        goal: str,
        workspace_scope: Optional[List[str]] = None,
        permitted_categories: Optional[List[str]] = None,
        denied_categories: Optional[List[str]] = None,
        approved_destinations: Optional[List[str]] = None,
        high_impact_categories_requiring_approval: Optional[List[str]] = None,
        unresolved_ambiguities: Optional[List[str]] = None,
        created_from_event_id: Optional[str] = None,
    ) -> TaskContract:
        """Explicitly create version-1 contract. Called once at the start of a
        session when the caller actually has the user's stated goal/scope.
        Overwrites an existing auto-created version-0 contract for this
        session (but never a version >= 1 one -- call revise() for that)."""
        existing = self._contracts.get(session_id)
        if existing is not None and existing.version >= 1:
            raise ValueError(f"session {session_id} already has an explicit contract (version {existing.version})")
        c = TaskContract(
            session_id=session_id,
            version=1,
            goal=goal,
            workspace_scope=list(workspace_scope or []),
            permitted_categories=list(permitted_categories or []),
            denied_categories=list(denied_categories or []),
            approved_destinations=list(approved_destinations or []),
            high_impact_categories_requiring_approval=list(high_impact_categories_requiring_approval or []),
            unresolved_ambiguities=list(unresolved_ambiguities or []),
            created_from_event_id=created_from_event_id,
            history=[
                ContractRevision(
                    version=1,
                    event_id=created_from_event_id,
                    integrity=IntegrityLabel.TRUSTED_INSTRUCTION,
                    accepted=True,
                    reason="initial contract from explicit session start",
                    changed_fields={"goal": goal},
                )
            ],
        )
        self._contracts[session_id] = c
        return c

    def revise(self, session_id: str, event: SessionEvent, changed_fields: Dict[str, Any]) -> TaskContract:
        """The only mutator. Raises UntrustedRevisionAttempt if `event` is not
        a trusted instruction. `changed_fields` must be a subset of
        _REVISABLE_FIELDS; anything else is dropped (not silently applied)."""
        contract = self.get_or_create(session_id)
        accepted_fields = {k: v for k, v in changed_fields.items() if k in _REVISABLE_FIELDS}

        if event.integrity != IntegrityLabel.TRUSTED_INSTRUCTION:
            # Record the rejected attempt in history for audit, then raise.
            contract.history.append(
                ContractRevision(
                    version=contract.version,
                    event_id=event.event_id,
                    integrity=event.integrity,
                    accepted=False,
                    reason="revision source is not a trusted instruction; rejected",
                    changed_fields=accepted_fields,
                )
            )
            raise UntrustedRevisionAttempt(session_id, event.event_id, event.integrity, accepted_fields)

        new_version = contract.version + 1
        updated = contract.model_copy(update={**accepted_fields, "version": new_version})
        updated.history = list(contract.history) + [
            ContractRevision(
                version=new_version,
                event_id=event.event_id,
                integrity=event.integrity,
                accepted=True,
                reason="trusted instruction revision",
                changed_fields=accepted_fields,
            )
        ]
        self._contracts[session_id] = updated
        return updated

"""parliament/navigator_authflow.py
===================================

NAVIGATOR redesign, built independently on kavach-rearch (see README's
SCOPE/PLAN sections for the full design rationale). This is a genuinely
separate, parallel effort from any other NAVIGATOR work happening
elsewhere — not a completion of, comparison to, or reconciliation with
it. Gate-then-build discipline throughout: this file implements pieces
1-2 (pinned intent, observational/consequential taxonomy) only. Pieces
3-4 (hard constraint, authorized-flow derivation) are NOT implemented
here yet — they come after a discriminability census against the 22
real benign sessions + AgentDojo attack cases, per the standing
gate-then-build rule this whole project follows.

NAVIGATOR's post-rearchitecture question, distinct from the other three
ministers: was THIS ACTION itself authorized by what the user asked for?
(CHANNEL asks where data came from/is going; VAULT asks if this looks
like a credential; EXECUTOR asks if this looks like dangerous code.)

Piece 1 — PINNED INTENT
------------------------
Captured ONCE, from the user's own original instruction, at the first
call seen in a session. Never updated from tool_output or any later
call at any point in the session — this immutability IS the security
property (a pinned intent that could be mutated by something the agent
reads mid-session would be exactly as injectable as the data it's
meant to gate). Same session-state architectural pattern as
channel_taint.py's SessionProvenance / new_provenance_state() and
server.py's _state dict (a session_id-keyed defaultdict, owned by the
caller, same lifecycle).

Piece 2 — OBSERVATIONAL vs CONSEQUENTIAL TAXONOMY
----------------------------------------------------
A static, two-class split over the real tool surface (confirmed
directly against AgentDojo's four suites -- banking/travel/workspace/
slack, 69 real tool names, not guessed). OBSERVATIONAL = read/list/
search/get/view/check, no external effect. CONSEQUENTIAL = send/
transfer/invite/delete/unlock/schedule/post/create/update/cancel/
reschedule/remove/add/share/append -- external or irreversible effect.
Ambiguous tools are flagged explicitly as their own third class, never
force-classified -- per the real tool surface, update_password and
update_user_info are the clearest ambiguous case: they mutate account
state (consequential-shaped) but only affect the calling user's own
account, self-directed rather than externally consequential (unlike
send_money/send_email/invite_user_to_slack, which affect someone/
something outside the session). Forcing these into either bucket would
be a real classification error in one direction or the other -- kept
explicit instead.

Reuses channel_taint.py's _tokenize_tool_name() for the regex-fallback
path (verb-prefix matching on snake_case/camelCase/PascalCase tool
names not in the exact-match lists) rather than reimplementing
tokenization -- same tool-naming-convention-agnostic fix already
built and tested for CHANNEL's source-tool matching tonight.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .channel_taint import _tokenize_tool_name

# ──────────────────────────────────────────────────────────────────────────────
# Piece 1 — Pinned intent
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class PinnedIntent:
    """Per-session pinned intent state. `text` is set exactly once, on
    the first call `capture()` is invoked for a session, and never
    changed after -- see module docstring for why immutability is the
    security property here, not an implementation detail."""
    text: str | None = None
    captured: bool = False


def new_pinned_intent_state() -> PinnedIntent:
    """Factory for a fresh per-session pinned-intent state (use via
    defaultdict, same pattern as channel_taint.new_provenance_state())."""
    return PinnedIntent()


def capture_intent(state: PinnedIntent, user_instruction: str | None) -> None:
    """Capture the user's original instruction ONCE. A caller that never
    supplies user_instruction, or calls this again later in the same
    session, has no effect after the first successful capture -- pinned
    intent is immutable once set, by design. Mutates `state` in place,
    same convention as check_provenance()/check_channel_taint()."""
    if state.captured:
        return
    if user_instruction:
        state.text = user_instruction
        state.captured = True


# ──────────────────────────────────────────────────────────────────────────────
# Piece 2 — Observational vs. consequential taxonomy
# ──────────────────────────────────────────────────────────────────────────────

Classification = Literal["OBSERVATIONAL", "CONSEQUENTIAL", "AMBIGUOUS"]

# Exact-match sets, confirmed directly against AgentDojo v1.2's real
# tool surface (banking/travel/workspace/slack, 69 total tool names) --
# not guessed from naming convention alone, though the regex fallback
# below extends to novel tool names following the same verb-prefix
# pattern for tools outside this exact corpus.

OBSERVATIONAL_TOOLS: frozenset[str] = frozenset({
    # banking
    "get_balance", "get_iban", "get_most_recent_transactions",
    "get_scheduled_transactions", "get_user_info", "read_file",
    # travel
    "check_restaurant_opening_hours", "get_all_car_rental_companies_in_city",
    "get_all_hotels_in_city", "get_all_restaurants_in_city",
    "get_car_fuel_options", "get_car_price_per_day", "get_car_rental_address",
    "get_car_types_available", "get_contact_information_for_restaurants",
    "get_cuisine_type_for_restaurants", "get_day_calendar_events",
    "get_dietary_restrictions_for_all_restaurants", "get_flight_information",
    "get_hotels_address", "get_hotels_prices", "get_price_for_restaurants",
    "get_rating_reviews_for_car_rental", "get_rating_reviews_for_hotels",
    "get_rating_reviews_for_restaurants", "get_restaurants_address",
    "get_user_information", "search_calendar_events",
    # workspace
    "get_current_day", "get_draft_emails", "get_file_by_id",
    "get_received_emails", "get_sent_emails", "get_unread_emails",
    "list_files", "search_contacts_by_email", "search_contacts_by_name",
    "search_emails", "search_files", "search_files_by_filename",
    # slack
    "get_channels", "get_users_in_channel", "get_webpage",
    "read_channel_messages", "read_inbox",
})

CONSEQUENTIAL_TOOLS: frozenset[str] = frozenset({
    # banking
    "schedule_transaction", "send_money", "update_scheduled_transaction",
    # travel
    "cancel_calendar_event", "create_calendar_event", "reserve_car_rental",
    "reserve_hotel", "reserve_restaurant", "send_email",
    # workspace
    "add_calendar_event_participants", "append_to_file", "create_file",
    "delete_email", "delete_file", "reschedule_calendar_event", "share_file",
    # slack
    "add_user_to_channel", "invite_user_to_slack", "post_webpage",
    "remove_user_from_slack", "send_channel_message", "send_direct_message",
})

# Genuinely ambiguous -- mutates persistent state but is self-directed
# (affects only the calling user's own account/data), not clearly
# "external effect" the way send_money/send_email/invite_user_to_slack
# are. Explicitly flagged rather than force-classified into either
# bucket; see module docstring for the reasoning.
AMBIGUOUS_TOOLS: frozenset[str] = frozenset({
    "update_password", "update_user_info",
})

# Regex-fallback verb families for tool names outside the exact-match
# corpus above, using the SAME tokenizer channel_taint.py already built
# and tested for naming-convention-agnostic matching (snake_case/
# camelCase/PascalCase all normalize to the same token list).
_OBSERVATIONAL_VERB_TOKENS = frozenset({
    "get", "list", "search", "read", "check", "view", "find",
})
_CONSEQUENTIAL_VERB_TOKENS = frozenset({
    "send", "create", "delete", "update", "cancel", "reserve", "schedule",
    "invite", "remove", "add", "share", "post", "append", "reschedule",
    "transfer", "grant", "revoke", "unlock", "lock", "pay", "withdraw",
    "deposit", "modify", "write",
})


def classify_tool(tool_name: str) -> Classification:
    """Returns OBSERVATIONAL, CONSEQUENTIAL, or AMBIGUOUS for the given
    tool name. Exact-match sets checked first (confirmed against the
    real AgentDojo tool surface); falls through to a verb-prefix regex
    family for novel tool names following the same naming pattern,
    using channel_taint.py's own tokenizer. A tool name whose first
    token matches BOTH verb families (shouldn't happen given the two
    sets above are disjoint, but defensive) or NEITHER family falls to
    AMBIGUOUS -- conservative bias, same discipline as struct_parse.py:
    an unclassifiable tool costs an extra flag for review, never a
    silent miscategorization."""
    if tool_name in AMBIGUOUS_TOOLS:
        return "AMBIGUOUS"
    if tool_name in OBSERVATIONAL_TOOLS:
        return "OBSERVATIONAL"
    if tool_name in CONSEQUENTIAL_TOOLS:
        return "CONSEQUENTIAL"

    tokens = _tokenize_tool_name(tool_name)
    first = tokens[0] if tokens else ""
    is_obs = first in _OBSERVATIONAL_VERB_TOKENS
    is_conseq = first in _CONSEQUENTIAL_VERB_TOKENS
    if is_obs and not is_conseq:
        return "OBSERVATIONAL"
    if is_conseq and not is_obs:
        return "CONSEQUENTIAL"
    return "AMBIGUOUS"

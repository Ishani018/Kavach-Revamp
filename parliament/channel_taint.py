"""
parliament/channel_taint.py
============================

Stage 2 of the Kavach re-architecture (docs/status/REARCHITECTURE_PLAN.md §2, CHANNEL):
symbolic taint tracking for the read-sensitive-data -> send-externally exfil
shape. The taint/lattice model itself is borrowed (Denning 1976, realized in
CaMeL/FIDES/NeuroTaint) -- not novel. What's novel here is applying it to
Kavach's own tool-call surface plus a destination allow-list scoped to the
tool suites Kavach actually screens (AgentDojo workspace/slack/banking).

UNLIKE VAULT/EXECUTOR: this is inherently a multi-call, SESSION-level
pattern -- the sensitive read and the external send are different tool
calls in the same session. A single-call regex (prefilters.py's shape)
cannot express this; it needs state that persists across calls within a
session.

Session-state mechanism (design decision, made explicit rather than
silently reusing trajectory.py):
    trajectory.py's ActionRecord/_state["history"] was read in full before
    designing this. It is cosine-only by explicit design constraint (module
    docstring: "no re-embedding... performs ONLY cosine math over cached
    768-dim vectors") and its ActionRecord dataclass stores only the BGE
    vector + verdict metadata -- no raw tool name or args. Taint requires
    knowing the ACTUAL tool identity (is this call a sensitive-read tool?
    a destination tool?), which an embedding alone can't answer reliably
    for the same reason VAULT/EXECUTOR moved off cosine. Rather than
    overload ActionRecord with fields trajectory.py's five cosine signals
    don't use, channel_taint.py keeps its OWN small per-session taint-tag
    store, mirroring the exact pattern server.py already uses for
    _state["history"] / _state["intents"] (a session_id-keyed dict, same
    lifecycle, same place it would be wired into _state). This is a
    deliberate choice, flagged for review before the dispatch-wiring pass:
    an alternative would be to extend ActionRecord with a `tool` field and
    fold taint into trajectory.py directly. Kept separate here because
    trajectory.py's risk signals are continuous/cosine-based and taint is
    a discrete boolean lattice -- mixing them would blur trajectory.py's
    own "pure cosine math" design constraint for no benefit.

TAINT MODEL
    A call to a SOURCE tool (reads domain-specific sensitive data) marks
    the session TAINTED, tagged with which source fired. A subsequent call
    in the SAME session to a DESTINATION tool (external communication) is
    BLOCKed if the session is tainted AND the destination is not on the
    allow-list. No allow-list match + no taint -> ALLOW. Taint persists for
    the rest of the session (matches CHAN-102's "any subsequent send" L2
    mechanism; a single-session TTL/expiry was considered and rejected --
    the 32 ground-truth cases are all two-call sessions, no evidence a
    decay window is needed yet, and premature decay risks under-catching).

SOURCE definition (design decision, justified):
    Fixed tool-name pattern, NOT a keyword-in-args check or a
    NAVIGATOR-adjacent signal. Justification: the actual attack corpus
    (attacker_cases_ds.jsonl, all 32 cases) uses a clean, structural verb-
    prefix shape (Get/View/Search/List/Download/Access + a domain-specific
    sensitive noun: address, payment, holdings, genetic, health, password,
    access-history, log, location). This is the same "deterministic beats
    cosine when the shape is structural" thesis VAULT/EXECUTOR already
    validated. Scoped to DOMAIN-SPECIFIC sensitive nouns specifically so
    ordinary reads (read_file, get_balance, get_most_recent_transactions,
    get_scheduled_transactions, get_user_info) do NOT taint -- confirmed
    necessary by real benign trajectories in benign_v0.json's own source
    data (real_benign_trajectories.json): "read_file -> send_money" (pay a
    bill) and "get_most_recent_transactions -> send_money" (goal_as_task
    cases) are both real, legitimate, same-session read-then-send chains
    that must NOT taint, or CHANNEL would immediately re-create Stage 1's
    kind of false-positive problem on the banking domain alone.

DESTINATION definition + allow-list (design decision, flagged explicitly):
    Destination tools are AgentDojo's real outbound-communication surface,
    confirmed directly against the installed agentdojo package (not
    guessed): workspace's send_email/share_file, slack's
    send_direct_message/send_channel_message/invite_user_to_slack, and
    banking's send_money/schedule_transaction (recipient=IBAN, matching
    the plan's explicit "IBANs" destination-surface mention). Each has a
    known recipient-argument key (recipients/email/recipient/channel/user).
    Allow-list is EMPTY by default -- there is no corpus evidence of a
    "trusted" email/Slack recipient distinct from an attacker-controlled
    one (all 32 ground-truth cases target amy.watson@gmail.com /
    john.doe@gmail.com, both attacker-supplied, never the session's own
    user). An empty allow-list means: tainted session + ANY destination
    call -> BLOCK. This is the conservative choice and is flagged here
    rather than picked silently -- a real deployment would need to seed
    this with the actual user's own verified email/Slack handle (e.g. from
    seed_intent or a user-profile call), which Kavach does not currently
    capture anywhere. Left as an explicit gap for whoever wires a user-
    identity source in later, not a silent assumption.

    send_money/schedule_transaction are NOT exempted as a special case --
    they are real destination tools per AgentDojo's banking suite and the
    plan's own IBAN mention. They simply never fire here because ordinary
    banking reads are correctly excluded from SOURCE, so a taint is never
    present when send_money is legitimately reached from a user-stated
    bill-pay/transfer instruction. This is scope-correct, not a carve-out.

Output shape mirrors prefilters.py exactly: MinisterScan, confidence=1.0
on a hit / 0.0 otherwise, retrieval_mode="deterministic",
matched_level="deterministic".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ministers import MinisterScan
from .prefilters import ParsedCall, parse_call, _flatten_arg_values


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE tools — domain-specific sensitive-data reads
# ──────────────────────────────────────────────────────────────────────────────
# Two layers, both required to taint conservatively:
#   (a) exact match against the 32 corpus-confirmed read-tool names (CHAN-102's
#       own evidence base) -- guarantees the ground-truth set is covered even
#       if the lexical pattern below is ever tightened.
#   (b) a generalizable lexical pattern: Service + (Get|View|Search|List|
#       Download|Access) + a domain-specific sensitive noun. Requires the
#       sensitive-noun component specifically so generic reads (read_file,
#       get_balance, get_user_info, get_most_recent_transactions,
#       get_scheduled_transactions) do NOT match -- verified against
#       benign_v0.json's real trajectories below.

SOURCE_TOOLS_EXACT: frozenset[str] = frozenset({
    "AmazonViewSavedAddresses", "AmazonViewSavedPaymentMethods",
    "AugustSmartLockViewAccessHistory", "BankManagerGetAccountInformation",
    "BankManagerSearchPayee", "BinanceGetOrderHistory",
    "CiscoUmbrellaGetLogDetails", "DeepfakeGeneratorGenerateAudioDeepfake",
    "DropboxGetItemMetadata", "DropboxListFilesAndFolders",
    "EpicFHIRDownloadFiles", "EpicFHIRGetPatientDetails",
    "ExpediaSearchReservations", "FacebookManagerGetUserProfile",
    "FacebookManagerSearchFriends", "FedExShipManagerSearchShipment",
    "GitHubGetUserDetails", "GoogleMapGetCurrentLocation",
    "GoogleSearchGetSearchHistory", "InvestmentManagerGetHoldingsInformation",
    "NortonIdentitySafeSearchPasswords", "SpokeoDownloadPublicRecord",
    "SpokeoSearchPeople", "TDAmeritradeGetHoldingsInformation",
    "TeladocAccessUserInfo", "TeladocViewPrescriptions",
    "The23andMeDownloadData", "The23andMeGetGeneticData",
    "The23andMeGetHealthRecommendations", "TwilioGetPhoneNumberInfo",
    "VenmoListLinkedAccounts", "WebBrowserSearchHistory",
})

_SENSITIVE_NOUN = (
    r"(Address|Payment|Holdings?|Genetic|Health|Password|AccessHistory|Log|"
    r"Location|Prescription|PatientDetail|Record|Metadata|SearchHistory|"
    r"PhoneNumber|LinkedAccount|UserProfile|UserDetail|UserInfo|Friend|"
    r"Reservation|Shipment|OrderHistory|Deepfake)"
)
_SOURCE_VERB = r"(Get|View|Search|List|Download|Access)"
SOURCE_TOOL_PATTERN = re.compile(rf"^\w*{_SOURCE_VERB}\w*{_SENSITIVE_NOUN}\w*$")

# ──────────────────────────────────────────────────────────────────────────────
# Naming-convention-agnostic fallback (found via ground-truth replay against
# AgentDojo: SOURCE_TOOL_PATTERN above requires PascalCase adjacency, so it
# cannot match ANY snake_case tool name regardless of semantic content --
# confirmed directly, e.g. AmazonViewSavedAddresses matches but a
# semantically-identical snake_case equivalent structurally cannot).
#
# Fix: tokenize the tool name (snake_case, camelCase, PascalCase all split to
# a common lowercase token list), then check for verb-token + noun-token
# co-occurrence ANYWHERE in the token list, rather than requiring adjacent
# PascalCase substring structure. Uses the EXACT SAME vocabulary as
# SOURCE_TOOL_PATTERN above -- no new nouns/verbs added here. This
# deliberately does NOT add AgentDojo-specific tool names (e.g.
# search_emails, read_channel_messages) as new source triggers: confirmed
# via direct testing against real AgentDojo ground_truth() data that doing
# so would false-positive on 2 real workspace user_tasks and 9/21 (43%) of
# slack user_tasks, where the exact same read-then-send shape is the
# correct, user-requested action, not an attack (same conflict already
# documented above for banking's get_most_recent_transactions/
# get_scheduled_transactions). So this fix closes the NAMING-CONVENTION gap
# only -- it does not and should not expand semantic coverage, which would
# require a signal CHANNEL's session-taint model doesn't have (was this
# specific recipient/content requested by the user, not just "was there a
# prior read").
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def _tokenize_tool_name(tool: str) -> list[str]:
    """Splits snake_case, kebab-case, camelCase, and PascalCase tool names
    into a common lowercase token list. E.g. 'AmazonViewSavedAddresses' and
    'amazon_view_saved_addresses' both -> ['amazon','view','saved','addresses']."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", tool)          # camelCase/PascalCase boundary
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)            # e.g. HTTPServer -> HTTP_Server
    return [p.lower() for p in _TOKEN_SPLIT_RE.split(s) if p]


_SOURCE_VERB_TOKENS = frozenset({"get", "view", "search", "list", "download", "access"})
# Exact tokens/compounds -- some source nouns are themselves multi-word
# (e.g. "PhoneNumber" tokenizes to ['phone','number']), so this set includes
# both the single-token and adjacent-2-token-joined forms actually seen in
# the vocabulary below. Matched against individual tokens and adjacent-pair
# joins ONLY (not the full concatenated name) -- an earlier version joined
# ALL tokens into one string and substring-matched against it, which caused
# a real false positive: "get_user_information" joins to
# "getuserinformation", which contains "userinfo" as an accidental
# cross-boundary substring even though "user"/"information" were never
# meant to match "userinfo". Bounding the join to adjacent-pairs-only
# eliminates that class of collision while still catching genuine two-word
# compounds like "phone"+"number" -> "phonenumber".
_SENSITIVE_NOUN_TOKENS: frozenset[str] = frozenset({
    "address", "addresses", "payment", "payments", "holding", "holdings",
    "genetic", "health", "password", "passwords", "accesshistory", "log",
    "logs", "location", "prescription", "prescriptions", "patientdetail",
    "patientdetails", "record", "records", "metadata", "searchhistory",
    "phonenumber", "linkedaccount", "userprofile", "userdetail", "userinfo",
    "friend", "friends", "reservation", "reservations", "shipment",
    "shipments", "orderhistory", "deepfake",
})
# Two-token compounds that form a sensitive noun only when ADJACENT, in this
# order (e.g. "phone","number" adjacent -> phone-number lookup; "phone" or
# "number" alone, or non-adjacent, do not count).
_SENSITIVE_NOUN_BIGRAMS: frozenset[tuple[str, str]] = frozenset({
    ("phone", "number"), ("access", "history"), ("search", "history"),
    ("linked", "account"), ("user", "profile"), ("user", "detail"),
    ("patient", "detail"), ("order", "history"),
})


def is_source_tool(tool: str) -> bool:
    if tool in SOURCE_TOOLS_EXACT:
        return True
    if SOURCE_TOOL_PATTERN.match(tool):
        return True
    tokens = _tokenize_tool_name(tool)
    has_verb = any(t in _SOURCE_VERB_TOKENS for t in tokens)
    if not has_verb:
        return False
    has_noun = any(t in _SENSITIVE_NOUN_TOKENS for t in tokens)
    if not has_noun:
        has_noun = any(
            (tokens[i], tokens[i + 1]) in _SENSITIVE_NOUN_BIGRAMS
            for i in range(len(tokens) - 1)
        )
    return has_noun


# ──────────────────────────────────────────────────────────────────────────────
# DESTINATION tools — external communication, confirmed against the
# installed agentdojo package (default_suites/v1/tools/*.py), not guessed.
# ──────────────────────────────────────────────────────────────────────────────

# tool name -> arg key(s) holding the recipient/destination value(s)
DESTINATION_TOOLS: dict[str, tuple[str, ...]] = {
    "send_email":              ("recipients", "cc", "bcc"),
    "share_file":               ("email",),
    "send_direct_message":      ("recipient",),
    "send_channel_message":     ("channel",),
    "invite_user_to_slack":     ("user", "user_email"),
    "add_user_to_channel":      ("user", "channel"),
    "send_money":                ("recipient",),
    "schedule_transaction":      ("recipient",),
    # slack's real exfil-destination tool (found during provenance Gate 1/
    # Gate 2 build via slack::injection_task_4/5's ground truth -- posts
    # externally to `url`, same destination shape as send_email's
    # recipient). Added here specifically because it was missing entirely
    # (a real, pre-existing gap, not new scope) and both check_channel_taint
    # and check_provenance share this dict -- confirmed zero regression risk
    # against both the 22 real benign sessions and the 32 InjecAgent
    # ground-truth cases (neither uses post_webpage at all) before adding.
    "post_webpage":              ("url",),
    # InjecAgent corpus wire-format name for the same shape as send_email.
    "GmailSendEmail":            ("email", "to", "recipient", "recipients"),
    # NOTE: reserve_hotel was tried here during the GPT-4o real-trajectory
    # expansion (5/629 real attack cases use an attacker-substituted hotel
    # name, e.g. runs/gpt-4o-2024-05-13/travel/user_task_16/.../
    # injection_task_0.json) and reverted the same night. Adding it without
    # also extending _extract_candidate_values() (which only recognizes
    # email/IBAN/phone/URL shapes) makes EVERY reserve_hotel call --
    # including ones where the user explicitly named the hotel themselves,
    # e.g. "my friend recommended 'Le Marais Boutique'" -- classify as
    # NOVEL and false-positive ESCALATE, since a proper-noun business name
    # never matches any of those four regexes. Robustly recognizing
    # proper-noun-shaped destination values from free text (without
    # over-matching ordinary words elsewhere) is a genuinely harder
    # problem than the existing four shapes and needs its own
    # census/regression pass, not a same-night follow-on. Documented as a
    # known, narrow gap (5/629 real cases) rather than shipped half-fixed.
}


def is_destination_tool(tool: str) -> bool:
    return tool in DESTINATION_TOOLS


def _destination_values(call: ParsedCall) -> list[str]:
    keys = DESTINATION_TOOLS.get(call.tool, ())
    out: list[str] = []
    for k in keys:
        if k in call.args:
            out.extend(_flatten_arg_values({k: call.args[k]}))
    return out


def _general_destination_values(call: ParsedCall) -> list[str]:
    """Behavior-general fallback for tools NOT in DESTINATION_TOOLS.

    Found via a Phase 2 census (overnight session): _destination_values()
    above is tool-name AND argument-key-name keyed -- it only looks at
    DESTINATION_TOOLS[call.tool]'s specific named keys. A tool that isn't
    in that dict is entirely invisible to CHANNEL, however consequential
    its arguments are. Confirmed non-hypothetical: `send_transaction`
    (banking's alternate transfer-tool name, real in
    real_benign_trajectories.json's injection_task_2 fixture) has a real
    `recipient` argument but was never added to DESTINATION_TOOLS.

    Scans EVERY argument value on the call (not just named-key values,
    via the same _flatten_arg_values() VAULT/EXECUTOR already use) for a
    destination-SHAPED value (email/IBAN/phone/URL, the same regex set
    _extract_candidate_values() already applies to tool_output/
    user_instruction) -- so a genuinely novel tool with a real destination
    argument is still caught, without needing its name pre-listed.

    Deliberately NOT used for tools already in DESTINATION_TOOLS -- see
    check_provenance()'s call site. This keeps every already-tested
    destination tool's exact behavior byte-identical (zero regression
    risk on the locked 5/22, 5/5 numbers); only tools with NO listed
    entry get this net. Conservative bias, same discipline as
    struct_parse.py: a missed novel-tool destination falls through to
    ALLOW (no verdict), not a false ESCALATE -- the existing named-key
    path is unaffected and remains the precise, primary mechanism.

    BUG FOUND AND FIXED during this session's own live regression: the
    original version joined ALL arg values into one string
    (" ".join(...)) before scanning -- this let _PHONE_RE (an 8+-digit
    sequence with optional dashes/spaces) match ACROSS argument
    boundaries that were never adjacent in any real single value, e.g.
    update_scheduled_transaction's {"id": 6, "date": "2022-03-01",
    "amount": 75.0} joined into "6 2022-03-01 75", which _PHONE_RE
    matched as a fabricated 'phone number' spanning three unrelated
    fields -- a real false positive on a real benign fixture (found via
    the live 22-benign-session regression, not a synthetic edge case).
    Fixed by scanning each argument value independently, never joined,
    so a pattern can only match within a single real value.

    SECOND bug found in the same regression pass: even scanned in
    isolation, a bare ISO-date string ("2022-03-01") still matches
    _PHONE_RE (an 8+-digit sequence tolerant of dashes/spaces, by
    design loose enough to catch "+1 555-123-4567"-shaped numbers) --
    a real, pre-existing ambiguity in that regex, just never exercised
    before because a lone date string was never scanned as a standalone
    candidate value until this fallback existed. Not fixing _PHONE_RE
    itself (shared with tool_output/user_instruction scanning elsewhere,
    already tested, out of scope to touch tonight) -- instead excluding
    ISO-8601-date-shaped strings specifically from THIS fallback's
    output, since a date is never a legitimate destination value and
    dates are exactly the kind of coincidentally-digit-heavy field a
    novel tool's args are likely to carry (id/date/amount, as seen
    here)."""
    out: set[str] = set()
    for v in _flatten_arg_values(call.args):
        for cand in _extract_candidate_values(v):
            if _ISO_DATE_RE.fullmatch(cand):
                continue
            out.add(cand)
    return list(out)


# ──────────────────────────────────────────────────────────────────────────────
# Allow-list — deliberately empty by default (see module docstring). A real
# deployment must seed this with the session's own verified user identity
# (email/Slack handle) from a source Kavach does not currently capture.
#
# WORKSPACE FIX (self-send exemption, added after the empty allow-list's
# false-positive gap was demonstrated concretely -- 3/3 constructed "send
# sensitive data to self" cases false-positived): AgentDojo's workspace
# suite genuinely exposes a real, populated, per-task identity field for
# EMAIL destinations specifically -- Inbox.account_email (confirmed
# directly against the installed agentdojo package: populated with a real
# default like "emma.johnson@bluesparrowtech.com", structurally distinct
# from the recipients send_email() is called with). Kavach did not
# previously capture or pass this through anywhere; it now can, via an
# optional `account_email` on the /hook/parliament request's existing
# `context` dict (server.py Step 3a4).
#
# Scope, explicitly: this exemption applies ONLY to EMAIL-shaped
# destination tools (send_email, share_file, and GmailSendEmail -- the
# InjecAgent corpus's wire-format name for the same shape), because
# account_email is specifically an EMAIL identity and AgentDojo's own
# environment model only associates it with the Inbox/Calendar objects.
# It does NOT apply to Slack tools (send_direct_message,
# send_channel_message, invite_user_to_slack, add_user_to_channel) or
# banking tools (send_money, schedule_transaction) -- confirmed directly
# against the installed agentdojo package that NEITHER suite exposes any
# analogous verified-identity field (Slack's environment model has no
# "which user am I" marker at all; banking's BankAccount.iban is not
# semantically distinguished from a recipient IBAN). This remains a
# permanent limitation for those two suites, unchanged by this fix -- no
# identity source was invented for them.
# ──────────────────────────────────────────────────────────────────────────────

DESTINATION_ALLOWLIST: frozenset[str] = frozenset()

_EMAIL_DESTINATION_TOOLS: frozenset[str] = frozenset({"send_email", "share_file", "GmailSendEmail"})


def _destination_allowed(tool: str, values: list[str], account_email: str | None) -> bool:
    if not values:
        return False
    if account_email and tool in _EMAIL_DESTINATION_TOOLS:
        if all(v == account_email or v in DESTINATION_ALLOWLIST for v in values):
            return True
    return all(v in DESTINATION_ALLOWLIST for v in values)


# ──────────────────────────────────────────────────────────────────────────────
# Per-session taint state — mirrors _state["history"]/_state["intents"]'s
# session_id-keyed pattern in server.py. Kept separate from trajectory.py's
# ActionRecord (see module docstring for why).
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SessionTaint:
    tainted: bool = False
    source_tool: str | None = None
    source_matched_id: str | None = None


def new_taint_state() -> SessionTaint:
    """Factory for a fresh per-session taint state (use via defaultdict)."""
    return SessionTaint()


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def check_channel_taint(
    text: str,
    state: SessionTaint,
    account_email: str | None = None,
) -> MinisterScan | None:
    """Score ONE call against the session's taint state, mutating `state` in
    place (source calls set taint; the caller owns state's lifetime, keyed
    per session_id exactly like trajectory.py's history deque).

    account_email: the session's own verified email identity, if known
    (e.g. AgentDojo workspace suite's Inbox.account_email, passed through
    server.py's request context). None by default -- callers that don't
    have this (or Slack/banking sessions, which have no such field at all)
    simply get the original empty-allow-list behavior unchanged.

    Returns a MinisterScan on a destination-tool BLOCK; None otherwise
    (source-tool calls taint the state but do not themselves return a
    verdict -- the read call is not the malicious action, the send is)."""
    call = parse_call(text)
    if call is None:
        return None

    if is_source_tool(call.tool):
        if not state.tainted:
            state.tainted = True
            state.source_tool = call.tool
            state.source_matched_id = f"CHANNEL-TAINT-SOURCE:{call.tool}"
        return None

    if is_destination_tool(call.tool):
        values = _destination_values(call)
        if state.tainted and not _destination_allowed(call.tool, values, account_email):
            return MinisterScan(
                minister="CHANNEL",
                verdict="BLOCK",
                confidence=1.0,
                matched_id="CHANNEL-TAINT:read-then-send",
                matched_text=(
                    f"session tainted by prior read of {state.source_tool!r} "
                    f"({state.source_matched_id}); untrusted destination call "
                    f"to {call.tool!r} with recipient(s) {values!r}"
                ),
                matched_level="deterministic",
                source="MITRE ATT&CK T1041",  # Exfiltration Over C2 Channel
                retrieval_mode="deterministic",
            )
        return None

    # Behavior-general fallback: `call.tool` is not in the named
    # DESTINATION_TOOLS dict, so the named-key path above is structurally
    # blind to it regardless of how consequential its arguments are (the
    # exact generalization gap the audit in Appendix A documents). Reuse
    # _general_destination_values() -- already built, and already hardened
    # against two real false-positive bugs (see its docstring) -- to check
    # for a destination-SHAPED value (email/IBAN/phone/URL) on ANY tool.
    # This is deliberately conservative and narrower than the named path:
    # it only fires on a shape match, so a proper-noun destination (e.g.
    # a hotel name) is NOT caught here either -- that remains the
    # documented reserve_hotel gap, unchanged by this fallback.
    general_values = _general_destination_values(call)
    if general_values and state.tainted and not _destination_allowed(call.tool, general_values, account_email):
        return MinisterScan(
            minister="CHANNEL",
            verdict="BLOCK",
            confidence=1.0,
            matched_id="CHANNEL-TAINT-GENERAL:read-then-send",
            matched_text=(
                f"session tainted by prior read of {state.source_tool!r} "
                f"({state.source_matched_id}); untrusted destination-shaped "
                f"value on novel tool {call.tool!r}: {general_values!r}"
            ),
            matched_level="deterministic",
            source="MITRE ATT&CK T1041",  # Exfiltration Over C2 Channel
            retrieval_mode="deterministic",
        )

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Argument provenance (CHANNEL Stage 2b) — WHERE did this destination value
# come from, as a fact, not an authorization decision.
# ──────────────────────────────────────────────────────────────────────────────
#
# Built after a Gate 1 discriminability census against real AgentDojo
# ground-truth data (5/5 structurally-applicable multi-step attack cases
# were genuinely OUTPUT_DERIVED) and a benign census against the 22 real
# banking sessions (parliament/benign_test_set/real_benign_trajectories.json)
# that found 2/22 real false-positive risk cases: "pay the bill using the
# IBAN stated in the bill file you just read" -- a legitimate
# read-then-send flow whose destination is genuinely OUTPUT_DERIVED. That
# finding is why this mechanism NEVER hard-BLOCKs on its own (see
# check_provenance()'s verdict logic below) -- naive
# OUTPUT_DERIVED-blocks-everything provenance would immediately regress
# CHANNEL's own FPR discipline on banking. Resolving that case correctly
# (distinguishing "the user asked me to pay using whatever the invoice
# says" from "an attacker's injected instruction told me to send here")
# needs NAVIGATOR's authorized-flow work (see navigator-rearch branch) --
# provenance here only ever reports the fact of where a value came from.
#
# SCOPE (locked decisions, not to be revisited without a fresh discussion):
#   A. Matching is BROAD and ATTRIBUTED. A destination value is checked
#      against every tool output seen so far in the session -- not just
#      ground_truth()-listed "source" tools -- and the record always
#      names WHICH tool the value first appeared in. E.g. a destination
#      URL that first appears in a get_webpage() result attributes to
#      get_webpage, even though get_webpage is not itself a CHANNEL
#      SOURCE_TOOLS entry -- provenance and taint are independent
#      mechanisms answering different questions (see composition rule
#      below), so provenance's "have I seen this value before, and
#      where" does not require the tool to also be a taint SOURCE.
#   B. Verdict logic is intentionally asymmetric with taint: a
#      consequential-call destination classified OUTPUT_DERIVED or NOVEL
#      returns ESCALATE, never BLOCK. USER_SUPPLIED or SELF (matches the
#      session's own verified identity) returns None (pass, no verdict --
#      same "no news is no news" convention check_channel_taint() uses).
#      check_channel_taint()'s own BLOCK authority is completely
#      untouched by this addition.
#   C. Composition: taint answers "is sensitive data leaving the
#      session" (can BLOCK); provenance answers "where did this
#      destination value actually come from" (can ESCALATE). They are
#      independent verdicts scored from independent per-session state --
#      check_provenance() never reads SessionTaint, check_channel_taint()
#      never reads SessionProvenance -- and the Speaker's existing
#      most-restrictive-wins logic (BLOCK > ESCALATE > ALLOW, see
#      speaker.py's combine_verdicts()) resolves the two without any new
#      wiring: this required no changes to speaker.py or server.py's
#      dispatch order, only a new deterministic-minister call sitting
#      alongside the existing three.
#
# DATA-AVAILABILITY GAP (found during Gate 1, still true here): Kavach's
# wire format ("tool:X args:Y", see prefilters.parse_call()) carries only
# the CALL, never the tool's OUTPUT/result -- /hook/parliament has never
# had a capture point for tool outputs anywhere in the pipeline. Rather
# than invent a new endpoint, this reuses ParliamentRequest's existing
# open-ended `context` dict (the same extension point account_email
# already uses): a caller MAY pass `context["tool_output"]` -- the
# result of the CURRENT call, if this call is itself a read whose result
# should be recorded for later destination-value checks. This is
# genuinely optional and additive: a caller that never sets it (e.g.
# InjecAgent's live runner, which doesn't have per-call output plumbing
# today) gets identical behavior to before this feature existed --
# check_provenance() only ever ESCALATEs when it actually has evidence a
# destination value came from prior output; no evidence never means
# "assume attacker," it means "no verdict," exactly like taint's
# fail-open discipline on unrecognized tools.

# Candidate destination-value shapes -- email/IBAN/phone are the SAME
# regex set as benchmarks/_provenance_census.py's Gate 1 census,
# unchanged. _URL_RE is a REAL ADDITION found during Gate 2's own
# testing, not part of the original census: the census's Gate 1 report
# claimed slack::injection_task_4 was OUTPUT_DERIVED based on a manual
# `'my-website-234' in str(page)` substring check done by hand while
# writing that report -- NOT via the census's own _extract_candidates()
# regex mechanism, which never had a URL pattern at all. This was only
# discovered here, building the live check_provenance() test for exactly
# that case: the destination (a bare URL, not an email/IBAN/phone) was
# silently un-extractable, so slack::4's own required test case would
# have wrongly reported NOVEL instead of OUTPUT_DERIVED with correct
# source_tool attribution -- a real gap between what Gate 1 reported and
# what its own frozen regex set actually covered. Adding _URL_RE closes
# that specific gap; it does not touch email/IBAN/phone matching at all.
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b")
_PHONE_RE = re.compile(r"\b(\+?\d[\d\-\s]{7,14}\d)\b")
_URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
# ISO-8601 date shape (YYYY-MM-DD) -- used only by _general_destination_values()
# to exclude a real false-positive class found during this session's own live
# regression: a bare date string spuriously matches _PHONE_RE's loose
# 8+-digit-with-dashes shape. See that function's docstring for the full
# finding. Scoped narrowly (this regex, this one caller) rather than tightening
# _PHONE_RE itself, which is shared with already-tested tool_output/
# user_instruction scanning elsewhere.
_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _extract_candidate_values(text: str) -> set[str]:
    """Every candidate destination-value-shaped string in free text:
    emails, IBAN-shaped tokens, phone-shaped digit runs (>=8 digits, to
    avoid matching ordinary short numbers). Same three patterns as the
    Gate 1 census -- see module-level docstring above for why this
    doesn't also try to regex-extract bare Slack usernames/channels (too
    ambiguous from free text; those are read directly from known
    destination-tool arg keys via _destination_values() instead, same as
    check_channel_taint()).

    All returned values are lowercased+stripped (via _normalize_value()),
    matching exactly how _classify_destination_value() normalizes a
    destination value before comparing against this set -- storing and
    looking up under two different normalization rules was a real bug
    found during testing (an IBAN stored here in its original uppercase
    form, e.g. "UK12...", failed to match its own lowercased self at
    lookup time, silently misclassifying a confirmed OUTPUT_DERIVED value
    as NOVEL -- same ESCALATE verdict today since both classifications
    trigger it, but wrong source_tool attribution, which breaks the
    frozen CHANNEL/NAVIGATOR interface contract's promise)."""
    if not isinstance(text, str) or not text:
        return set()
    out: set[str] = set()
    out.update(_normalize_value(m) for m in _EMAIL_RE.findall(text))
    out.update(_normalize_value(m) for m in _IBAN_RE.findall(text))
    out.update(_normalize_value(m) for m in _PHONE_RE.findall(text) if len(re.sub(r"\D", "", m)) >= 8)
    out.update(_normalize_value(m.rstrip(".,;:)")) for m in _URL_RE.findall(text))
    return out


def _normalize_value(value: str) -> str:
    """Single normalization rule used consistently for BOTH storage
    (output_candidates, user_candidates) and lookup (the value being
    classified) -- see _extract_candidate_values()'s docstring for the
    bug this fixes."""
    return value.strip().lower() if isinstance(value, str) else str(value)


def _classify_value_type(value: str) -> str:
    """email / iban / phone / url / other -- coarse type tag for
    ProvenanceRecord, NOT used for classification logic itself (that's
    purely presence-based, see _classify_destination_value()). Purely
    descriptive, for NAVIGATOR's consumption per the CHANNEL/NAVIGATOR
    interface contract."""
    if _EMAIL_RE.fullmatch(value) or "@" in value:
        return "email"
    if _IBAN_RE.fullmatch(value):
        return "iban"
    if _PHONE_RE.fullmatch(value):
        return "phone"
    if value.lower().startswith(("http://", "https://", "www.")) or _URL_RE.match(value):
        return "url"
    return "other"


@dataclass
class ProvenanceRecord:
    """CHANNEL/NAVIGATOR interface contract (frozen schema -- see
    test_channel_taint.py's test_provenance_record_schema_frozen() for the
    permanent regression test). One record per flagged destination value
    on a consequential call. Exposed via check_provenance()'s
    `records` return value; NAVIGATOR consumes this READ-ONLY to make
    authorization decisions -- CHANNEL never reads NAVIGATOR state,
    NAVIGATOR never mutates CHANNEL state (see composition rule in the
    module docstring above). Do not change field names/types without
    coordinating across both branches; this is a two-person API."""
    value: str
    value_type: str            # "email" | "iban" | "phone" | "other"
    classification: str        # "USER_SUPPLIED" | "SELF" | "OUTPUT_DERIVED" | "NOVEL"
    source_tool: str | None    # tool name a OUTPUT_DERIVED value was first seen in, else None
    first_seen_turn: int | None  # turn index the value was first recorded at, else None (USER_SUPPLIED/SELF/NOVEL)


@dataclass
class SessionProvenance:
    """Per-session provenance state -- independent of SessionTaint (see
    composition rule in the module docstring above). user_candidates is
    populated once, on the FIRST call seen in a session (the caller's own
    original instruction, if supplied); output_candidates accumulates
    across the whole session, each value mapped to (attributed tool name,
    turn index it was first seen at) -- first-seen wins, matching taint's
    "only the first source tool sets state" convention. turn starts at 0
    and increments once per check_provenance() call (i.e. once per real
    tool call scored in this session), independent of check_channel_taint()'s
    own call count."""
    user_candidates: set[str] = field(default_factory=set)
    user_instruction_seen: bool = False
    output_candidates: dict[str, tuple[str, int]] = field(default_factory=dict)  # value -> (tool, turn)
    turn: int = -1  # incremented to 0 on the first real call


def new_provenance_state() -> SessionProvenance:
    """Factory for a fresh per-session provenance state (use via defaultdict,
    same pattern as new_taint_state())."""
    return SessionProvenance()


def _classify_destination_value(
    value: str,
    state: SessionProvenance,
    account_email: str | None,
) -> tuple[str, str | None, int | None]:
    """Returns (classification, attributed_tool, first_seen_turn).
    classification is one of USER_SUPPLIED / SELF / OUTPUT_DERIVED / NOVEL.
    attributed_tool and first_seen_turn are populated only for
    OUTPUT_DERIVED (None otherwise)."""
    norm = _normalize_value(value)
    if account_email and norm == _normalize_value(account_email):
        return "SELF", None, None
    if norm in state.user_candidates or any(norm in c for c in state.user_candidates):
        return "USER_SUPPLIED", None, None
    if norm in state.output_candidates:
        tool, turn = state.output_candidates[norm]
        return "OUTPUT_DERIVED", tool, turn
    for cand, (tool, turn) in state.output_candidates.items():
        if norm in cand:
            return "OUTPUT_DERIVED", tool, turn
    return "NOVEL", None, None


def check_provenance(
    text: str,
    state: SessionProvenance,
    account_email: str | None = None,
    user_instruction: str | None = None,
    tool_output: str | None = None,
) -> tuple[MinisterScan | None, list[ProvenanceRecord]]:
    """Score ONE call against the session's provenance state, mutating
    `state` in place (records this call's own output, if supplied, for
    future calls to check against; classifies THIS call's destination
    values if it's a destination-tool call). Independent of
    check_channel_taint() and SessionTaint -- see composition rule in the
    module docstring above.

    text: the "tool:X args:Y" call being scored, same wire format as
        check_channel_taint().
    state: this session's SessionProvenance (caller owns its lifetime,
        same convention as SessionTaint).
    account_email: the session's own verified identity, if known -- same
        parameter, same source as check_channel_taint() already uses.
    user_instruction: the session's original instruction text, needed
        ONCE (first call only; ignored on subsequent calls -- see
        SessionProvenance.user_instruction_seen). A caller that never
        supplies this simply never gets USER_SUPPLIED classifications
        (destination values fall through to NOVEL instead) -- documented
        limitation, not a silent failure.
    tool_output: the result of THIS call, if this call is itself a read
        whose output should be recorded for later destination-value
        checks. See the DATA-AVAILABILITY GAP note in the module
        docstring above for why this is an optional context field, not
        a guaranteed capture.

    Returns (scan, records):
      scan: a MinisterScan with verdict=ESCALATE if a destination-tool
        call's value is OUTPUT_DERIVED or NOVEL; None otherwise (matches
        check_channel_taint()'s "no verdict" convention for ALLOW-shaped
        outcomes).
      records: a ProvenanceRecord for EVERY destination value checked on
        this call (not just flagged ones) -- the CHANNEL/NAVIGATOR
        interface contract. Empty list when this call isn't a
        destination-tool call at all."""
    if not state.user_instruction_seen:
        state.user_candidates = _extract_candidate_values(user_instruction or "")
        state.user_instruction_seen = True

    call = parse_call(text)
    if call is None:
        return None, []

    state.turn += 1

    # Classify THIS call's own destination values BEFORE recording this
    # call's own tool_output. Bug found and fixed during the benign
    # re-census with real environment-dispatched outputs: a destination
    # tool's own confirmation output (e.g. send_money returning
    # "Transaction to <IBAN> sent.") echoes back its own recipient
    # argument -- storing that into output_candidates BEFORE classifying
    # this same call created a circular, meaningless self-attribution
    # (a destination value "first seen in the output of the very call
    # that used it as an argument"). Real destination-tool calls in
    # AgentDojo's environment consistently echo their own args back in
    # their confirmation message, so this wasn't a synthetic edge case --
    # it fired on a real fixture (benign\local\banking\user_task_2,
    # send_money's own IBAN misattributed to itself instead of correctly
    # falling through to NOVEL, since the real source -- read_file's
    # landlord-notice content -- never actually contained the IBAN at all).
    if is_destination_tool(call.tool):
        values = _destination_values(call)
    else:
        # Behavior-general fallback (Phase 2 census finding) -- a tool NOT
        # in DESTINATION_TOOLS still gets checked for destination-shaped
        # argument values, so a genuinely novel tool (e.g. send_transaction)
        # isn't silently invisible to provenance. See
        # _general_destination_values()'s docstring for the full finding.
        values = _general_destination_values(call)

    if not values:
        if tool_output:
            for cand in _extract_candidate_values(tool_output):
                if cand not in state.output_candidates:
                    state.output_candidates[cand] = (call.tool, state.turn)
        return None, []

    records: list[ProvenanceRecord] = []
    flagged: list[ProvenanceRecord] = []
    for v in values:
        classification, tool, turn = _classify_destination_value(v, state, account_email)
        rec = ProvenanceRecord(
            value=v,
            value_type=_classify_value_type(v),
            classification=classification,
            source_tool=tool,
            first_seen_turn=turn,
        )
        records.append(rec)
        if classification in ("OUTPUT_DERIVED", "NOVEL"):
            flagged.append(rec)

    # Record THIS call's own output for FUTURE calls to reference, now
    # that this call's OWN destination values have already been
    # classified against only prior state (see the ordering fix above).
    if tool_output:
        for cand in _extract_candidate_values(tool_output):
            if cand not in state.output_candidates:
                state.output_candidates[cand] = (call.tool, state.turn)

    if not flagged:
        return None, records

    winner = flagged[0]
    if winner.classification == "OUTPUT_DERIVED":
        detail = f"destination {winner.value!r} first seen in output of {winner.source_tool!r}, not in the user's original instruction"
    else:
        detail = f"destination {winner.value!r} not found in the user's original instruction or any prior tool output this session"

    scan = MinisterScan(
        minister="CHANNEL",
        verdict="ESCALATE",
        confidence=1.0,
        matched_id=f"CHANNEL-PROVENANCE:{winner.classification.lower()}",
        matched_text=(
            f"consequential call to {call.tool!r} — {detail}"
        ),
        matched_level="deterministic",
        # Exfiltration Over Web Service -- same shape as check_channel_taint's
        # T1041 (unverified destination receiving session data), but T1567
        # specifically since provenance's finding is about the DESTINATION's
        # legitimacy rather than the read-then-send session pattern taint
        # detects. Confirmed registered in provenance.py's _TECH table (an
        # earlier T1204 "User Execution" guess was NOT registered there and
        # would have silently resolved to "(unmapped technique)" in the
        # ledger/response -- found and fixed during this build's own testing).
        source="MITRE ATT&CK T1567",
        retrieval_mode="deterministic",
    )
    return scan, records

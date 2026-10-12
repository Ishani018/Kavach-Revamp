# NAVIGATOR 2.0 architecture

**Status: implemented, shadow-mode only, not wired into the production verdict path.** This document describes
`kavach/ministers/navigator2/`, a parallel package that never touches `kavach/coordinator.py`,
`kavach/speaker.py`, `kavach/schemas.py`, or the legacy `kavach/ministers/navigator.py`. All seven components the
task brief asked for are implemented; see the file map in §10.

## 0. No-LLM, deterministic-first architecture

**There has never been a real LLM/paid-API call anywhere in this package, and a follow-up pass made that
property structural rather than incidental.** Reassessed and hardened:

- `Navigator2`'s default `reasoner_provider` is `reasoner.py::DeterministicMockProvider` — a small, documented,
  rule-based function, not a model. No file in this package imports `anthropic`, `openai`, or any HTTP client; no
  network socket is opened anywhere in `kavach/ministers/navigator2/`.
- The reasoner is **optional and advisory everywhere**: `core.py::_needs_reasoner()` skips it entirely whenever a
  deterministic policy decision is already decisive (see `test_pol008_blocks_deterministically_without_invoking_reasoner`),
  and `verdict.py::compose()` structurally caps a reasoner `"block"` recommendation to `escalate` unless a
  `PolicyDecision` backs it — a model's opinion, real or mocked, can never *by itself* produce a BLOCK.
  Every security-relevant demonstration in this package's test suite reaches its decision from policies and
  evidence alone; the reasoner path is exercised separately, specifically to prove it is *safe to have* even
  though it adds no required authority of its own.
- The reasoner call is now wall-clock-bounded (`core.py::_call_reasoner`, default 2s, configurable) via a
  daemon-style thread pool that is abandoned (not waited on) past the timeout, so a hung provider cannot block
  the pipeline. A timeout is treated exactly like a missing reasoner (an indeterminate evidence finding, feeding
  the same escalate-on-coverage-gap rule) — never like a safe default.
- Every reasoner failure mode is now handled explicitly and distinctly, each recorded on the final
  `Navigator2Verdict` (`reasoner_timed_out`, `reasoner_rejected`, `reasoner_capped`): a provider that raises, a
  provider that returns the wrong type entirely (not just a malformed `ReasonerResponse` — a plain dict, a
  string, `None`), and a provider that returns a syntactically valid but fabricated response (referencing event
  or policy IDs it was never given) are all rejected and treated identically to "no reasoner available." See
  `tests/test_navigator2_unit.py::TestNavigator2Core` (`test_hostile_reasoner_returning_wrong_type_is_rejected_not_trusted`,
  `test_hostile_reasoner_raising_is_handled_not_crashed`, `test_reasoner_timeout_is_handled_not_blocking_forever`,
  `test_reasoner_cannot_expand_the_task_contract`).
- The reasoner is **never** the thing that writes to the task contract: `contract.py::TaskContractStore.revise()`
  is only ever called from `core.py`'s own untrusted-content detector, never from anything reasoner-shaped. A
  reasoner that lies about new permissions in its free-text `explanation`/`observed_facts` has no code path to
  make that lie real (`test_reasoner_cannot_expand_the_task_contract`).
- Two new policies (POL-008, POL-009 — §6) and real cross-call confidentiality propagation (§5) were added in
  this pass specifically so that MORE of NAVIGATOR 2.0's decisions are reachable without ever invoking the
  reasoner at all, not merely tolerant of it being absent.

**What this does NOT claim:** the deterministic core is still only as good as the policies and evidence modules
written so far (7 of a plausible much larger set — see `docs/navigator2-migration-matrix.md`), and the optional
reasoner, when it *is* consulted (ambiguous/escalated/indeterminate cases only), is still a small rule-based mock,
not real judgment — its presence in the test suite demonstrates the *safety contract* around an eventual real
reasoner, not that reasoning itself has been achieved.

## 1. Why a new package instead of editing NAVIGATOR

The legacy `NavigatorMinister.check()` (`kavach/ministers/navigator.py`) receives one `ToolCall`, embeds
`call.to_wire_text()`, and returns the nearest semantic match across 100 patterns × 3 levels. The pattern
disposition review (`docs/navigator-pattern-disposition-review.md`) measured that **47 of the 100 patterns
(14 CROSS-CALL + 8 REPLY-TEXT + 4 CONTEXT-DEPENDENT + 10 DEFER, less overlap) cannot be judged from one call's
text, however it is reworded** — they need a call sequence, the agent's own reply text, a user-stated scope, or a
removed COMPASS subsystem. No amount of pattern rewriting (the NAV-093/NAV-073 experiment) or evidence-gating
(the decode-execution prototype) fixes an architectural mismatch between "one call's text" and "a property of a
session." NAVIGATOR 2.0 exists to hold the state (contract + history + provenance) that makes those 47 patterns'
underlying risks judgeable at all, while leaving the other 53 to the legacy NAVIGATOR, EXECUTOR, VAULT, or
CHANNEL as appropriate (see `docs/navigator2-migration-matrix.md`).

## 2. Data flow (shadow mode)

```
ToolCall ──────────────────────────────────────────────────────────────────┐
  │                                                                        │
  ▼ (unchanged, existing path)                                            │
Coordinator.evaluate() ─► VAULT/EXECUTOR/CHANNEL/NAVIGATOR ─► Speaker ─► Decision
  │                                                                        │
  │  (shadow.py wraps the SAME ToolCall + the SAME four MinisterResults    │
  │   the Coordinator just computed; no second NAVIGATOR embed, no retry) │
  ▼                                                                        │
Navigator2.check(call, legacy_results, contract, ledger) ──────────────────┘
  │
  ├─► provenance.compute_label()       (Component 3 — integrity/confidentiality)
  ├─► evidence.run_all()               (Component 6 — shell/decode/minister-adapter findings)
  ├─► policy.PolicyEngine.evaluate_all() (Component 4 — deterministic, no LLM)
  ├─► reasoner.assess()  [only if ambiguous/escalated/indeterminate; Component 5]
  └─► verdict.compose()                (Component 7 — final Navigator2Verdict)

Navigator2Verdict is logged/returned for comparison. It is NEVER passed back into Speaker/Coordinator/Decision.
```

`ShadowRunner.evaluate_shadow(call)` (in `shadow.py`) is the only integration point, and it is additive: it calls
`Coordinator.evaluate(call)` exactly as `kavach/api.py` already does, unmodified, and *separately* builds a
`Navigator2` assessment from the same call and the `Decision.ministers` it got back. If `Navigator2.check()`
raises, `ShadowRunner` catches it, records the exception, and still returns the production `Decision` unchanged —
a NAVIGATOR 2.0 failure can never affect production. **No existing file is imported for modification, only for
reading (`kavach.schemas.ToolCall`/`MinisterResult`, `kavach.coordinator.Coordinator`).**

## 3. Component 1 — Trusted Task Contract (`contract.py`)

```python
class TaskContract(BaseModel):
    session_id: str
    version: int                                  # starts at 0 (auto-created, unscoped) or 1 (explicit)
    goal: str
    workspace_scope: list[str]                     # path/URL prefixes the task is said to operate within
    permitted_categories: list[str]
    denied_categories: list[str]
    approved_destinations: list[str]                # recipient emails/hosts/identifiers the user actually named
    high_impact_categories_requiring_approval: list[str]
    unresolved_ambiguities: list[str]
    created_from_event_id: str | None
    history: list[ContractRevision]                 # append-only, every version kept
```

`TaskContractStore.get_or_create(session_id, ...)` auto-creates a **version 0** contract with everything empty
and `unresolved_ambiguities=["no explicit task contract provided"]` if nobody called `start_session()` first —
this is deliberately *not* permissive: an empty `approved_destinations`/`permitted_categories` means policies that
need positive authorization (POL-001, POL-002, POL-006) cannot find it and lean toward `escalate`, not `allow`.
It is also not maximally restrictive: EXECUTOR/VAULT/CHANNEL/legacy-NAVIGATOR still run as normal, and routine
low-impact calls are not blocked just because no contract was declared (see `verdict.py`'s coverage rule).

`TaskContractStore.revise(session_id, event)` is the CaMeL-derived trust boundary (see `docs/navigator2-research.md`
§B): it raises `UntrustedRevisionAttempt` and refuses to change the contract unless
`event.integrity == IntegrityLabel.TRUSTED_INSTRUCTION`. A `tool_output`-sourced event (an email, a README, a
webpage) is always `UNTRUSTED_EXTERNAL` (see §5) and can never reach this path successfully — it can only ever be
evidence fed to the reasoner, never a contract edit. Every accepted revision is versioned and the old version
kept in `history`; nothing is overwritten in place.

## 4. Component 2 — Session Event Ledger (`ledger.py`)

```python
class SessionEvent(BaseModel):
    session_id: str
    event_id: str                                   # f"{session_id}:{seq:06d}"
    seq: int                                         # monotonic per session, used for ordering (not wall clock)
    timestamp: float
    parent_event_ids: list[str]
    tool_name: str
    arg_summary: dict[str, Any]                      # redacted: see _summarize_args, never raw secret values
    source_kind: str                                 # "user_instruction" | "tool_output" | "system" | "unknown"
    integrity: IntegrityLabel
    confidentiality: ConfidentialityLabel
    artifacts_read: list[str]
    artifacts_written: list[str]
    destinations: list[str]
    history_gap: bool                                # True if a parent_event_id was named but not found
    legacy_minister_results: dict[str, str]           # {"VAULT": "ALLOW", ...} — verdict strings only, no reason text
    disposition: str | None                           # filled in after Navigator2 decides
```

`SessionEventLedger` is a plain in-memory `dict[session_id, list[SessionEvent]]`, matching
`ChannelMinister`'s existing per-`session_id` state pattern (`kavach/ministers/channel.py`) rather than inventing
a new state-scoping convention. `append()` never raises; a lookup for an unknown `parent_event_id` sets
`history_gap=True` on the new event and records a note, it does not fail the call. `recent(session_id, n)`
returns the last *n* events for that session only — cross-session leakage is structurally impossible since the
ledger is keyed by `session_id` exactly like CHANNEL's `_taint`/`_provenance` dicts.

**Explicit behaviour for missing/truncated/unavailable history** (required by Part 2/Component 2): if the ledger
has zero prior events for a session (e.g. this is the shadow runner's first call, or the ledger was never
populated), `recent()` returns `[]` and every consumer (evidence modules, policy engine, reasoner) is written to
treat an empty history as **reduced evidence, not as "nothing suspicious happened"** — see `policy.py`'s
`POL-007` (insufficient-evidence-coverage), which specifically escalates when a CROSS-CALL-shaped risk category
is being evaluated but the relevant history is empty or gapped, rather than silently scoring it as safe.

## 5. Component 3 — Integrity/Confidentiality Provenance (`provenance.py`)

Two independent enums, never collapsed into one score (the FIDES lesson, `docs/navigator2-research.md` §A):

```python
class IntegrityLabel(str, Enum):
    TRUSTED_INSTRUCTION = "trusted_instruction"   # this session's own user_instruction context field
    TRUSTED_SYSTEM = "trusted_system"             # Kavach's own deterministic minister output, not model-generated
    UNTRUSTED_EXTERNAL = "untrusted_external"     # tool_output, or anything derived from it
    UNKNOWN = "unknown"                           # no context field told us the origin

class ConfidentialityLabel(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    SECRET = "secret"
    UNKNOWN = "unknown"
```

`compute_label(call, legacy_results)` is a **heuristic, call-scoped classifier, explicitly not byte-level taint
tracking** (the task brief's own warning: "do not pretend to have exact... taint tracking if the available tools
do not provide it"):
- Integrity: `UNTRUSTED_EXTERNAL` if `call.context` carries a non-empty `tool_output`; `TRUSTED_INSTRUCTION` if it
  carries `user_instruction` and no `tool_output`; `TRUSTED_SYSTEM` for Kavach-internal synthetic events (e.g.
  contract creation itself); else `UNKNOWN`. **When both are present, integrity is `UNTRUSTED_EXTERNAL`** — a
  call made in the context of *any* untrusted tool output in play is conservatively the more distrusted label,
  consistent with "unknown/mixed provenance must not silently become trusted."
- Confidentiality: `SECRET` if the real VAULT result (passed in, not recomputed) is not `ALLOW`; `PRIVATE` if
  CHANNEL's result is not `ALLOW` (CHANNEL already owns destination/PII-adjacent judgment, reused rather than
  reinvented); else `PUBLIC` only if at least one specialist minister result was observed and all were `ALLOW`;
  `UNKNOWN` if no legacy results were supplied at all (e.g. a unit test calling `Navigator2` standalone).
- `merge_integrity`/`merge_confidentiality` are the generic, symmetric merge utilities (schemas.py): integrity
  merges to the **least trusted** of two labels; confidentiality merges to the **most sensitive**. Documented
  coverage limit, stated directly in the module docstring: a merge only sees labels this prototype itself
  recorded in the ledger — it is not a general dynamic-taint engine and cannot track a value through an external
  system Kavach never observes.
- **`core.py::_propagate_confidentiality` now actually wires `merge_confidentiality` into the live pipeline**
  (added in this pass): every event's confidentiality is merged with its own direct parent's(s') confidentiality
  before being recorded, so a session that read something `SECRET` keeps that sensitivity on every subsequent
  event even if a *later* call's own arguments/legacy-minister results look completely clean. An unresolvable
  parent reference (missing, forged, or simply not yet appended) contributes nothing — neither trusting nor
  punishing a reference this component cannot verify.
- **Integrity is deliberately NOT propagated into the event's own primary field** by this same mechanism. The
  contract-revision trust gate (`contract.py`) must judge whether *this specific* event is a genuine,
  directly-supplied trusted instruction, on its own terms; propagating "least-trusted-wins" into that field would
  mean one early untrusted `tool_output` permanently strips the user's own ability to issue a fresh, genuinely
  trusted instruction for the rest of the session — exactly the over-blocking the task brief warns against. See
  `tests/test_navigator2_unit.py::test_confidentiality_propagates_from_parent_but_integrity_does_not` for the
  paired test proving both halves of this asymmetry.
- Because propagation is a *shortcut* keyed off the (possibly forged) `parent_event_ids` a caller supplies,
  POL-009 (§6) deliberately does **not** rely on it — it re-derives cross-call sensitivity directly from the
  ledger's own authoritative `recent_events` window, so a forged parent reference cannot hide a real prior
  sensitive read from policy enforcement even though it can defeat the propagation shortcut. See episode E15 and
  `test_pol009_catches_forged_parent_reference_that_pol001_and_propagation_miss`.

This is intentionally a different, narrower question than `channel_taint.py`'s existing read→send taint (which
answers "did THIS session read something sensitive before THIS send"). NAVIGATOR 2.0's provenance answers "is the
content behind THIS proposed action's instruction trustworthy enough to have come from the user," which is what
Component 1's trust-boundary check and Component 4's POL-003 need. CHANNEL's own taint/provenance verdict is
reused as-is (via `legacy_minister_results["CHANNEL"]`), not recomputed.

## 6. Component 4 — Deterministic Policy Engine (`policy.py`)

Each policy is a small class with a fixed `id`, `version`, human `title`, and an `evaluate(facts) -> PolicyDecision | None`
method that runs with **no LLM call** and is independently unit-testable. `PolicyEngine.evaluate_all(facts)` runs
every registered policy in a fixed order and collects every non-`None` decision — multiple policies can fire on
one event; nothing short-circuits except that a `block` decision later causes the reasoner to be skipped (§8).

| ID | Title | Fires on | Verdict | Evidence required (never fires without it) |
|---|---|---|---|---|
| POL-001 | proven-exfil-to-unauthorized-destination | A destination found in the call's own arguments is not in `contract.approved_destinations`, confidentiality is `PRIVATE`/`SECRET`, **and** integrity traces to a protected source | `block` | A concrete destination string extracted from this call (not merely "CHANNEL said BLOCK") plus a non-`PUBLIC` confidentiality label |
| POL-002 | contract-scope-violation | Event's `artifacts_written`/`artifacts_read` paths fall outside every `contract.workspace_scope` prefix **and** `contract.workspace_scope` is non-empty (i.e. a scope was actually declared) | `escalate` | At least one path token; never fires when scope is unknown, by design (an unscoped contract cannot prove a violation) |
| POL-003 | untrusted-content-privilege-induction | A `TRUSTED_INSTRUCTION`-only field (contract revision attempt) was sourced from an `UNTRUSTED_EXTERNAL` event | `block` | The actual rejected `UntrustedRevisionAttempt` raised by `contract.py` for this event |
| POL-004 | decode-execute-structural | `DecodeExecutionEvidenceModule` resolved a decode→execute data flow (incl. one-hop variable indirection) | `escalate` (→ `block` only if POL-001 *also* fires on the same event, i.e. the decoded content is proven to reach an unauthorized external destination) | An AST-confirmed (not regex) decode-to-sink path; a mere `base64` substring never satisfies this |
| POL-005 | specialist-hard-block-preserved | Any passed-in legacy `MinisterResult.verdict == "BLOCK"` | `block` | The legacy result itself — pass-through, not a new detection |
| POL-006 | high-impact-without-approval | Event's tool/category is in `contract.high_impact_categories_requiring_approval` and no prior ledger event for this session has `source_kind == "approval"` | `escalate`, `requires_approval=True` | The contract's own declared category list — never invents what counts as high-impact |
| POL-007 | insufficient-evidence-coverage | Any evidence finding has `coverage == "indeterminate"` on a security-relevant construct (parser failure, unsupported dialect, unresolved indirection) | `escalate` | The evidence module's own coverage flag — never silently treated as safe |
| POL-008 | explicit-task-restriction-violation | Event's `tool_name` is literally in `contract.denied_categories` | `block` | The contract's own explicit denial list — the most literal policy in the engine ("the trusted contract said no"); never guesses what should be denied |
| POL-009 | cross-call-sensitive-read-then-transmit | A destination in this call is not in `contract.approved_destinations`, **and** an earlier event in `facts.recent_events` (the ledger's own authoritative window, independent of this call's claimed `parent_event_ids`) has `confidentiality` in `{PRIVATE, SECRET}` and touched an artifact | `block` | A concrete destination on THIS call, plus a genuine, artifact-touching, sensitive EARLIER event found by scanning the ledger directly — deliberately does not trust the caller's own parent-chain claim (see §5's forged-reference note) |

No policy here is a broad keyword match; each requires a named, structured fact (a contract field, a ledger
lookup, an AST-confirmed evidence finding, or another minister's already-computed verdict), per the task brief's
explicit instruction against "broad, unqualified keyword rules." POL-001 and POL-009 look similar but answer
different questions: POL-001 asks "is THIS event's own confidentiality already sensitive," which a per-call
heuristic can miss when a later 'send' call's own arguments/legacy results look clean; POL-009 asks "did this
SESSION touch something sensitive earlier, regardless of what this call's parent claims," which is the
genuinely cross-call check. Both can fire on the same event; neither depends on the other.

## 7. Component 5 — Constrained Trajectory Reasoner (`reasoner.py`)

```python
class TrajectoryReasonerProvider(Protocol):
    def assess(self, request: ReasonerRequest) -> ReasonerResponse: ...
```

`ReasonerRequest` carries only: the current `TaskContract`, the proposed `SessionEvent`, up to the last *N*
`SessionEvent`s for the session (`relevant_events`), the `EvidenceFinding`s gathered for this event, the passed-in
legacy minister verdicts (strings, not full reasons — see redaction note below), and the IDs of the policy
clauses that were *applicable* (even if none fired). It never receives raw secret values, VAULT's redacted match
text, or full tool-output bodies — only `arg_summary` (already redacted at ledger-append time) and short
evidence claims.

`ReasonerResponse` is validated by `validate_response()` against the exact schema the task brief specifies
(`assessment`, `supporting_event_ids`, `observed_facts`, `applicable_policy_clauses`, `potential_impact`,
`recommended_disposition`, `uncertainty`, `explanation`) **and** against a fabrication check: every ID in
`supporting_event_ids` must be an ID that was actually present in `relevant_events` (plus the current event), and
every entry in `applicable_policy_clauses` must be a policy ID the engine actually has registered. A reference to
an event or policy the model was never shown raises `ReasonerFabricationError`, which `verdict.py` treats as
`insufficient_evidence` (fail toward escalate, never toward a model-invented allow).

Two providers ship in this prototype, **no network call in either, no API key needed for tests**:
- `NullReasonerProvider` — always returns `insufficient_evidence`/`escalate`, `uncertainty=1.0`. The safe default
  when nothing else is configured.
- `DeterministicMockProvider` — a small rule-based stand-in (explicitly documented as *not* an LLM) used by the
  test suite and by `episodes.py`'s evaluation runner so the whole pipeline is exercised end-to-end without a
  real model. It looks only at the same structured `ReasonerRequest` fields a real model would get (no special
  back-door access to ground truth) and applies simple, documented rules (e.g. "an `UNTRUSTED_EXTERNAL`-sourced
  event whose `observed_facts` include an approved-destination mismatch → `suspicious`/`block`"). Its ruleset is
  intentionally small and is itself unit-tested in `tests/test_navigator2_unit.py`.

**A real provider (Anthropic/OpenAI/etc.) is intentionally NOT plugged in, as a hard architectural decision, not
just an unfinished task.** A second model is itself attackable by the same untrusted content NAVIGATOR 2.0 exists
to defend against, and a mandatory paid API would add cost, latency, a network dependency, API-key management,
and a new attack surface to Kavach's security core — see `docs/navigator2-report.md`'s "No-LLM architecture"
section for the full reasoning and §0 above for what was added in this pass to make that boundary airtight
against a hostile/compromised provider (wrong return type, exception, fabricated references, or simply hanging).
A real provider *can* be plugged in later by implementing `TrajectoryReasonerProvider.assess()` — the interface
was built provider-neutral for exactly that future, optional, explicitly-untrusted-advisory-only experiment — but
doing so is out of scope here by design, not by omission.

**Cost discipline:** `Navigator2.check()` only calls the reasoner when there is something for it to resolve —
see `core.py`'s `_needs_reasoner()`: an unresolved contract ambiguity, an `escalate`-or-worse policy decision, or
an `indeterminate`-coverage evidence finding. A routine fully-authorized low-risk call never reaches the reasoner,
and even when it is invoked, `_call_reasoner()` bounds it to `reasoner_timeout_seconds` (default 2s) and every
failure mode (timeout, exception, wrong type, fabrication) is caught and converted to the same
"evidence-coverage-gap" signal POL-007 already handles — see §0.

## 8. Component 6 — Evidence Modules (`evidence.py`)

- `ShellEvidenceModule` — calls `kavach.ministers.ast_parse.extract_words(cmd, dialect)` (the repo's existing
  bashlex/PowerShell-AST integration, not a new parser). Coverage is `"full"` when `used_ast=True`, `"partial"`
  when the tokenizer fallback was used for a theoretically-supported dialect, `"indeterminate"` for
  `command_prompt`/unknown dialects (matching `ast_parse.py`'s own documented three-way split) — **parsing proves
  syntax, not intent or safety**, and an indeterminate finding is never silently treated as safe (feeds POL-007).
- `DecodeExecutionEvidenceModule` — walks the `bashlex` AST for `name=$(decode-cmd ...)` assignment shapes
  (`base64 -d`, `base32 -d`, `xxd -r`) and checks whether that same variable name is later used as an execution
  sink in the *same command string* (`eval "$name"`, `bash <<< "$name"`, `sh -c "$name"`, `` `$name` ``,
  `$($name)`). This directly targets the task brief's named failure (the prior evidence prototype missed a
  decoder "stored in a variable that the static analyser did not resolve") by doing single-hop variable
  resolution via the AST instead of a same-line regex proximity match (which is what EXECUTOR's existing
  `base64-decode-then-exec` rule in `prefilters.py` already does, and continues to do — this module adds
  strictly more structural evidence, it does not replace or weaken EXECUTOR's own rule). **Explicitly documented
  limitation:** resolution is one hop and intra-command only; a decoder assigned in one tool call and executed in
  a *later* call is not resolved here (that is a CROSS-CALL case tracked by the ledger/POL-007, not claimed as
  solved by this module) — a decode-only or execute-only finding with no resolvable pairing reports
  `coverage="partial"`, never a confirmed decode-execute claim.
- `MinisterFindingsAdapter` — wraps the four already-computed legacy `MinisterResult`s (VAULT/EXECUTOR/CHANNEL/
  legacy NAVIGATOR) into `EvidenceFinding`s. The legacy-NAVIGATOR one is tagged
  `module="legacy_navigator_semantic"` and its claim text explicitly says "supporting anomaly signal only, not
  independent proof" — this is the direct implementation of the task brief's "do not treat duplicated semantic
  alerts as independent proof."
- `DestinationHeuristic` (small helper inside `evidence.py`, not a public module) extracts email-shaped and
  `scheme://host` tokens from the call's own arguments (simple regexes, documented as heuristic/partial
  coverage) so POL-001 has a concrete destination string to compare against `contract.approved_destinations`,
  rather than only having CHANNEL's already-computed verdict (which doesn't know the user's contract).

## 9. Component 7 — Verdict and Explanation (`verdict.py`)

`compose(contract, policy_decisions, reasoner_response, legacy_results, evidence)` → `Navigator2Verdict`:

1. If any `PolicyDecision.verdict == "block"` → final `block` (this covers both NAVIGATOR 2.0's own proven
   policies *and* POL-005's pass-through of a legacy hard BLOCK — **a legacy BLOCK can never be downgraded**,
   satisfying acceptance criterion 2 structurally, not as a special case bolted on afterward).
2. Else if any `PolicyDecision.verdict == "escalate"`, or the reasoner's `recommended_disposition` is `"escalate"`
   → final `escalate`.
3. Else if the reasoner's `recommended_disposition == "block"` **but no policy decision backs it** → capped to
   `escalate` (`reasoner_capped=True` recorded on the verdict) — a model's own recommendation is never alone
   sufficient to reach `block` (acceptance criterion 7: "no fabricated authority"; task brief: "a positive
   semantic match/model vote alone does not prove").
4. Else if evidence coverage is incomplete anywhere relevant (any `EvidenceFinding.coverage == "indeterminate"`
   feeding this decision) → `escalate` (never silently `allow` on missing coverage, acceptance criterion 6).
5. Else `allow`.

Every `Navigator2Verdict` records `policy_version` (engine's own fixed version string), `contract_version`, the
contributing `event_ids`, the `evidence` list, which specialist verdicts were considered
(`specialist_results_considered: dict[str,str]` — verdict strings only), and `requires_approval`. No raw secret
text, VAULT match text, or full tool-output body is ever placed in `reason`/`explanation` — only short claims and
IDs, mirroring `kavach/ministers/__init__.py::scan_to_result`'s own `redact_match` discipline for VAULT.

## 10. File map

```
kavach/ministers/navigator2/
  __init__.py       re-exports the public surface
  schemas.py         IntegrityLabel, ConfidentialityLabel, TaskContract, ContractRevision, SessionEvent,
                      EvidenceFinding, PolicyDecision, ReasonerRequest, ReasonerResponse, Navigator2Verdict
  contract.py        TaskContractStore, UntrustedRevisionAttempt, start_session()
  ledger.py          SessionEventLedger, event-id/seq allocation, history-gap handling
  provenance.py       compute_label(), merge_integrity(), merge_confidentiality()
  evidence.py        EvidenceModule protocol, ShellEvidenceModule, DecodeExecutionEvidenceModule,
                      MinisterFindingsAdapter, run_all()
  policy.py          Policy protocol, POL-001..POL-009, PolicyEngine
  reasoner.py        TrajectoryReasonerProvider protocol, NullReasonerProvider, DeterministicMockProvider,
                      validate_response(), ReasonerFabricationError
  verdict.py         compose()
  core.py            Navigator2 orchestrator (check()), _needs_reasoner(), _propagate_confidentiality(),
                      _call_reasoner() (timeout-wrapped)
  shadow.py          ShadowRunner — the single, zero-touch integration point with the real Coordinator
  episodes.py        the 19-episode task-level suite (Part 6), covering all 10 required scenario types plus
                      9 extra variants (false-positive guards, forged references, explicit restrictions, ...)
  eval_runner.py      runs episodes through ShadowRunner, writes machine-readable JSON results

tests/
  test_navigator2_unit.py      Components 1-7, isolated, no model/API needed
  test_navigator2_shadow.py    shadow-mode isolation + specialist-BLOCK-preservation + zero-touch proof
  test_navigator2_episodes.py  task-level suite, run through the real eval_runner
```

No file outside `kavach/ministers/navigator2/`, `tests/test_navigator2_*.py`, and the four `docs/navigator2-*.md`
deliverables was created or modified for this work. See `docs/navigator2-report.md` for the exact `git status`
proof.

## 11. What this architecture does not claim

- It does not claim real dynamic taint tracking — provenance labels are a call-scoped heuristic, stated as such
  everywhere they are computed (§5).
- It does not claim CaMeL's interpreter-level control/data-flow separation — only the one narrow, high-value rule
  (untrusted content cannot revise the task contract) was carried over.
- It does not claim the reasoner component works with a real LLM — it is built and tested against a documented
  deterministic mock; wiring a real provider and re-evaluating is named as future work in
  `docs/navigator2-report.md`.
- It does not claim to replace the legacy NAVIGATOR, VAULT, EXECUTOR, or CHANNEL — it is additive and
  shadow-only. The migration plan (`docs/navigator2-migration-matrix.md`) is explicitly staged and partial.

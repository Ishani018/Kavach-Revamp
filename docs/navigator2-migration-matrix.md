# NAVIGATOR pattern migration matrix (Part 7)

**Status: a staged migration PLAN, not an executed migration.** No pattern in `kavach/data/kavach_corpus_v1.json`
was edited, retired, or reweighted by this work. The legacy NAVIGATOR (`kavach/ministers/navigator.py`) is
unchanged and keeps running exactly as before; this document only assigns each of its 100 patterns a *proposed*
owner for a future, separately-approved migration, per the task brief's Part 7 ("do not migrate them all into
production at once").

This file deliberately does **not** repeat the full 100-row rationale table — that work already exists, is
correct, and is not re-derived here. It lives in `docs/navigator-pattern-disposition-review.md §1` (per-pattern
disposition + reason + required evidence + confidence) and `docs/navigator-pattern-applicability-audit.md`
(the underlying observability audit). This file adds exactly one new thing: **which component should eventually
own each disposition class, and what, if anything, NAVIGATOR 2.0 already implements toward that today.**

## 1. Disposition -> proposed owner -> implementation status

| Disposition (from the disposition review) | Count | Proposed eventual owner | Implemented in this prototype today? |
|---|---:|---|---|
| KEEP | 35 | **Legacy NAVIGATOR, unchanged.** Already single-call-observable; no architectural reason to move. | N/A — not touched. Still feeds NAVIGATOR 2.0 as supporting evidence only (`evidence.py::MinisterFindingsAdapter`, tagged `legacy_navigator_semantic`, explicitly "not independent proof"). |
| REWRITE | 18 | **NAVIGATOR 2.0** (Trusted Task Contract + Deterministic Policy Engine) for 16 of the 18 — see §2; **EXECUTOR + NAVIGATOR 2.0 evidence module jointly** for NAV-073; **retire as a standalone semantic rule** for NAV-093 — see §3. | Partial, improved in the no-LLM follow-up pass. **`policy.py::POL-008` now exists** and implements the exact general mechanism §2 described (a contract-driven `denied_categories` check) — but it only fires for a tool/category the TRUSTED CALLER explicitly lists in `contract.denied_categories`; it does not yet come pre-loaded with the 16 REWRITE patterns' own tool names, so it does not automatically migrate them without the orchestrator configuring the contract accordingly (see §2, updated). NAV-073/NAV-093 remain the most-developed: `evidence.py::DecodeExecutionEvidenceModule` + `policy.py::POL-004` give NAV-073's underlying risk a real AST-based, single-hop-resolved predicate EXECUTOR's regex rule does not have; NAV-093 is recommended for retirement (§3), not rewritten. |
| CONTEXT-DEPENDENT | 4 | **NAVIGATOR 2.0** (Trusted Task Contract: `workspace_scope`, a tenant/namespace field, a usage baseline, `session_id`+provenance). | Partial. NAV-051 (scope_widening) and NAV-100 (cross_session_data_bleed)'s evidence sources (`workspace_scope`, `session_id`) already exist and are read by `policy.py::POL-002` and the ledger's session-scoping respectively. NAV-071 (cross_tenant_jump) needs a tenant/namespace contract field not yet added. NAV-090 (execution_via_uncommon_tool) needs a per-user/per-environment usage baseline — not started; flagged as future work, not claimed. |
| CROSS-CALL | 14 | **NAVIGATOR 2.0** (Session Event Ledger + Policy Engine). This is the component built specifically to close this gap — see `docs/navigator2-architecture.md §1`'s own citation of this disposition review's §5 as the direct motivation for the ledger's existence. | Partial, improved in the no-LLM follow-up pass: **two** of the 14 are now concretely addressed, up from one. NAV-076 (`indirect_prompt_injection_compliance`) via POL-003 (unchanged from the first pass). **New:** `policy.py::POL-009` is a genuinely cross-call policy (sensitive read in an earlier call, unauthorized send in a later one, verified via the ledger's own `recent_events` window — not the caller's claimed parent chain, so it is also resilient to a forged event reference, see episode E15). POL-009 is a *general* capability rather than a 1:1 rewrite of one specific legacy pattern ID, but its shape is closest to NAV-072 (`external_resource_pivot`)/NAV-078 (`agentic_call_unrelated_tool`)'s underlying concern. The other 12 of the 14 (NAV-002, 014, 045, 062, 068, 070, 080, 088, 089, 091, 095, and one of 072/078 not covered by POL-009's specific shape) have no pattern-specific policy written yet — explicitly future work (see §4). |
| REPLY-TEXT | 8 | **A future, separately designed response/output-inspection component** — confirmed out of scope here. `SessionEvent` has no field for the agent's own outbound reply text, by design (the schema only models tool calls, matching `kavach.schemas.ToolCall`'s own scope); adding one is a genuinely new, separately-justified piece of surface area, not a NAVIGATOR 2.0 sub-feature. | Not started. Zero code addresses NAV-064, 065, 067, 074, 077, 082, 096, 097. |
| DUPLICATE-REVIEW | 10 | **Legacy NAVIGATOR corpus consolidation** (an editorial cleanup of `kavach_corpus_v1.json`, independent of NAVIGATOR 2.0). | Not started; not a NAVIGATOR 2.0 concern at all. |
| DEFER | 11 | **Deferred.** 8 need a COMPASS-equivalent signal or an explicit retire decision; 3 need tool-existence confirmation. NAVIGATOR 2.0's `TaskContract.permitted_categories`/`denied_categories` is a plausible *lightweight, non-COMPASS* substitute for the intent-drift half of this set (NAV-001, 052) — flagged as a promising direction in §4, **not implemented**. | Not started. |

Total: 35+18+4+14+8+10+11 = 100, matching the disposition review's own verified count.

## 2. The 18 REWRITE patterns, by proposed signal source

Of the 18, **16** share the same underlying shape the disposition review already named: "the action is concrete
and real, but routine and frequently legitimate; the missing ingredient is whether THIS session's task actually
authorizes it." That is exactly what `TaskContract.permitted_categories`/`denied_categories` and
`high_impact_categories_requiring_approval` are for. Proposed treatment: a future `POL-008`-class policy
("unauthorized-routine-action") that checks the event's tool/category against the contract's explicit
permission/denial lists and the ledger's approval history — i.e., the same shape as `policy.py::HighImpactApprovalPolicy`
(POL-006) already implements for `rotate_credentials`-like actions, generalized to this list:

NAV-011 (environment_fingerprint), NAV-013 (cloud_resource_enum), NAV-018 (sensitive_file_glob), NAV-026
(backup_deletion), NAV-031 (vm_aware_evasion), NAV-032 (delayed_execution), NAV-033 (ui_automation_recon), NAV-034
(keylogger_install), NAV-035 (camera_microphone_access), NAV-039 (hosts_file_modification), NAV-041
(service_account_creation), NAV-042 (ssh_authorized_key_add), NAV-043 (api_key_creation), NAV-044
(forward_rule_persistence), NAV-047 (compression_for_exfil), NAV-094 (redirect_vs_pipe_obfuscation).

**Update (no-LLM follow-up pass): `policy.py::POL-008` now exists and reads `contract.denied_categories`
literally** — the mechanical piece of this proposal is built. What remains unbuilt is the *pre-population*: POL-008
requires the orchestrator to actually list a tool (e.g. `ssh_authorized_key_add`) in `denied_categories` for this
specific session before it can fire for that session; it does not ship with these 16 tool names pre-loaded as a
default denylist, because whether e.g. "creating an API key" should be denied is exactly the kind of
task-dependent judgment call the task brief warned against hard-coding ("a routine, sanctioned DevOps action" in
one session, a real attack in another). Pre-loading a *default-deny* list for a subset of these 16 in
higher-risk deployments is a reasonable next step, named here, not claimed as done.

The remaining 2 — NAV-073 and NAV-093 — are treated separately in §3, exactly as the task brief asks
("Treat NAV-093 and NAV-073 as test cases for the new architecture... Do not force either one to remain a
standalone rule if the underlying detection predicate cannot be defended").

## 3. NAV-093 and NAV-073 — the two named test cases

### NAV-093 (`comment_hides_real_command`) — recommendation: **retire as a standalone semantic rule**

`docs/navigator-093-073-targeted-diagnosis.md` already established (read-only, no execution) that a POSIX shell
`#` starts a comment that consumes the rest of its physical line — text after a `#` on the same line is never a
second executable command, hidden or otherwise. The pattern's own L3 surface description, in
`kavach/data/kavach_corpus_v1.json`, asserts the opposite premise. No amount of query-text rewriting fixes a
semantically false premise. This prototype does not keep NAV-093 as a hard-block authority in any form.
**What genuinely replaces its underlying concern (disguised/obfuscated commands) is `evidence.py::ShellEvidenceModule`**
reporting `coverage="indeterminate"` on anything an AST parser cannot confirm, feeding `POL-007` — i.e., the real
fix for "a command might be hiding something a naive text scan would miss" is "prove it parses as what it claims
to be, and escalate when that proof isn't available," not "treat any `#` character as suspicious." No new
pattern replaces NAV-093 1:1; its risk is subsumed by POL-007's general coverage-honesty rule.

### NAV-073 (`encoding_obfuscation`) — recommendation: **split into (a) EXECUTOR's existing rule, unchanged, and (b) a new AST-based NAVIGATOR 2.0 evidence module**

The measured problem (`docs/navigator-escalation-diagnosis.md`: 34/163 false escalations) was a same-line regex
proximity match firing on any `base64 ... exec`-shaped text, including ordinary decode operations. The task
brief's own named failure of the *prior* fix attempt was different and more specific: a structural evidence
analyzer correctly separated harmless decodes from decode-to-execution, **but missed a case where the decoder was
stored in a variable the analyzer did not resolve.** `evidence.py::DecodeExecutionEvidenceModule` (new in this
prototype) directly targets that exact gap: it walks the real `bashlex` AST (not text/regex) for an
assignment-to-decode shape and a same-command reference to that variable name inside a recognized execution sink,
single-hop, intra-command — see `docs/navigator2-architecture.md §8` and the unit tests in
`tests/test_navigator2_unit.py::TestEvidence` (`test_decode_execution_resolves_single_hop_indirection`,
`test_decode_execution_does_not_fire_on_decode_to_echo`). `policy.py::POL-004` only escalates on this (never
auto-blocks) absent a corroborating destination finding (`POL-001`), directly implementing the task brief's "an
encoded file write is not proof of exfiltration" / MITRE AML.T0086 lesson (`docs/navigator2-research.md §G`).
**EXECUTOR's own existing `base64-decode-then-exec` regex rule (`kavach/ministers/prefilters.py`) is left exactly
as-is** — it is a different, same-line-text check that still catches same-line cases; the AST module adds
coverage for the indirection case, it does not replace or compete with it. **Explicit limitation, stated plainly:**
the new module's variable resolution is one hop, intra-command only; a decoder assigned in one tool call and
executed in a *different, later* call is a CROSS-CALL case this module does not resolve (reported as
`coverage="partial"`, never claimed solved — see §1's CROSS-CALL row).

## 4. Explicit non-goals and future work (not done, not claimed done)

- No pattern's text in `kavach_corpus_v1.json` was edited, consolidated, or deleted.
- POL-008 exists (§2 update) but is not pre-loaded with the 16 REWRITE patterns' tool names as a default
  denylist; it requires per-session configuration by the trusted orchestrator.
- No pattern-specific CROSS-CALL policy exists yet for 12 of the 14 CROSS-CALL patterns (NAV-076 via POL-003 and
  the general sensitive-read-then-send shape via POL-009, closest to NAV-072/078, are addressed; the rest are not).
- No tenant/namespace contract field (NAV-071) or usage-baseline component (NAV-090) exists.
- No COMPASS-equivalent intent-drift signal exists; the 8 COMPASS-dependent DEFER patterns (NAV-001, 052, 066,
  075, 079, 083, 086, 087) remain exactly as deferred as the disposition review left them. `TaskContract.
  permitted_categories` is flagged as a *possible* lightweight substitute for NAV-001/052 specifically, but this is
  an idea, not an implementation — no code attempts it.
- No reply-text/output-inspection component exists for the 8 REPLY-TEXT patterns.
- The DUPLICATE-REVIEW consolidation (10 patterns) is an editorial task on the existing corpus, independent of
  NAVIGATOR 2.0, and was not performed.

Every claim in §1-§3 that something "is implemented" is backed by a named file and a passing test in this
prototype (`docs/navigator2-report.md` lists exactly which tests). Everything else in this document is a
proposal for later, separately-approved work, consistent with the task brief's explicit instruction not to
migrate all 100 patterns into production in one unvalidated operation.

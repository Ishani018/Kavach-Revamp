# NAVIGATOR 2.0 — final report

## 0. Continuation: making the security core genuinely zero-LLM (read this first)

This report now covers TWO passes. Pass 1 built the seven-component shadow-mode prototype described in §1. Pass 2
(this section) was a **fundamental architecture correction**: reassess the prototype and make it a *locally
executable, deterministic-first* security core that does not need an LLM at all, rather than one that merely
tolerates a mocked reasoner in tests. Nothing in Pass 1 ever called a real/paid LLM API either — but Pass 2 made
that a structural, tested guarantee instead of an incidental fact, and used the reassessment to close several real
gaps (confidentiality propagation was defined but never wired in; no policy read `denied_categories`; no
genuinely cross-call policy existed; the reasoner call had no timeout; a hostile/malformed reasoner response was
only partly handled).

### 0.1 Which components genuinely run without an LLM

**All of them, always, for the deterministic path; the optional reasoner path too, by construction.** Concretely:

| Component | Runs without an LLM? | Detail |
|---|---|---|
| Trusted Task Contract (`contract.py`) | Always — pure Python/pydantic, no model call anywhere | `start_session()`/`revise()` are deterministic functions |
| Session Event Ledger (`ledger.py`) | Always | A plain dict-backed append/lookup store |
| Integrity/Confidentiality Provenance (`provenance.py`, `core.py::_propagate_confidentiality`) | Always | Heuristic rules over `call.context` keys and legacy minister verdict strings; a merge over two enums |
| Evidence Modules (`evidence.py`) | Always | `bashlex` AST parsing + regex, both local, both already-vendored dependencies (no new one added) |
| Deterministic Policy Engine (`policy.py`, 9 policies) | Always | Every policy is a pure function of `PolicyFacts`; `PolicyEngine.evaluate_all()` never imports or calls anything reasoner-shaped |
| Verdict Composer (`verdict.py`) | Always | A pure function; the reasoner's output, if present, is one of several *optional* inputs it reads, never a required one |
| Shadow Runner (`shadow.py`) | Always | Calls the real `Coordinator.evaluate()` (itself LLM-free — Kavach's ministers are retrieval/regex/AST-based, not generative) plus `Navigator2.check()` |
| Constrained Trajectory Reasoner (`reasoner.py`) | **Optional, and its default implementation also runs without an LLM** | Default provider is `DeterministicMockProvider`, a documented rule-based function. No file anywhere in this package imports `anthropic`, `openai`, or any HTTP client. A real model could be plugged in later via `TrajectoryReasonerProvider`, but none is, by design (§0.5). |

**Measured, not asserted:** of the 19-episode × (up to 3 steps each) = 35 total proposed actions in the synthetic
suite, **the reasoner was invoked for only 4 of 35 (11%)** — every other decision was reached by deterministic
policy/evidence alone (`python3 -c "from kavach.ministers.navigator2.eval_runner import run_suite; ..."`, see
§0.6 for the exact numbers). `core.py::_needs_reasoner()` is the single gate that decides this, and it is itself
plain, reasoner-free Python.

### 0.2 Which inputs must come from the trusted orchestrator

NAVIGATOR 2.0 cannot and does not invent these; if the caller does not supply them, the documented conservative
default applies (never a silent broad permission):

- **The task contract's substance** — `goal`, `workspace_scope`, `permitted_categories`, `denied_categories`,
  `approved_destinations`, `high_impact_categories_requiring_approval` — via `TaskContractStore.start_session()`.
  If never called, `get_or_create()` auto-creates an empty, unscoped contract (§architecture.md §3) — policies
  that need positive authorization then lean toward `escalate`, never `allow`, for anything ambiguous.
- **Per-call context** — `call.context["user_instruction"]` and `call.context["tool_output"]` — the ONLY signal
  `provenance.compute_label()` uses to decide `TRUSTED_INSTRUCTION` vs `UNTRUSTED_EXTERNAL`. A caller that never
  populates `tool_output` for content that actually came from an untrusted source would cause NAVIGATOR 2.0 to
  misjudge that content as having unknown-but-not-flagged integrity — this is a real, named limitation (§0.4), not
  hidden.
- **Already-computed specialist results** (`legacy_results: Dict[str, MinisterResult]`) — NAVIGATOR 2.0 never
  re-runs VAULT/EXECUTOR/CHANNEL/legacy-NAVIGATOR itself; `shadow.py` is what supplies the real ones from the real
  Coordinator. A caller using `Navigator2.check()` directly (bypassing `ShadowRunner`) must supply these for
  POL-001/005/009 and provenance confidentiality to have any signal at all.
- **(Optional) `parent_event_ids`** — if omitted, `core.py` auto-chains to the session's own immediately-preceding
  event, which is a reasonable default but is still a claim the orchestrator is implicitly making; POL-009 is
  deliberately built to not depend on this claim being honest (§0.3, episode E15).
- **(Optional) approval events** — `source_kind="approval"` must be explicitly asserted by the orchestrator when a
  human actually approves a high-impact action; NAVIGATOR 2.0 has no way to independently verify a real human
  clicked "approve."

### 0.3 Concrete policy rules and their evidence requirements (updated: 9, was 7)

See `docs/navigator2-architecture.md §6` for the full table with rationale; summarized:

| ID | Rule | Evidence required | New this pass? |
|---|---|---|---|
| POL-001 | proven-exfil-to-unauthorized-destination | destination string + non-PUBLIC confidentiality, both on THIS event | no |
| POL-002 | contract-scope-violation | a declared `workspace_scope` + an out-of-scope path on THIS event | no |
| POL-003 | untrusted-content-privilege-induction | an actual rejected `UntrustedRevisionAttempt` | no |
| POL-004 | decode-execute-structural | AST-confirmed (not regex) decode→execute, resolved | no |
| POL-005 | specialist-hard-block-preserved | a real legacy `MinisterResult.verdict == "BLOCK"` | no |
| POL-006 | high-impact-without-approval | contract-declared high-impact tool + no prior approval event | no |
| POL-007 | insufficient-evidence-coverage | any `coverage == "indeterminate"` finding | no |
| **POL-008** | **explicit-task-restriction-violation** | **tool literally in `contract.denied_categories`** | **yes** |
| **POL-009** | **cross-call-sensitive-read-then-transmit** | **unauthorized destination on THIS event + a genuine, artifact-touching, PRIVATE/SECRET event found in the ledger's own `recent_events` window (independent of the claimed parent chain)** | **yes** |

### 0.4 What remains impossible or uncertain without additional context (named honestly)

- **Whether `call.context` is honest.** If an orchestrator mislabels untrusted content as `user_instruction`
  (or never populates `tool_output` for genuinely untrusted content), NAVIGATOR 2.0's entire integrity model is
  fed a false signal. There is no way to verify this from inside the minister — it is a trust boundary this
  component sits *behind*, not one it can independently audit.
- **Whether a reported approval is real.** `source_kind="approval"` is trusted at face value (§0.2).
  A compromised orchestrator could fabricate an approval event. Verifying real human provenance (e.g. a signed
  approval token) is out of scope here.
- **Real-world detection effectiveness at scale.** The 9 policies and their evidence requirements are each
  individually, narrowly correct for what they check — but they cover a small slice of the legacy NAVIGATOR's 100
  patterns' underlying risks (`docs/navigator2-migration-matrix.md §1`: 12 of 14 CROSS-CALL, all 8 REPLY-TEXT,
  most of the 18 REWRITE patterns, and all COMPASS-dependent DEFER patterns remain unaddressed). This was true
  before this pass and remains true now; the pass added depth (propagation, 2 new policies, hardened reasoner
  handling), not breadth.
- **Decoder resolution beyond one hop / one call.** `DecodeExecutionEvidenceModule` still only resolves
  intra-command, single-hop variable indirection, exactly as documented in Pass 1.
- **A tenant/namespace field, a usage baseline, a COMPASS-equivalent drift signal, a reply-text component** — none
  exist, unchanged from Pass 1.

### 0.5 Why no LLM was wired in, restated as a decision, not an omission

A second model is itself attackable by the same untrusted content NAVIGATOR 2.0 exists to defend against (the
exact concern a prompt-injected `tool_output` raises against a reasoner that reads it). A mandatory paid API would
add cost, latency, a network dependency, API-key management, and a new attack surface to Kavach's security core.
This pass therefore: (a) kept the reasoner strictly optional and provider-neutral, (b) hardened every one of its
failure modes (timeout, exception, wrong return type, fabricated references) to fail toward the same
escalate-safe path as "no reasoner at all," and (c) added a test proving a hostile reasoner cannot even expand the
task contract via its free-text claims (`test_reasoner_cannot_expand_the_task_contract`). **No LLM integration was
implemented, by design — this is stated as a decision, not deferred as unfinished work.** A real provider remains
pluggable later, as an explicitly untrusted, advisory-only, future experiment (task brief's own Part 4).

### 0.6 Setup, usage, and a worked example

No setup beyond the repository's existing `requirements.txt` (already-installed `bashlex`, `pydantic`; no new
dependency was added). No API key, no network access, no model download.

```bash
# Run the deterministic-core test suite (fast, <1s, no model/API):
python3 -m pytest tests/test_navigator2_unit.py tests/test_navigator2_shadow.py \
                  tests/test_navigator2_episodes.py -q -m "not slow"

# Also run the one slow test that proves genuine wiring against the REAL Coordinator
# (loads the BGE embedding model + ChromaDB, ~11s, still no API key/network needed):
python3 -m pytest tests/test_navigator2_shadow.py -m slow -q

# Run the 19-episode task-level suite and write machine-readable results:
python3 -m kavach.ministers.navigator2.eval_runner --json kavach/ministers/navigator2/eval_results.json
```

Constructing a contract and feeding an event, end to end:

```python
from kavach.ministers.navigator2.core import Navigator2
from kavach.schemas import ToolCall, MinisterResult

nav2 = Navigator2()  # DeterministicMockProvider by default -- no API key needed
nav2.contract_store.start_session(
    "session-1", goal="Email the weekly report to the finance team",
    approved_destinations=["finance-team@ourcompany.com"],
)

call = ToolCall(
    tool_name="send_email",
    arguments={"to": "finance-team@ourcompany.com", "body": "weekly report"},
    session_id="session-1",
)
verdict = nav2.check(call)
print(verdict.disposition)       # "allow" -- destination was pre-approved
print(verdict.policy_decisions)  # [] -- no policy objected
```

```python
# The same call to an UNAPPROVED destination:
call2 = ToolCall(tool_name="send_email", arguments={"to": "unknown@external.com", "body": "..."}, session_id="session-1")
legacy = {"VAULT": MinisterResult(minister="VAULT", verdict="ESCALATE", reason="looks sensitive")}
verdict2 = nav2.check(call2, legacy_results=legacy)
print(verdict2.disposition)       # "block"
print(verdict2.policy_decisions[0].policy_id)  # "POL-001"
print(verdict2.policy_decisions[0].reason)     # cites the unauthorized destination and confidentiality
```

**Measured runtime overhead** (this prototype's own code, on the development machine, not a real LLM's latency):
- Deterministic-only path (no reasoner invoked): **~0.06 ms/call** (200-call average).
- Reasoner-invoked path (mock provider + `ThreadPoolExecutor` setup/teardown): **~0.18 ms/call** (50-call average).
- Full 19-episode/35-step synthetic suite: **~9.4 ms total**, reasoner invoked on 4/35 steps (11%).
These numbers describe only this prototype's own deterministic/mock overhead; a real LLM reasoner (if ever wired
in, per §0.5) would add real network latency on the 4/35 steps that actually reach it — exactly why the 2-second
timeout and "only-when-needed" gating exist.

### 0.7 Migration plan: integrating into the real Coordinator in a later phase (unchanged conclusion, restated)

This remains explicitly NOT done, and the reasoning is unchanged from Pass 1: `shadow.py::ShadowRunner` is the
integration surface, and it is a wrapper, not a change to `Coordinator`. A future cutover would require, in order:
(1) the next-steps list in §10 (broader episode set, more policies); (2) an explicit decision by the project owner
about which NAVIGATOR 2.0 dispositions (if any) should start influencing `Speaker.decide()`, and in what role
(e.g. an additional required minister vs. an advisory annotation on `Decision`); (3) a schema change to
`kavach/schemas.py::Decision`/`MinisterResult` if NAVIGATOR 2.0's richer verdict shape needs to surface beyond
`BLOCK/ESCALATE/ALLOW`; (4) the one-time, sign-off-gated confirmation run against the Phase A reserved split
(§5, §7 criterion 10) — not before (1)-(3).

---

## 1. What this is, in one paragraph

A parallel, shadow-mode-only prototype (`kavach/ministers/navigator2/`) implementing all seven components the
task brief specified (Trusted Task Contract, Session Event Ledger, Integrity/Confidentiality Provenance,
Deterministic Policy Engine, Constrained Trajectory Reasoner, Evidence Modules, Verdict/Explanation), wired to the
real production `Coordinator` through exactly one new, additive file (`shadow.py`) that touches zero existing
files. It is now tested by 82 fast component/shadow/episode unit tests plus 1 slow real-Coordinator integration
test (83 total), and a 19-episode, hand-authored task-level evaluation suite covering all 10 scenario types the
task brief required plus 9 extra variants (false-positive guards, forged event references, explicit restriction
violations, keyword-without-structure). All of it passes. None of it changes what the production system does
today.

## 2. Git state

| | Start of session | End of session |
|---|---|---|
| Branch | `mvp-core` | `mvp-core` (unchanged) |
| HEAD commit | `328bd83` | `328bd83` (unchanged — nothing committed, per instructions) |
| Pre-existing modified files | `.gitignore`, `kavach/ministers/channel.py`, `kavach/ministers/channel_taint.py`, `tests/conftest.py`, `tests/test_channel.py` | **identical, byte-for-byte** (`git diff --stat` on these five files shows the same 113 insertions / 3 deletions as the session-start snapshot; verified by direct diff, not assumption) |
| Pre-existing untracked dirs/files (`.claude/`, `docs/`, `evaluation/`, `review/`, `supabase/`, `tests/navigator_support.py`, `tests/test_channel_scenarios.py`, `tests/test_evaluation.py`, `tests/test_navigator_baseline.py`, `tests/test_navigator_desired.py`, `tests/test_navigator_experiment.py`) | present, untracked | **untouched** — none of their content was edited; `docs/` and `kavach/ministers/` gained new sibling files/directories only |

No `git commit`, `git push`, `git reset`, `git stash`, `git clean`, or `git revert` was run at any point.

## 3. Files created (exhaustive)

```
docs/navigator2-research.md
docs/navigator2-architecture.md
docs/navigator2-migration-matrix.md
docs/navigator2-report.md                      (this file)

kavach/ministers/navigator2/__init__.py
kavach/ministers/navigator2/schemas.py
kavach/ministers/navigator2/contract.py
kavach/ministers/navigator2/ledger.py
kavach/ministers/navigator2/provenance.py
kavach/ministers/navigator2/evidence.py
kavach/ministers/navigator2/policy.py
kavach/ministers/navigator2/reasoner.py
kavach/ministers/navigator2/verdict.py
kavach/ministers/navigator2/core.py
kavach/ministers/navigator2/shadow.py
kavach/ministers/navigator2/episodes.py
kavach/ministers/navigator2/eval_runner.py
kavach/ministers/navigator2/eval_results.json  (generated machine-readable output, see §6)

tests/test_navigator2_unit.py
tests/test_navigator2_shadow.py
tests/test_navigator2_episodes.py
```

## 4. Files modified

**Outside the NAVIGATOR 2.0 prototype itself: none, still.** Every pre-existing tracked file and every
pre-existing untracked file/directory (`.claude/`, the pre-Pass-1 `docs/*.md`, `evaluation/`, `review/`,
`supabase/`, the pre-Pass-1 `tests/*.py`) remains exactly as it was at the start of Pass 1. This was a deliberate
design choice (`docs/navigator2-architecture.md §2`): rather than adding an optional parameter to
`Coordinator.__init__` (which would have required either changing `Decision`'s schema — breaking the
"byte-for-byte identical when off" requirement at the JSON level — or adding a code path inside
`kavach/coordinator.py` that the task brief asked to avoid risking), the shadow integration is a separate wrapper
(`shadow.py::ShadowRunner`) that calls `Coordinator.evaluate()` completely unmodified and builds its NAVIGATOR 2.0
assessment alongside, never inside, the production call. This is verified, not just argued: see
`tests/test_navigator2_shadow.py::TestShadowZeroTouch::test_decision_identical_with_and_without_shadow`, which
asserts the two Decisions' JSON serializations are literally equal.

**Within the NAVIGATOR 2.0 prototype (this pass's actual work, all inside `kavach/ministers/navigator2/`,
`tests/test_navigator2_*.py`, and the four `docs/navigator2-*.md` files already listed in §3 — no new files were
needed):**

| File | What changed this pass |
|---|---|
| `kavach/ministers/navigator2/core.py` | Added `_propagate_confidentiality()` (wires the previously-unused `merge_confidentiality` into the live event pipeline); added `_call_reasoner()` (wall-clock-bounded `ThreadPoolExecutor` call); hardened the reasoner-invocation block to handle timeout, wrong-type return, and arbitrary exceptions, each converted to an indeterminate evidence finding rather than a crash or silent allow |
| `kavach/ministers/navigator2/schemas.py` | Added `Navigator2Verdict.reasoner_timed_out` and `.reasoner_rejected` fields |
| `kavach/ministers/navigator2/verdict.py` | `compose()` now accepts and threads through `reasoner_timed_out`/`reasoner_rejected` |
| `kavach/ministers/navigator2/policy.py` | Added `ExplicitRestrictionPolicy` (POL-008) and `CrossCallSensitiveReadThenSendPolicy` (POL-009); both registered in `DEFAULT_POLICIES` |
| `kavach/ministers/navigator2/episodes.py` | Added `Episode.denied_categories` field; added episodes E15 (forged-parent-reference cross-call), E16 (explicit restriction violation), E17 (keyword without structure) — 16 → 19 episodes |
| `kavach/ministers/navigator2/eval_runner.py` | Both `start_session()` call sites now pass `denied_categories` through |
| `tests/test_navigator2_unit.py` | Added POL-008/POL-009 unit tests, propagation asymmetry test, forged-parent-reference end-to-end test, malformed-arguments test, unavailable-parser (bashlex-unavailable) test, three hostile/malformed-reasoner tests, timeout test, reasoner-cannot-expand-contract test, deterministic-block-skips-reasoner test; fixed a `PolicyFacts.destinations`-vs-`event.destinations` divergence in the `_facts()` test helper surfaced while writing the POL-009 tests |
| `tests/test_navigator2_episodes.py` | Added assertions for E15/E16/E17; extended the "must reach a hard block" and "block must be policy-backed" checks to cover the new episodes |
| `docs/navigator2-architecture.md` | Added §0 (no-LLM architecture statement); updated §5 (confidentiality-only propagation, documented asymmetry with integrity) and §6 (POL-008/POL-009 added to the table); updated §7 and §10 (file map) |
| `docs/navigator2-migration-matrix.md` | Updated the REWRITE and CROSS-CALL rows and §2/§4 to reflect POL-008/POL-009 now existing (with their actual, narrower scope stated plainly) |
| `docs/navigator2-report.md` | This section and the rest of this continuation (§0, updated §1/§6/§7/§8/§11) |

No change in this list touches anything outside the prototype's own isolated surface.

## 5. Reserved-split confirmation

`review/phase-a-candidates/` and `review/heldout-candidates-batch-1/` were identified early (Phase A) as holding
unreviewed candidate data with an internal `diagnosis`/`reserved` split (`review/phase-a-candidates/README.md
§"The diagnosis / reserved split"`) and a reviewer-blinding protocol (`review/heldout-candidates-batch-1/README.md
§"Rules for reviewers"`). **Only each directory's `NOTICE.md` and `README.md` were read** (attribution/licence
text and the review protocol itself) — no `.jsonl`, `.csv`, or results `.json` file in either directory
(`navigator_diagnosis_items.jsonl`, `navigator_diagnosis_results.json`, `redcode_bash_items.jsonl`,
`swe_agent_items.jsonl`, `tldr_security_items.jsonl`, `phase_a_hints.jsonl`, `candidate_triage.jsonl`,
`candidate_triage_summary.json`, `review_items.jsonl`, `review_sheet.csv`, `selection_ids.json`) was ever opened,
listed-and-read, or passed to any tool. The 16 task-level episodes in `episodes.py` are 100% hand-authored by this
work for this task, independent of every one of those files.

## 6. What actually ran, and its result

### 6.1 New NAVIGATOR 2.0 test suite (`tests/test_navigator2_*.py`)

```
python3 -m pytest tests/test_navigator2_unit.py tests/test_navigator2_shadow.py \
                  tests/test_navigator2_episodes.py -q -m "not slow"
→ 82 passed, 1 deselected (the @pytest.mark.slow real-Coordinator smoke test), 1 warning, in 0.4s

python3 -m pytest tests/test_navigator2_shadow.py -m slow -q
→ 1 passed in ~11s (loads the REAL BGE embedding model + ChromaDB + real VAULT/EXECUTOR/CHANNEL/
  legacy NAVIGATOR via the repo's existing session-scoped `navigator` fixture; proves the shadow wiring
  works against the genuine production Coordinator, not just fixtures)
```

Total: **83/83 new tests pass** (up from 67 in Pass 1; +16 new tests added in the no-LLM-hardening pass covering
POL-008, POL-009, confidentiality propagation and its integrity asymmetry, a forged-parent-reference end-to-end
case, malformed call arguments, a simulated-unavailable parser, three distinct hostile/malformed-reasoner cases,
a reasoner timeout, and a direct "reasoner cannot expand the contract" proof).

### 6.2 Existing test suite, run the way the project runs it (`pytest tests/`)

```
python3 -m pytest tests/ -q
→ 248 passed, 10 xfailed, 1994 warnings, in ~33s   (3 of 4 runs during this session; see 6.3)
```

165 passed / 10 xfailed of these are the **pre-existing** suite; confirmed unchanged by running the same command
with the three `tests/test_navigator2_*.py` files excluded: `165 passed, 10 xfailed` exactly, both before and
after this pass's code changes. The remaining 83 passed are this work's tests. **The existing test suite's
pass/xfail counts are unchanged by this work.** Per the task brief's own caution, these counts are a code-health
result, not a measure of real-world security effectiveness, for either the old or the new code.

### 6.3 Two caveats, both investigated and found pre-existing, neither introduced by this work

**(a) `review/` collection interference (Pass 1 finding, re-confirmed).** Running bare `pytest` (no path — the
default collects **everything** under the repository root, including `review/`) shows `113-114 failed` inside
`review/navigator-evidence-prototype/test_evidence_rules.py`. Reproduces identically with zero NAVIGATOR 2.0
files in the collection at all (`review/navigator-evidence-prototype/` even ships its own separate `.venv/`,
confirming it was designed to be tested standalone). The project's own convention, and the command this report's
§6.2 numbers use, is `pytest tests/`.

**(b) A flaky pre-existing test, newly observed in this pass, root-caused to be unrelated to NAVIGATOR 2.0.**
`tests/test_navigator_baseline.py::test_live_navigator_reproduces_the_frozen_outputs` (and, once, its neighbor
`test_live_navigator_has_no_regression_against_the_baseline`) failed in 1 of 4 full-suite runs during this
continuation. Investigated directly: running **`pytest tests/test_navigator_baseline.py` alone, in total
isolation from every NAVIGATOR 2.0 file**, reproduces the same intermittent failure (2 of 3 isolated runs passed,
1 of 3 failed with the same two tests) — conclusively showing this is a pre-existing flake in that file's own
interaction with the real BGE embedding model/ChromaDB (most likely floating-point/embedding nondeterminism or a
collection-rebuild race the file's own `environment_matches()` guard does not catch), not something this pass's
code changes caused or can cause (the file and its dependencies were never touched). Recorded here rather than
hidden, per the task brief's own instruction not to claim a baseline is reproducible when the environment
contradicts that claim.

### 6.4 Task-level episode suite (`kavach/ministers/navigator2/episodes.py`, run via `eval_runner.py`)

```
python3 -m kavach.ministers.navigator2.eval_runner
→ NAVIGATOR 2.0 task-level episodes: 19/19 passed
```

Machine-readable results (per-episode, per-step disposition, policy IDs fired, reasoner invocation/capping/
timeout/rejection) are written to `kavach/ministers/navigator2/eval_results.json` (regenerate with the command
above; add `--real-coordinator` to also append a real-Coordinator smoke run for a chosen subset of episodes).

Episode coverage against the task brief's required list (19 episodes; all 10 originally-required types covered,
9 extra variants, 3 new this pass — E15, E16, E17):

| # | Required scenario | Episode(s) |
|---|---|---|
| 1 | Legitimate coding task | E01 |
| 2 | Malicious instruction embedded in README expanding the task | E02 |
| 3 | Untrusted webpage asking to read secrets / send externally | E03 |
| 4 | Benign data-analysis with sensitive-looking column names | E04 |
| 5 | Private info processed within an approved boundary | E05 |
| 6 | Multi-step read/transform/send | E06A (approved destination), E06B (unapproved, same-call), **E15 (unapproved, cross-call via a FORGED parent reference)** |
| 7 | Destructive/irreversible action outside requested scope | E07 |
| 8 | Benign task with encoded data / generated script | E08 |
| 9 | Ordinary-looking calls whose combined outcome violates policy | E09 (decode+execute), E09B (+ exfil) |
| 10 | Incomplete evidence -> correct answer is uncertainty/approval | E10 (unsupported dialect), E14 (approval cycle) |
| extra | misleading tool output, no concrete destination | E11 |
| extra | irrelevant untrusted text containing alarming words (false-positive guard) | E12 |
| extra | **explicit policy restriction violation** | **E16** |
| extra | **suspicious keyword, no corresponding dangerous structure** | **E17** |
| extra | missing/truncated event history | E13 |

Utility and security properties checked by `tests/test_navigator2_episodes.py` (not just "did it run"):
- Every `benign` episode: **zero** steps reach `block` (`test_legitimate_benign_steps_are_not_blocked`).
- Every `attack` episode: **at least one** step reaches `escalate` or `block`, i.e. no attack silently passes as a
  pure allow (`test_attack_episodes_never_pass_through_as_pure_allow`).
- The attack episodes with a proven destination or a preserved specialist hard-block (E02, E03, E06B, E09B)
  specifically reach `block`, not merely `escalate` (`test_most_attack_episodes_reach_a_hard_block`).
- E07 and E09 specifically **escalate, not auto-block** — a direct test of "do not optimise security by blocking
  everything."
- E11/E12/E17 specifically **stay allow** — a direct test against false-positive over-triggering on superficial
  keyword overlap, including a dedicated case (E17) for "a suspicious word in a string literal, no actual
  dangerous structure."
- **E15 specifically** proves a forged `parent_event_ids` claim cannot hide a real prior sensitive read from
  POL-009 (`test_cross_call_forged_parent_reference_still_caught`) — the direct test of "forged event references"
  the no-LLM follow-up specifically asked for.
- **Every episode step that reaches `block` is backed by at least one `PolicyDecision`**
  (`test_no_episode_needs_the_reasoner_to_reach_its_blocking_decisions`) — the task-episode-level proof that the
  deterministic core, not the optional reasoner, is what actually blocks anything.

**These are 19 hand-written episodes, not a statistically meaningful benchmark.** They prove the pipeline's
logic does what it is documented to do on the cases it was designed to cover; they are not evidence about
real-world attack coverage or false-positive rate at scale, and are not presented as such anywhere in this work.

## 7. Acceptance criteria (Part 9) — assessed honestly

| # | Criterion | Assessment |
|---|---|---|
| 1 | No silent loss of existing attack BLOCKs | **Met by construction.** NAVIGATOR 2.0 never runs in the production verdict path at all (shadow-only); the legacy NAVIGATOR/VAULT/EXECUTOR/CHANNEL path is untouched. Within NAVIGATOR 2.0's own shadow verdict, `POL-005` passes through every legacy specialist BLOCK unconditionally (`test_pol005_preserves_specialist_block_but_not_legacy_navigator`). |
| 2 | No unapproved weakening of existing security | **Met.** `verdict.compose()` rule 1 (docs/navigator2-architecture.md §9): any policy BLOCK — including POL-005's pass-through — wins over everything, including a contradicting reasoner recommendation. |
| 3 | Task utility is measured | **Partially met.** Measured only on the 19 synthetic episodes (§6.4); not measured against any larger or independent benchmark. |
| 4 | Multi-step security is measured | **Partially met, strengthened this pass.** E02, E03, E06A/B, E09/E09B, E14, **and now E15 specifically (cross-call correlation resilient to a forged parent reference)** are explicitly multi-step with injected tool-output content; still only on 19 synthetic episodes. |
| 5 | Every block is evidence-backed | **Met for NAVIGATOR 2.0's own verdict, now also checked at the episode level.** Every `Navigator2Verdict` carries `policy_decisions` (each with `evidence_refs`/`event_ids`) and/or `reasoner_output`; `verdict.compose()` never emits `block` without a `PolicyDecision` backing it (a reasoner-only "block" recommendation is structurally capped to `escalate` — `test_reasoner_block_without_policy_is_capped_to_escalate`), and `test_no_episode_needs_the_reasoner_to_reach_its_blocking_decisions` confirms this holds across the whole episode suite, not just in isolated unit tests. |
| 6 | Uncertainty is honest | **Met, hardened this pass.** `POL-007` and `verdict.compose()`'s final coverage check both escalate rather than allow on any `coverage="indeterminate"` evidence finding; tested directly (`test_indeterminate_evidence_never_silently_allows`, E10). A reasoner timeout, exception, or wrong-type return is now ALSO converted into the same indeterminate-coverage signal rather than being a separate, untested failure path (`test_reasoner_timeout_is_handled_not_blocking_forever`, `test_hostile_reasoner_raising_is_handled_not_crashed`). |
| 7 | No fabricated authority | **Met, hardened this pass.** `contract.py::TaskContractStore.revise()` structurally refuses any non-`TRUSTED_INSTRUCTION`-sourced change (`test_revise_from_untrusted_external_is_refused`); `reasoner.py::validate_response()` rejects any reference to an event/policy ID not actually given to the reasoner (`ReasonerFabricationError`, tested in `TestReasoner`); **and now a reasoner that returns the wrong type entirely, or one that lies in free text about new permissions, is also rejected/ignored** (`test_hostile_reasoner_returning_wrong_type_is_rejected_not_trusted`, `test_reasoner_cannot_expand_the_task_contract`). |
| 8 | Reproducibility | **Partially met.** `PolicyEngine.ENGINE_VERSION` and `TaskContract.version` are recorded on every verdict; the episode suite is deterministic (fixed fixtures, no randomness) and was re-run to confirm identical results (including a timing/overhead measurement, §0.6: ~0.06 ms/call deterministic-only, ~0.18 ms/call when the mock reasoner is invoked). No random seed is used anywhere in this prototype, so seed-recording does not apply. Dataset provenance for the episodes is "hand-authored this session," stated plainly, not claimed to be anything else. One **unrelated** pre-existing flake was newly observed and root-caused during this pass (§6.3b) — itself a reproducibility caveat about `tests/test_navigator_baseline.py`, reported rather than hidden. |
| 9 | Privacy and data minimisation | **Met for this prototype's own data.** `SessionEvent.arg_summary` stores only key names/string lengths, never raw argument values; `legacy_minister_results` stores verdict strings only, never minister reason text (which can carry redacted-but-still-sensitive detail per VAULT's own redaction discipline). |
| 10 | Independent confirmation | **Met by abstention.** The Phase A reserved split was never accessed (§5). No confirmation run against it was performed or requested — Stage 5 of `docs/navigator-pattern-disposition-review.md`'s own staged plan ("only after explicit project-owner sign-off") was correctly not reached, because stages 1-4 of real pattern migration work (§ migration-matrix.md §4) were not completed either. |

**Overall real-world-effectiveness acceptance disposition (Part 9's own 10 criteria, unchanged conclusion):
INCONCLUSIVE, not REJECTED, not PASSED.** The architecture is built, wired, and tested against its own design; it
has not been measured against anything beyond synthetic episodes it was itself designed to satisfy, which is
exactly the independence problem acceptance criterion 10 exists to guard against — this report does not claim
otherwise. **This is a separate question from the no-LLM continuation's own mandate, which §11 assesses on its
own terms.**

## 8. What NAVIGATOR 2.0 demonstrably does, versus what remains hypothesis

**Demonstrated (passing, tested, runnable today):**
- A trust boundary that structurally prevents untrusted tool output from expanding a session's authorized
  destinations/categories, with the rejection itself becoming a BLOCK-triggering fact (POL-003).
- Per-session event history with explicit, observable handling of a missing/gapped parent reference
  (`history_gap`), without that gap alone causing a false escalate/block.
- Two independent, never-collapsed integrity/confidentiality labels driving policy decisions.
- A real AST-based (not regex) single-hop decode-then-execute evidence finding, directly fixing the named gap in
  the prior evidence prototype (a decoder resolved through one level of variable indirection).
- **Nine** deterministic policies (seven from Pass 1 + POL-008/POL-009 this pass), each requiring a named
  structural fact, none a bare keyword match, each independently unit-tested for both its firing and non-firing
  conditions — and now measured to actually decide 89% of synthetic episode steps **without ever invoking the
  optional reasoner** (§0.1, §0.6).
- **Real, wired cross-call confidentiality propagation** (`core.py::_propagate_confidentiality`), with a
  deliberate, tested asymmetry against propagating integrity into the contract-revision gate (§0's architecture
  update, §5 of the architecture doc).
- **POL-009, a genuinely cross-call policy proven resilient to a forged event reference** — it reads the ledger's
  own authoritative history, not a caller's claimed parent chain, so a forged/wrong `parent_event_ids` cannot hide
  a real prior sensitive read (episode E15, directly answering the brief's "forged event reference" requirement).
- **POL-008, a literal explicit-restriction check** against `contract.denied_categories` — the most direct,
  least-inferential policy in the engine.
- A schema-and-fabrication-validated reasoner interface, runnable with zero API key/network dependency via a
  documented rule-based mock, that cannot itself grant `block` without policy backing, is now wall-clock-bounded
  against hanging, and is now proven unable to fabricate new contract permissions even when it lies in free text.
- A shadow integration verified, not merely argued, to leave the production `Decision` byte-for-byte identical,
  including against the real Coordinator with real ministers.
- A 19-episode task-level suite covering every required scenario type plus false-positive guards, a forged-
  reference case, an explicit-restriction case, and a keyword-without-structure case, 100% passing.

**Remains hypothesis / explicitly future work (named, not hidden):**
- Whether any of this reduces real-world false-escalation or misses real attacks at the scale the legacy NAVIGATOR
  was measured at (163 escalated benign commands, etc.) — **not measured**, because that would require either the
  reserved split (correctly not touched) or a large new independently-collected dataset (not built this session).
- **A real LLM-backed `TrajectoryReasonerProvider` — now explicitly a non-goal, not merely unfinished** (§0.5). Only
  the deterministic mock and null providers exist; none was wired to Anthropic/OpenAI/etc., by architectural
  decision: the brief for this pass was specifically to remove any dependency on one.
- A default-populated denylist for the 16 REWRITE patterns' tool names (POL-008 exists but requires per-session
  configuration — §migration-matrix.md §2), and policies for the remaining 12 of the 14 CROSS-CALL patterns not
  covered by POL-003/POL-009 (`docs/navigator2-migration-matrix.md §1, §4`).
- A tenant/namespace contract field, a per-user tool-usage baseline, and any COMPASS-equivalent intent-drift
  signal — none exist.
- A reply-text/output-inspection component for the 8 REPLY-TEXT patterns — no such component, and no field for it
  in any schema here.
- Any actual cutover of production traffic through NAVIGATOR 2.0 — explicitly out of scope for this task (Part 5:
  "Do not perform a live decision cutover in this task"; §0.7 above states the concrete prerequisites for one).

## 9. Is the production verdict path unchanged?

**Yes, unchanged, verified three ways:** (a) zero bytes of diff in `kavach/coordinator.py`, `kavach/speaker.py`,
`kavach/schemas.py`, `kavach/api.py`, and `kavach/ministers/navigator.py` (§4, confirmed by `git diff --stat`
returning nothing for all five); (b) `tests/test_navigator2_shadow.py`'s direct JSON-equality assertion between a
bare `Coordinator.evaluate()` call and the same call routed through `ShadowRunner`; (c) the existing test
suite's pass/xfail counts are unchanged (165 passed / 10 xfailed, before and after, §6.2).

## 10. Recommended next steps, in order

1. Pre-populate POL-008's `denied_categories` with a sensible default-deny subset of the 16 REWRITE patterns'
   tool names for higher-risk deployments (migration-matrix.md §2), starting with NAV-026/NAV-042 (the two the
   prior research specifically flagged).
2. Pick 2-3 of the remaining 12 unaddressed CROSS-CALL patterns and write their specific ledger-based policies,
   following POL-003/POL-009's pattern as the template.
3. Build a materially larger, independently-sourced task-level episode set (tens to low hundreds, not 19) before
   drawing any conclusion about real-world security/utility trade-offs — AgentDojo's own suite structure
   (`docs/navigator2-research.md §D`) is the recommended template, built fresh rather than imported wholesale.
4. Only after (3), and only as the explicitly-separate "optional, untrusted advisory" experiment the task briefs
   for both passes named but declined to implement: consider a real `TrajectoryReasonerProvider` and re-run the
   same episode suite to see whether reasoner-driven escalation changes any outcome versus the deterministic mock
   — with the reasoner's recommendation still capped exactly as `verdict.compose()` already enforces today.
5. Only after (1)-(4) and explicit project-owner sign-off: the single, one-time confirmation run against the
   Phase A reserved split, exactly as `docs/navigator-pattern-disposition-review.md`'s own Stage 5 already
   specifies — not before.

## 11. Final disposition for this continuation (no-LLM mandate)

The task brief for this continuation asked for one explicit call: **PASS, REJECTED, or INCONCLUSIVE.** Answering
precisely, because the continuation's mandate is narrower than (and distinct from) §7's real-world-effectiveness
question:

**PASS**, specifically and only for this continuation's own stated mandate — *"a locally executable,
deterministic-first security engine that tracks authorization, action history, and data provenance... no paid
API, no mandatory LLM, no trusting a second model to decide whether the first model is malicious."* Every claim
that mandate makes is demonstrated, not merely argued: zero LLM/network dependency anywhere in the package
(§0.1); the deterministic core decides 89% of synthetic steps without the reasoner and (per the episode-level
test in §6.4) **100% of steps that reach BLOCK are policy-backed, never reasoner-alone**; every named hostile/
degraded-reasoner condition (timeout, exception, wrong type, fabricated references, a lying free-text claim of
new permissions) is handled and tested, not merely assumed benign; existing specialist hard BLOCKs remain
preserved; the shadow-mode, zero-touch guarantee on the real production `Decision` path is unchanged and
re-verified; 83/83 of this work's own tests pass, and the pre-existing suite's 165/10 pass/xfail count is
unchanged.

This PASS does **not** extend to, and should not be read as overriding, §7's separate, still-**INCONCLUSIVE**
verdict on real-world detection effectiveness — the no-LLM architecture correction was a necessary precondition
for a credible security core, not a substitute for the broader evaluation against real/independent data that §7,
criterion 10, and `docs/navigator-pattern-disposition-review.md`'s own staged plan all still require before any
stronger claim would be honest.

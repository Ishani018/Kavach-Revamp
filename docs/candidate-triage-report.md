# Automated triage of the 256 candidate examples

Methodology, results and gaps for `review/heldout-candidates-batch-1/`. Machine-readable results are in `review/heldout-candidates-batch-1/candidate_triage.jsonl` (256 records) and `candidate_triage_summary.json`; the pipeline is `triage_pipeline.py` and its checker is `validate_triage.py`.

**Read this first.**
- Every classification below is an **automated heuristic proposal**, marked `automated_proposal_not_verified` in every record. None is ground truth, none replaces a source label, and none shows that any example is malicious or harmless.
- The examples are still **not held out**, are **not in the evaluation registry**, and nothing here supports a performance claim.
- No command from the dataset was executed. The Kavach MVP was not run and none of its verdicts was read, so the triage cannot be circular with the system being tested.
- I (an AI assistant) wrote the rules after reading these 256 commands and adjusted them while checking the output for obvious misfires. They are therefore informed by this very dataset, which is a limitation in itself (§9).

## 1. What the pipeline does

```
review_items.jsonl  ->  deterministic checks  ->  proposed classification  ->  MVP test-value  ->  decision
(unchanged originals)   (text/structure only)     (heuristic, with reasons)   (per minister)       (retain/exclude/review)
```

| Stage | Input | Output | Nature |
|---|---|---|---|
| 1. Deterministic checks | the transformed command, `prep_flags`, source metadata | completeness, syntax check, risk indicators, duplicate clusters, URL/address presence | deterministic, reproducible |
| 2. Proposed classification | the stage-1 evidence plus the source's own label meaning | label (`likely_malicious` / `likely_benign` / `dual_use`), confidence, rationale, unresolved concerns, label concern, relevance, dual-use risk | heuristic rules |
| 3. MVP test value | stage 1-2 plus each minister's documented scope | per-minister value for VAULT, EXECUTOR, NAVIGATOR, CHANNEL | heuristic rules |
| 4. Decision | all of the above | `retain` / `exclude` / `further_review`, tier, the rule that decided, spot-check flag | ordered, explicit rules |

**Preservation.** Each record carries `original_command_sha256` and `transformed_call_sha256`, and the source's `proposed_label_meaning` verbatim. `validate_triage.py` re-hashes the originals in `review_items.jsonl` and fails if anything differs. The triage never writes a field called a label, ground truth or verified label; its output sits under separate `proposed_classification`, `mvp_test_value` and `triage` objects.

**Blindness.** The pipeline reads the commands and source metadata only. It also reads which ATT&CK techniques each minister *cites* in its definitions (a data lookup of rule tags and corpus citations), but it never calls a minister.

## 2. Deterministic checks

| Check | How | Result across the 256 |
|---|---|---|
| Placeholders / run-time variables | `prep_flags` from the package build (`{{...}}`, Caldera `#{...}`) | 105 tldr placeholder rows, 51 Caldera variable rows |
| Missing payloads | `needs_payload_file` flag | 30 Caldera rows |
| Unsupported or non-literal syntax | documentation notation such as `[-a\|--all]`, `...`, help-only requests | 40 rows classed `template_or_fragment` (39) or `not_a_security_relevant_command` (1): 37 tldr and 3 Caldera. One Caldera fragment is also a duplicate and is excluded under X1 first, so X2 excludes 39 |
| Does it parse as shell? | `bashlex` syntax-tree parse for `sh`/`bash` tool names (parse only, nothing runs); PowerShell and cmd only get a bracket/quote balance check because no parser is available | 5 `sh`/`bash` rows do not parse; 58 of the 114 retained rows are on the path where the MVP can use its shell parser |
| Duplicates | exact match on normalized command and tool; near-duplicate at token-set Jaccard ≥ 0.9; the kept representative is the lowest source id | 8 exact and 3 near-duplicate rows (all Caldera, mostly the same command for macOS and Linux) |
| Risk indicators | 34 text-only patterns, each tagged with a threat family and a severity, in `triage_pipeline.py` (`INDICATORS`) | see §4 |
| URL / address present | URL, e-mail, IP or phone-shaped value in the command | 18 rows; flagged as a CHANNEL confound (§5) |

**Completeness** is `complete` (83), `partial` (133: placeholders, variables or payload dependencies), `template_or_fragment` (39) or `not_a_security_relevant_command` (1).

## 3. Proposed classification: how and with what confidence

The source label meaning is an input, never an answer.

- **Caldera rows (source meaning: attack-emulation action).** `likely_malicious` only if the command text itself matches a *high*-severity indicator (confidence high if two or more strong indicators, otherwise medium). Medium-severity indicators give `dual_use`. No or weak indicators give `dual_use` with low confidence **and a label concern**: the source calls it an attack-emulation action but nothing in the command alone looks harmful.
- **tldr rows (source meaning: documented legitimate usage).** No or low indicators give `likely_benign`; medium or high give `dual_use`. **A documented-legitimate row is never labelled malicious automatically**; a high-risk surface produces a label concern instead.
- **Confidence** starts from the above and is lowered by: a placeholder or variable that decides the target, a missing payload file, an assumed shell for cross-platform pages, or an unrunnable template.
- **Rationale** names the indicators matched and the completeness class. **Unresolved concerns** list what is missing or assumed.
- **Source evidence insufficient** is set when an incomplete command is only medium-severity or lower and the missing value could change what it does (for example a placeholder named `command`, `url`, `host` or `script`, or an unresolved variable in a command that is not already clearly high-severity).
- **Relevance to agent-tool security:** `high` (a high-severity behaviour), `medium` (medium behaviour, or a low indicator in a dual-use tool), `low` (nothing notable), `none` (help-only or an unrunnable fragment).
- **Dual-use risk:** how likely a context-free judgement is to be wrong (`high` when a dual-use label sits on a high-severity indicator; `medium` when on a medium one).

Totals: Caldera rows proposed as 43 `likely_malicious` and 63 `dual_use`; tldr rows as 141 `likely_benign` and 9 `dual_use`. Confidence: 107 high, 96 medium, 53 low. Label concerns on 16 rows; source evidence marked insufficient on 71.

## 4. Indicator catalogue (summary)

Severity is *what the command does*, independent of any detector.

| Family | Examples of what is matched | Severity |
|---|---|---|
| credential access | LSASS/ntds/shadow dumping, secret-shaped literals, key and credential-store paths, secret-manager queries, password or key searches, security-testing tools (hydra etc.) | high / medium / low |
| code execution | download-and-run, encoded commands, reverse shells, trusted-binary proxy execution, known offensive tool names, remote fetch | high / medium |
| persistence, privilege | cron, scheduled tasks, run keys, service changes; `setuid`, `visudo`; plain `sudo` is low | medium / low |
| destruction, evasion, injection | recursive deletes, disk wipes, log clearing, defender/firewall changes, security-policy edits, process injection, cryptomining | high / medium |
| lateral movement, egress | remote copy/exec, uploads, POSTs, staging archives | medium / low |
| discovery | host, user, process and network enumeration | low |

## 5. Which ministers can this example test meaningfully?

Per-minister values are `attack_in_scope`, `dual_use_in_scope`, `hard_negative` (a benign-looking command with a risky surface), `baseline_negative` (generic benign), `not_applicable`, or for CHANNEL always `not_testable_standalone`. An example is "meaningful for" a minister when (a) the command's behaviour falls in that minister's threat family or the source technique is in the minister's documented scope, **and** (b) the command is complete enough to be a real call.

- **VAULT:** credential-access behaviour. Scope: 8 ATT&CK parent techniques cited by its rules.
- **EXECUTOR:** execution, persistence, privilege, destruction, evasion, injection. Scope: 21 parent techniques.
- **NAVIGATOR:** discovery, evasion, movement, egress, persistence and collection behaviours, or a source technique among the 37 parents its corpus cites. A *generic* benign command is labelled `baseline_negative`: it tests unnecessary escalation, **not semantic understanding**, because a bare command carries no stated intent.
- **CHANNEL: no standalone example is treated as testing CHANNEL.** Its core mechanism needs a prior sensitive read followed by a destination call. A single command cannot test that, and the batch has no multi-step workflow. Where a command contains a URL, address or IP (18 rows; 16 of them retained), CHANNEL's generic provenance rule may react for reasons unrelated to the command's intent; that is recorded as `channel_confound`.
- **Full agent workflows** (instruction, reasoning, tool results, multi-step plans) are not represented at all.

## 6. Decision criteria

Rules are applied in this order; the first that matches decides, and the record stores the rule id and reason.

| Rule | Decision | Condition |
|---|---|---|
| X1 | exclude | duplicate of a kept representative (exact or near) |
| X2 | exclude | not a runnable, security-relevant command as written (documentation notation, ellipsis, unparseable, help-only) |
| X3 | exclude | no minister has a meaningful test and it is not a useful generic control |
| X4 | exclude | generic benign control beyond the cap of 25 (selected by a seeded hash so the choice is reproducible) |
| R1 | further review | source label and command evidence disagree (label concern) |
| R2 | further review | source evidence insufficient for a *definite* label |
| R3 | further review | high dual-use risk |
| R4 | further review | low confidence on a security-relevant command |
| K3 | retain, tier `dual_use_stress` | label is `dual_use` and a minister is meaningfully exercised: **kept with no expected verdict** (do not count as a miss or a false positive) |
| K1 | retain, tier `core_definite_label` | definite proposed label, consistent evidence, complete enough, at least one minister meaningful |
| K2 | retain, tier `baseline_control` | generic benign command kept as a noise control |

Retention is a statement about **test value**, not correctness. An excluded row is kept in the data with its reason; nothing is deleted.

## 7. Results

### 7.1 Funnel

| Decision | Rows | Of which |
|---|---:|---|
| **Retain** | **114** | core definite-label 39 · dual-use stress 50 · baseline controls 25 |
| Further review | 11 | all Caldera, all label concerns (R1) |
| Exclude | 131 | generic benign over the cap 80 (X4) · fragments/templates/help-only 39 (X2) · duplicates 11 (X1) · no test value 1 (X3) |

By source: Caldera 106 → retain 81, review 11, exclude 14. tldr 150 → retain 33, exclude 117 (80 of them are simply surplus generic commands beyond the control cap).

### 7.2 The smallest useful set

| Set | Size | Contents | How to use it |
|---|---:|---|---|
| **Definite-label core** | **39** | all Caldera, proposed `likely_malicious` (confidence 9 high, 30 medium) | candidates for tests of misses |
| **Baseline controls** | **25** | generic benign tldr commands | candidates for measuring unnecessary escalation on ordinary commands |
| Dual-use stress | 50 | 42 Caldera, 8 tldr | study how a monitor handles context-dependent commands; **no verdict expected** |

So the smallest set that supports both a miss-style and a noise-style check is **64 items** (39 + 25), and 114 if the dual-use stress items are wanted. All of them stay "unverified candidates" until a human spot-check supports them.

Within the core 39: tests EXECUTOR 39, NAVIGATOR 29, VAULT 6 (33 exercise more than one minister). Platforms: Windows 29, macOS 7, Linux 3. Tactics: defense-evasion 10, lateral-movement 7, privilege-escalation 6, impact 5, execution 5, credential-access 5, command-and-control 1.

Among all 114 retained, minister values are: VAULT attack-in-scope 6, dual-use 14; EXECUTOR attack 39, dual-use 26; NAVIGATOR attack 29, dual-use 38, generic baseline 25. Only 39 of the 114 are `complete` (no stand-in values needed); 75 are `partial` (placeholders, run-time variables or payload dependencies), so even retained rows are often approximations that a human should know about.

### 7.3 Label concerns (16 rows)

All involve a Caldera row whose command alone does not look harmful, so the source label "attack-emulation" may not carry over to an agent setting. Examples: `sleep 60` (sandbox-evasion style delay; HC1-0178, 0222, 0232), the "File Hunter" mission binary (HC1-0013, 0176, 0193, 0228), a bookmark-adding AppleScript (HC1-0129), a bare `get-wmiobject` query (HC1-0173), reading shell history (HC1-0183). 11 of them are routed to further review; the other 5 were excluded earlier in the rule order (duplicates, a fragment, or no test value). This is the clearest evidence that the Caldera label means "emulation action", not "malicious command".

### 7.4 Ambiguous or insufficient-evidence cases

71 rows have insufficient source evidence for a definite label (mostly Caldera commands with run-time variables that decide the target, or tldr commands whose placeholders stand for a path, host or command). Dual-use ones are retained in the stress tier with the concern recorded. Definite-label candidates in that state are sent to review, but after the rules were refined none remain (all 11 reviews are label concerns). Excluded fragments (39) are documentation notation, not commands.

### 7.5 Manual work

| Item | Count |
|---|---:|
| Rows a human must look at (further review) | 11 |
| Deterministic spot-check sample (28 retained, 13 excluded; seed 20261014) | 41 |
| **Total** | **52** (down from 256; no overlap) |

The spot-check exists to measure how wrong the triage is, not to relabel everything. Suggested use (an **assumption**, not a validated threshold): reviewers apply the original review sheet to these 52 rows; if they disagree with the proposed label or decision on more than about one in five spot-checked rows, the rules need revision before the rest is trusted. Disagreements should be recorded per rule id so the rule can be fixed, not patched case by case.

## 8. Coverage gaps (what this batch still does not test)

1. **CHANNEL: none.** No multi-step read-then-send sequence, and no destination-tool call.
2. **Full agent workflows: none.** No instructions, tool outputs or multi-turn context.
3. **Few definite benign examples with a risky surface.** The random tldr sample produced almost no definite-benign "hard negatives" for VAULT or EXECUTOR (zero in the retained set); the only retained benign rows are generic. That limits false-positive testing of the credential and execution rules. A **targeted** draw from security-adjacent tldr pages would be needed.
4. **VAULT is thin:** 6 attack-in-scope core items and no definite benign counterpart.
5. **Windows/PowerShell-heavy core (29 of 39).** For these the MVP has no shell parser path (only the `sh`/`bash` tool names get one), so they exercise the simpler matching and say little about the parser.
6. **Dual-use items carry no verdict by design** (50 rows), so they cannot measure misses or false positives.
7. **Independence is unresolved.** The triage does not address whether the rule authors used these sources, and Caldera's technique families overlap Kavach's catalogue at the technique level (see `docs/heldout-dataset-plan.md`).
8. **No human has verified any label.**

## 9. Limitations of the triage itself

- The indicator catalogue is regular-expression matching. It will miss obfuscated behaviour and can misfire on a word that appears in a harmless place. During development I found and fixed one such misfire (the command `tldr shred`, which names a tool but does not run it), and several gaps (for example remote-fetch and policy-change commands) by reading the Caldera rows. That tuning used the dataset's own text, so **recall of the catalogue on a fresh batch would likely be worse than on these 256**.
- "Meaningful for NAVIGATOR" is the weakest judgement here: NAVIGATOR matches text against attack-intent descriptions, and a bare command shows little intent. I treat NAVIGATOR value as scope-based, not as evidence that the MVP understands intent.
- Minister scope comes from rule tags and corpus citations, which themselves have known problems (`docs/definition-review-batch-1.md`), including revoked and nonexistent technique IDs.
- The label proposals for `dual_use` encode my judgement about severity cut-offs. A different cut-off would move rows between tiers.
- The 25-item control cap and the 0.9 near-duplicate threshold are arbitrary and documented, not tuned.
- No parser for PowerShell or `cmd` was available, so syntax defects there go undetected.

## 10. How to reproduce and check

```bash
python review/heldout-candidates-batch-1/triage_pipeline.py     # rewrites candidate_triage.jsonl and the summary
python review/heldout-candidates-batch-1/validate_triage.py      # coverage, hashes, unverified status, CHANNEL rule
python review/heldout-candidates-batch-1/validate_package.py     # the original review package is unchanged
```

Outputs are deterministic (fixed seeds, no timestamps). The pipeline imports the repo's rule tags and corpus only to read scope; it needs `bashlex` (already a project dependency) and nothing new.

## 11. What is established and what is not

| Established (measured) | Assumed or unresolved |
|---|---|
| The counts, completeness classes, duplicate clusters and parse results above | That the proposed labels are right |
| The 256 originals are unchanged (hash-checked) | That any retained example is a fair test of the MVP |
| No command was run and no MVP verdict was used | That the dataset is independent of Kavach's development |
| The triage cuts the manual load from 256 rows to 52 | That a one-in-five disagreement threshold is the right one |

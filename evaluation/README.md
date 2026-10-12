# Evaluation harness (Phase 1)

Organizes the existing labelled test data and runs it through the **real MVP** (VAULT, EXECUTOR, CHANNEL, NAVIGATOR, Speaker) in a reproducible way. It is a **smoke-test** harness. It does not measure generalization or real-world accuracy, and nothing here claims the MVP detects more or less than before.

## What is in here

| Path | What it is |
|---|---|
| `registry.json` | Hand-curated metadata per dataset: role, purpose, provenance, licence, overlap with rule development, held-out status. `"unknown"` / `null` means unknown. |
| `manifest.json` | **Generated** from the registry and the data: example counts, label breakdown, unique and duplicate counts, cross-dataset overlap, byte-identity with the recorded source. Regenerate with `python -m evaluation.build_manifest`. |
| `loaders.py`, `registry.py` | Read each dataset's native format into normalized examples. Files are never modified or relabelled. |
| `runner.py` | The evaluation runner. |
| `build_manifest.py` | Manifest builder (`--check` fails if the committed manifest is stale). |
| `datasets/<id>/…` | Byte-identical copies of source files from `main` (pinned commit in the registry). One file is renamed `benign_traces.py.txt` so it cannot be imported; its content is unchanged. |

Two inputs are used in place from `tests/data/` (they are already in the MVP tree and identical to the `main` copies): `real_benign_trajectories.json` and `attacker_cases_ds.jsonl`.

## The four roles

| Role | Meaning | Datasets today |
|---|---|---|
| `unit_test_fixture` | Data created only to exercise code paths | the inline cases in `tests/` (listed under `unit_test_suites` in the manifest) |
| `development_tuning` | Used, or documented as usable, while writing/tuning rules, corpus or thresholds, or written by the authors with knowledge of the detectors | all 10 registered datasets |
| `historical_benchmark_result` | Recorded outputs of earlier pipelines. Not input data and not evidence about the MVP | 10 manifest-only entries pointing at files on `main` |
| `held_out_evaluation` | Verified never used for rule, corpus or threshold development | **none** |

**No dataset is verified as held out**, so every run is labelled `SMOKE TEST`. To register a held-out dataset someone must (a) record who collected it and when, (b) show it was never read during rule/corpus/threshold work (for example commit dates versus rule history, and zero exact or near overlap with training pairs, corpus text and the other registered sets), and (c) have it labelled by someone other than the rule authors. Only then should its registry entry set `held_out_status` to `verified_held_out`, which is the only value that lets the runner use the label "held-out evaluation".

## Datasets that can be sent through the MVP

| id | examples | labels | note |
|---|---:|---|---|
| `kavach_pb_attack` | 519 | attack | Atomic Red Team + GTFOBins converted to tool calls |
| `kavach_pb_bfcl_benign` | 793 | benign | generic BFCL function calls |
| `benign_v0_agent_shaped` | 55 (32 unique) | benign | one banking run; calls only |
| `benign_v0_with_context` | 55 (32 unique calls, 41 unique with their user task) | benign | **same 55 cases** as the row above, plus `user_task_text`. Kept as a pair so the effect of context is visible. Never add the two together. |
| `real_benign_sessions` | 22 (16 unique) | benign | same run; sessions |
| `atriumos` | 36 | 18 attack / 18 benign | author-written |
| `openclaw_native` | 30 | 20 attack / 10 benign | hand-written |
| `benign_traces` | 50 | benign | hand-written developer sessions |

The three InjecAgent files are **counted but not sent**: turning them into tool calls needs the legacy two-step dispatch in `injecagent_runner.py` (on `main`), which this phase does not reproduce.

## Running

Prerequisites are the same as the MVP (`pip install -r requirements.txt`; the first run downloads the embedding model and builds NAVIGATOR's index).

```bash
python -m evaluation.runner --list                      # datasets, roles, runnable or not
python -m evaluation.runner                             # all runnable datasets
python -m evaluation.runner --datasets atriumos,openclaw_native
python -m evaluation.runner --context none              # send no context at all (the Phase 1 behaviour)
python -m evaluation.runner --limit 20 --json out.json  # quick check; full results as JSON
python -m evaluation.build_manifest                     # regenerate manifest.json
python -m evaluation.build_manifest --check             # is the committed manifest current?
pytest tests/test_evaluation.py                          # tests for this harness
```

## Context: what the MVP accepts and what the runner sends

The MVP takes optional context in the request's `context` object (`ToolCall.context`, also accepted through the legacy `text` form and the HTTP API). Only **CHANNEL** reads it, and only three string keys:

| Key | Used for |
|---|---|
| `user_instruction` | what the user asked for; lets CHANNEL's provenance check recognise a destination the user supplied themselves (`USER_SUPPLIED`). Read once per session, on its first call. |
| `tool_output` | the result of *that* call; lets CHANNEL recognise a later destination that first appeared in a tool result (`OUTPUT_DERIVED`). |
| `account_email` | the session's own address; lets CHANNEL treat sends to it as `SELF`. |

Non-string values are ignored without error, so the runner only ever sends strings. VAULT, EXECUTOR and NAVIGATOR ignore context entirely.

**What the runner sends (`--context auto`, the default):** exactly the fields a dataset itself carries, mapped as declared in `registry.json` (`context.source_mapping`) and implemented in `loaders.py`. Nothing is guessed, defaulted or reconstructed. A null or empty field is left out. `--context none` sends no context at all. Every report states, per label, how many examples had a user instruction, a tool output (examples and calls) and an account email, and how many had no context.

| Dataset | Context it carries and the runner sends |
|---|---|
| `real_benign_sessions` | `user_instruction` (22/22 sessions), `tool_output` (62 of 64 calls). No `account_email`. |
| `benign_v0_with_context` | `user_instruction` (55/55). No outputs, no `account_email`. |
| all other runnable datasets | none: the files hold bare tool calls. `benign_traces` has an author-written `intent` per session; it is **not** treated as a user instruction. |

No registered dataset has `account_email`, so CHANNEL's `SELF` path is never exercised by this data.

### How missing context affects interpretation

- **Where context is missing, CHANNEL cannot recognise a legitimate destination.** Its provenance rule escalates a call whose email/URL/IBAN/phone-shaped value is not found in the instruction or a prior output, and a taint BLOCK is only overridden when the destination is `SELF` or `USER_SUPPLIED`. So results on context-free datasets can contain ESCALATEs (and, after a sensitive read, BLOCKs) that real use with context might not produce.
- **The effect is visible on the same data.** One measured example (single runs, development data, not a performance claim): the 55 `benign_v0` cases give 34 ESCALATE / 21 ALLOW with no context and 17 ESCALATE / 38 ALLOW when each is given its user task text; the 22 benign sessions go from 20 to 12 ESCALATE sessions with instructions and tool outputs. The calls are identical; only the context differs. Results run with `--context none` and results run with context are **not comparable**, and neither should be compared with a dataset that carries no context.
- **Context does not make a dataset trustworthy.** It reduces one source of unrealistic input. The overlap with rule development, the labels, the small size and the single-model, single-suite origin of these sets are unchanged, so every run is still a smoke test.
- **Other ministers are unaffected.** An ESCALATE decided by NAVIGATOR or a BLOCK decided by VAULT/EXECUTOR does not depend on context; the `decided by` line shows which minister drove each non-ALLOW verdict.
- **Not all context is representable.** Attack datasets here carry no instruction or outputs, so attack-side and benign-side results differ in how much context they had. Compare `context sent` lines before comparing the two sides.

## How results are reported

- Per dataset and per label (`attack` / `benign`): **samples**, **unique examples**, and **BLOCK / ESCALATE / ALLOW / ERROR counts**, once over all samples and once over unique examples.
- ESCALATE is never counted as ALLOW and never folded into "detected". There is no recall, false-positive-rate or accuracy headline; compute one yourself only with the caveats in mind.
- Per label, the report also states **context sent** (see above). The JSON has the same counts under `labels.<label>.context`, plus `context_mode` and `context_fields_available_in_dataset`.
- "Unique examples" counts distinct (calls, context) pairs when context is sent, so two identical calls with different user instructions are different examples.
- Each example runs in its own session. Multi-call examples (sessions) send their calls in order in one session, and the example's verdict is the **most severe** verdict across its calls.
- `ERROR` (malformed input, failed request) is its own category and is never counted as ALLOW.
- Duplicates are kept and reported (`inconsistent_duplicate_verdicts` would show if identical examples got different verdicts).
- Runs are deterministic: the JSON output has no timestamps, and the same code and data produce the same counts.

## Limitations

- Labels are the datasets' own (or implied by their format); this harness did not verify them.
- Only two datasets carry any context, and none carries `account_email`; most results are therefore for context-free input (see "How missing context affects interpretation").
- Source URLs and licences are recorded only where the repository itself records them; otherwise they are `unknown`. Sources on `main` were copied at the commit pinned in `registry.json`.
- Historical results (`hist_*` entries) are not re-run and say nothing about the MVP.

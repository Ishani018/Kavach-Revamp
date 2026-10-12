# Phase A: candidate data from RedCode, tldr-pages and SWE-agent trajectories

What was prepared, what is usable, what is not, and what is still missing. Everything is in `review/phase-a-candidates/`.

**Status of the data.** Candidate and unreviewed. **Not held out. Not in the evaluation registry.** Nothing here supports a detection, precision, recall, false-positive or accuracy claim. No example was executed; the Kavach MVP was not run to build it (the only parsing is `bashlex`, which builds a syntax tree). Labels are each source's own meaning, marked unreviewed. No detection logic, existing dataset, Supabase data or dependency was changed, and CredData was not downloaded.

## 1. What was prepared

| Source (pinned) | Licence | Prepared | Original label meaning kept (unreviewed) |
|---|---|---:|---|
| RedCode-Exec bash, `AI-secure/RedCode` @ `c84b6db8…` | MIT | **600** scripts, 20 risk scenarios × 30 | "risky by scenario design" |
| tldr-pages @ `3b04259a…` | CC BY 4.0 | **200** examples, stratified and seeded from a **1,899-command** pool from 405 security-adjacent pages | "documented legitimate usage" |
| `nebius/SWE-agent-trajectories` @ `68195a14…` | CC BY 4.0 | **786** single-line shell commands from a fixed 100-trajectory sample (**142 distinct**) | "agent-generated, assumed benign" |

Every item keeps: source file and git blob (or dataset row), pinned version, licence and licence URL, permalink, the `original` text verbatim (all RedCode fields; the tldr command and its description; the SWE command plus the SHA-256 of the full agent turn), the derived tool call and the rule that produced it, deterministic flags, duplicate and overlap information, and a diagnosis/reserved split. Automated text-pattern hints are in a **separate file** (`phase_a_hints.jsonl`) so they cannot be mistaken for labels.

## 2. How it was converted

| Source | Rule |
|---|---|
| RedCode | tool `bash`, arguments `{"command": <Code field, unchanged>}`. The Code field is a whole script (570 of 600 are multi-line with a shebang). |
| tldr | tool `bash`, arguments `{"command": <example with each {{placeholder}} replaced by its inner text>}`. Windows pages excluded (shell ambiguous). Documentation notation (`[-a\|--all]`, `...`) and bashlex-unparseable examples are **left out of the sample but listed** (623 of the pool, `tldr_excluded_from_sample.jsonl`). |
| SWE-agent | the last fenced block of each agent turn; SWE-agent's own editing built-ins (1,731 commands) and one multi-line command are listed in `swe_agent_excluded.jsonl`, not used. |

Sampling choices are explicit and stored in the manifest: the tldr page allow-list per family (credentials and keys, network transfer, reconnaissance, privilege and execution, destructive storage, logging and defence) with quotas 40/40/30/45/25/20 and seed 20261015; SWE-agent windows of 10 consecutive trajectories at offsets 0, 8,000, … 72,000 (build stops if the dataset revision is not the pinned one).

## 3. Flags and uncertainty (deterministic; nothing was deleted)

| Source | Flag | Items |
|---|---|---:|
| RedCode | multi-line / has shebang | 570 / 570 |
| RedCode | depends on filesystem state (absolute paths) / on a local service | 243 / 62 |
| RedCode | `bashlex_cannot_parse` | 218 |
| RedCode | duplicate within the source (2 exact, 119 near, Jaccard ≥ 0.9) | 121 |
| RedCode | overlap with data we hold (exact or near ≥ 0.8) | 0 |
| tldr | placeholders replaced / shell unspecified | 146 / 146 |
| tldr | duplicate within the sample / overlap with data we hold (exact) | 2 / 3 |
| SWE-agent | duplicate within the source (545 exact, 102 near) | 647 |
| SWE-agent | `bashlex_cannot_parse` / `malformed_builtin_like` (for example `open.dvc/config` typed without a space) / contains a URL / depends on the working directory | 106 / 40 / 12 / 9 |

`bashlex_cannot_parse` for RedCode is a **tool limitation**, not evidence of invalid bash: the errors are valid constructs bashlex does not support (arrays, `case` patterns, arithmetic expansion). Treat it as "no shell syntax tree available".

**Uncertain labels** (hints, not decisions): 388 of 600 RedCode scripts matched no risk indicator from the batch-1 pattern catalogue (it was written for commands, not multi-line scripts, so its blind spots here are large: six whole scenarios, 12, 15, 18, 21, 22 and 25, matched nothing). tldr: 11 examples have a high-risk surface although documented as legitimate. SWE-agent: 11 have a medium or high risk surface (mostly `wget`/`curl` fetches).

## 4. What is usable now

| Use | Source | Caveat |
|---|---|---|
| Attack-side commands for EXECUTOR and NAVIGATOR | RedCode, **after** removing duplicates (479 distinct clusters) | label means "risky scenario", severity varies; scenario names were not found in the files read (only the numeric index); no benign half |
| Risky-looking benign lookalikes | tldr (200), minus 2 duplicates and 3 overlaps | documented usage, not agent traffic; 146 use placeholder text |
| Realistic benign agent commands | SWE-agent (142 distinct) | **assumed** benign, never reviewed; 7 distinct entries are agent errors (python code typed as a command, malformed built-ins) |

## 5. What is not usable or still missing

1. **SWE-agent diversity is low.** 100 trajectories give only 142 distinct single-line commands, because agents repeat `ls`, `python`, `rm`. A false-escalation estimate needs far more distinct benign commands: more windows of the dataset, or a different source.
2. **RedCode has no benign counterpart,** and its scripts are long; they tell little about short commands.
3. **VAULT and CHANNEL are not covered** by Phase A (CredData and the harness are later phases).
4. **No labels have been reviewed.** The triage pipeline and spot-check design from batch 1 apply here too but have not been run on these items.
5. **Independence is unresolved:** nothing in our repo mentions these sources and no duplicates were found, but only the rule authors can confirm they were not consulted.
6. **Windows and PowerShell are not covered** on the benign side (tldr Windows pages were excluded).

## 6. The split protects against tuning on test data

Each item has `split` = `diagnosis` (60%) or `reserved` (40%), assigned by hash, with duplicates following their representative. Diagnosis and tuning work may read only `diagnosis`; `reserved` is for confirming a change. See `docs/navigator-escalation-diagnosis.md` for the first use. The split does not make the data independent of Kavach's development.

## 7. Validation (all pass)

- `validate_phase_a.py`: 1,586 items (600 + 200 + 786); provenance complete; each `command` reproduces from `original` by the stated rule; calls and original hashes match; labels all marked unreviewed; no ground-truth-like field; duplicate flags consistent and each duplicate shares its representative's split; file checksums match the manifest.
- A second build from the same pinned sources is **byte-identical** (deterministic).
- Fidelity checks of RedCode and tldr against the sources are built into the build (the checkout must be at the pinned commit, and the SWE dataset at the pinned revision).

## 8. Reproduce

See `review/phase-a-candidates/README.md`.

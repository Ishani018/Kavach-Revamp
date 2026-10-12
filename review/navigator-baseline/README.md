# NAVIGATOR frozen baseline and regression guard

A snapshot of NAVIGATOR **as it is today**, so a future fix can be compared against exactly what was tested. It is not a
specification: it records current behaviour, including the problems described in `docs/navigator-escalation-diagnosis.md`.
Nothing here changes NAVIGATOR. It is **outside the active evaluation registry**, and the diagnosis data it uses is **not held out**
(it has been inspected). The Phase A **reserved split was not read for any result**: the freezer discards reserved rows unread
(the Phase A files hold both splits, so it has to open them once), and replaying the baseline needs no Phase A file at all.

| File | Contents |
|---|---|
| `navigator_baseline.json` | what was tested: git head and SHA-256 of the defining files, library and model versions (model weights hash), thresholds and constants, wire format, corpus and index fingerprints, input hashes, hashes of the diagnostic results, summary |
| `navigator_baseline_items.jsonl` | 2,104 rows: the call text and what the unmodified minister returned (verdict, score, matched pattern), the step-by-step replica, and the VAULT/EXECUTOR verdicts for the same call. Sets: 206 diagnosis benign, 277 diagnosis attack, 793 BFCL benign and 519 Kavach-PB attack (development, not independent), 9 wrapper probes, 300 pattern-document canaries |
| `navigator_baseline_docs.jsonl` | the 300 indexed documents with hashes |
| `freeze_baseline.py` | creates the three files above |
| `regression_guard.py` | compares a baseline with a candidate run and lists lost BLOCKs, lost detections, lost pattern canaries, changes to other ministers, and the change in benign escalation |
| `verify_baseline.py` | replays the frozen inputs through the current NAVIGATOR and runs the guard |

## Tests (in `tests/`)
- `test_navigator_baseline.py`, marker `current_behaviour`: **A.** the baseline is intact and today's NAVIGATOR reproduces it (a pass means "unchanged", not "good"); facts about the frozen data that document the issues; **B.** unit tests of the guard on synthetic data.
- `test_navigator_desired.py`, marker `desired_behaviour`: what NAVIGATOR *should* do. They are **strict xfails** and fail today (ten of them): empty shell calls escalate; the wrapper inflates benign scores; the chosen document depends on BM25 tie order; one pattern document does not retrieve its own pattern; benign escalation is not lower than baseline; attack scripts do not outscore benign commands; two generic patterns dominate benign escalations. `pytest tests/test_navigator_desired.py --runxfail` shows the real failures. When a fix makes one pass, strict mode flags it so the marker and the baseline get reviewed.

## Using it for a change
1. Make one change. 2. `python verify_baseline.py` to see precisely what moved. 3. The guard's hard rules must hold (no lost BLOCK, no attack that was ESCALATE/BLOCK now ALLOW, no lost pattern canary, VAULT/EXECUTOR unchanged). 4. Confirm any benefit on the **reserved** split or independent data, once. 5. Freeze a NEW baseline id; never edit this one. `test_files_that_define_navigator_are_unchanged_since_the_freeze` is expected to fail the moment NAVIGATOR is deliberately changed: that is the prompt to do steps 2-5.

Exact-number tests skip, with a stated reason, if the library or model versions differ from the frozen ones.

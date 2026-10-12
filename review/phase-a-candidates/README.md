# Phase A candidate data

**Status: candidate, unreviewed. Not held out. Not in the evaluation registry.** Nothing here may be used for a detection,
precision, recall, false-positive or accuracy claim. No example was executed and the Kavach MVP was not run to prepare it.

| File | Contents |
|---|---|
| `redcode_bash_items.jsonl` | all 600 RedCode-Exec bash scripts (20 risk scenarios) |
| `tldr_security_items.jsonl` | 200 security-adjacent tldr-pages examples (stratified, seeded sample of a 1,899-command pool) |
| `swe_agent_items.jsonl` | 786 single-line shell commands from a fixed 100-trajectory sample (142 distinct) |
| `phase_a_hints.jsonl` | **automated text-pattern hints**, kept apart from the items on purpose; not labels |
| `tldr_excluded_from_sample.jsonl`, `swe_agent_excluded.jsonl` | what was left out and why (nothing is silently dropped) |
| `phase_a_manifest.json` | versions, licences, configuration, counts, flag statistics, checksums |
| `build_phase_a.py`, `validate_phase_a.py` | reproducible conversion and validation |
| `diagnose_navigator.py`, `navigator_diagnosis_results.json`, `navigator_diagnosis_items.jsonl` | the NAVIGATOR workstream (see `docs/navigator-escalation-diagnosis.md`) |
| `NOTICE.md` | attribution and licences |

Each item keeps its source reference, pinned version, licence, `original` text and the source's own label meaning
(marked unreviewed), plus the derived tool call and the rule that produced it, deterministic `flags`, duplicate and overlap
information, and a `split`.

## The diagnosis / reserved split
Every item is assigned by hash to `diagnosis` (60%) or `reserved` (40%). **Duplicates always follow their representative**, so
near-identical commands cannot straddle the split. Anything that investigates or tunes (for example the NAVIGATOR work)
may read only `diagnosis`. `reserved` exists so that a change can later be confirmed on examples nobody looked at. The
split protects against tuning on test data; it does not make the data independent of Kavach's development.

## Reproduce
```bash
git clone https://github.com/AI-secure/RedCode && git -C RedCode checkout c84b6db88fd8bd258e29f12e692ccfd4287a454d
git clone --filter=blob:none --sparse https://github.com/tldr-pages/tldr && git -C tldr checkout 3b04259a58d0bfecaa31c3179b3d349a81ef7893 && git -C tldr sparse-checkout set pages/common pages/linux pages/osx
python build_phase_a.py --redcode RedCode --tldr tldr [--extra-reference <Kavach main checkout>]
python validate_phase_a.py
```
The SWE-agent sample is fetched from the Hugging Face datasets server at fixed offsets and the build stops if the dataset
revision is not the pinned one. Without `--extra-reference` the overlap check uses only data in this repository, so overlap
counts can differ slightly from the recorded manifest.

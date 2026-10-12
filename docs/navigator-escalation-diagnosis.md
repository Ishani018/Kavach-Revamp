# NAVIGATOR escalation diagnosis and improvement plan

A diagnosis of why NAVIGATOR returns ESCALATE for so many ordinary benign commands, and a plan to fix it safely. **No detection logic, corpus, threshold or dataset was changed.** The analysis is `review/phase-a-candidates/diagnose_navigator.py`; results are in `navigator_diagnosis_results.json` and `navigator_diagnosis_items.jsonl` (per-item scores).

**Data discipline.**
- Only Phase A items with `split == "diagnosis"` were read (206 distinct benign commands from tldr-pages and SWE-agent, and 277 distinct RedCode scripts). The `reserved` split was never loaded, so it can still confirm a future change.
- Two existing development sets (BFCL benign 793, Kavach-PB attack 519) are used as extra *descriptive* material. They overlap with rule development and are **not independent evidence**.
- Everything below describes where scores come from. The "what-if" table computes alternative scorings arithmetically on the same examples, so it is **exploratory and must not be quoted as an improvement**. Nothing was selected or tuned from it.
- Earlier exploratory runs that used a different tldr and SWE-agent sample (the pilots behind the 75-93% figure) are superseded by this analysis.

## 1. Summary

1. **The ESCALATE band sits inside the embedding model's noise.** NAVIGATOR returns BGE cosine similarity (times a lexical factor of at most 1) to the best of 300 attack-description documents, and ESCALATE starts at 0.50. For ordinary benign commands the *best* similarity over 300 documents has a median of **0.60** (10th percentile 0.54), and two unrelated benign commands have a median cosine of 0.44 (90th percentile 0.54). The threshold is below the typical maximum noise, so most inputs are ESCALATE unless the lexical factor pulls them under.
2. **The tool-call wrapper alone scores as ESCALATE.** An empty call `tool:bash args:{"command": ""}` scores **0.653**, `sh` 0.638 and `powershell` 0.681, all above 0.50, before any command is present. A non-shell call with no command (`tool:read_file args:{}`) scores 0.40.
3. **Two generic documents win most escalations.** Of 163 escalated benign commands, the winning pattern is NAV-093 (70) or NAV-073 (34); five patterns account for 79% and only 23 of the 100 patterns ever win. The winners are mostly the "surface" (L3) text (127 of 163). NAV-093 L3 is "Shell command lines containing # followed by additional commands…" and NAV-073 L2 is "Agent assembling a command from base64… fragments"; both describe shell commands in general terms.
4. **BM25 rewards the wrapper's JSON key.** The word "command" (the JSON key in every shell call) occurs in only 10 of the 300 documents, so it carries high weight and points to those few documents. In 104 of the 163 escalations the query shared the token `command` with the winning document. The lexical factor therefore adds support for the *wrapper*, not for attack vocabulary.
5. **On this data NAVIGATOR does not separate attacks from benign.** Using the score alone, the chance that a random RedCode script scores higher than a random benign command is **0.41** (0.5 means no separation; below 0.5 means benign commands tend to score slightly higher). On the development sets the same measure is 0.93, but that is a dataset-shape effect: Kavach-PB is shell commands and BFCL is generic function calls, so the score is mostly telling "shell command" from "API call".
6. **Consequence for the product.** The Speaker returns ESCALATE if any minister does, so NAVIGATOR's noise decides most benign verdicts (in the earlier full-MVP runs NAVIGATOR was the deciding minister on most non-ALLOW benign results).

## 2. How the score is built (verified)

`NavigatorMinister.check()` → `retrieval.run_minister_hybrid()`:

1. Embed the wire text `tool:NAME args:{json}` with `BAAI/bge-base-en-v1.5`, with the instruction prefix "Represent this sentence for searching relevant passages: ".
2. Dense search: top 10 of the 300 documents by cosine.
3. BM25 over all 300 documents, using a tokenizer that drops `tool` and `args` only.
4. Reciprocal-rank fusion picks one candidate from the dense top 10 (dense rank plus BM25 rank).
5. `score = cosine(selected) × lexical_gate`, where `lexical_gate = 0.65 + 0.35 × (BM25 of selected ÷ best BM25 for this query)` (0.65 if there is no lexical overlap at all).
6. Verdict: ≥ 0.70 BLOCK, ≥ 0.50 ESCALATE, else ALLOW.

My step-by-step re-computation matches the real minister on **300 of 300** checked items (an earlier version differed on 63 because it ranked BM25 ties differently; the fix is the exact tie order the code uses).

## 3. Contribution of each part

| Part | Evidence | Reading |
|---|---|---|
| **BGE dense similarity** | Selected-document cosine for escalated benign commands: median 0.628, 10th-90th percentile 0.608-0.659. With the lexical factor switched off (what-if), **all 206** benign commands reach 0.50. | The dense layer alone cannot separate; it needs a threshold above the noise band, or a score relative to it. |
| **Wrapper text** | Empty-call scores above; removing the `tool:`/`args:` wrapper (what-if) cuts benign ESCALATE from 79% to 40% on the diagnosis data. | A large part of the benign score is the wrapper. |
| **BM25 + gate** | Gate median 0.93 for escalated benign; the lexical overlap is mostly the token `command`. The floor (0.65) applies when nothing overlaps (82% of selections in BFCL, 8-26% in the shell sets). | The gate mostly *removes* score where there is no overlap, which is why generic API calls (BFCL) escape and shell commands do not. |
| **BM25 tie-breaking** | Among documents with no overlap the BM25 rank is by array position, so RRF can prefer a document purely by position. Selection changes under a different tie order for 24% of tldr, 7% of RedCode and 53% of BFCL items. | An arbitrary component in the choice of document, and a reproducibility risk. |
| **Thresholds** | 0.50/0.70 are in raw cosine units. On the diagnosis data benign scores: share ≥ 0.50 / 0.55 / 0.60 / 0.65 / 0.70 = tldr 72% / 61% / 48% / 13% / 2%, SWE 90% / 49% / 22% / 0% / 0%. RedCode: 53% / 39% / 27% / 10% / 5%. | BLOCK is almost unreachable; the ESCALATE band is where benign and attack overlap completely. |
| **The 100 patterns / 300 documents** | 23 patterns ever win a benign escalation; NAV-093 (70) and NAV-073 (34) dominate; top documents by frequency are NAV-093 L3 (65), NAV-073 L2 (22), NAV-042 L3 (21, an `authorized_keys` line), NAV-026 L3 (11). | Generic, high-"surface-area" documents act as hubs. The corpus was built from attack descriptions only, with no benign negatives to calibrate against. |

Other what-ifs on the same data (exploratory): moving the gate floor to 0.5 or 0.8 moves benign and attack escalation together (66%/40% and 96%/95%), so it shifts the operating point without improving separation; restricting to only L1 or only L2 documents is worse for benign (98% and 94%); dropping the BGE instruction prefix changes both (71% benign, 68% attack).

## 4. What is *not* established

- Whether any fix preserves detection: the attack side here is RedCode (risky-by-scenario, severity varies, no benign scripts) and a development set.
- RedCode scripts are long and multi-line, so embedding length may affect scores independently of intent. Not isolated yet.
- Whether the escalation pattern is the same for tools other than shell, for Windows commands, or in real sessions with instructions and outputs.
- Which attack patterns are truly detected by similarity versus by luck of wording. A per-pattern view needs matched attack examples (§5).
- All numbers are single runs on small, partly duplicated sets (the 206 benign are distinct commands but come from 2 sources).

## 5. Data needed to diagnose reliably

| Need | Why | Candidate source |
|---|---|---|
| **Many more distinct benign shell commands** (target a few thousand) | 142 distinct SWE-agent commands is too few; need coverage of editors, build tools, package managers, VCS, containers, cloud CLIs, PowerShell | more windows of the SWE-agent dataset; targeted tldr; public terminal-session datasets after a licence check |
| **Benign non-shell tool calls in the same JSON shape** | the current benign evidence is shell-heavy or generic API calls, so shape and intent are confounded | BFCL-style calls with realistic agent tools; PrivacyLens-style tool calls |
| **Matched pairs** (benign vs malicious variants sharing the same tool and wrapper) | isolates intent from wrapper and vocabulary; `curl` download vs `curl | sh`, `rm tmpfile` vs `rm -rf /` | construct from tldr + RedCode/Caldera with documented, reviewed pairing |
| **Benign multi-line scripts** | RedCode has no benign half, so script-length effects cannot be separated | open-source script collections with a compatible licence |
| **Attack examples that paraphrase the 100 pattern intents** | a per-pattern recall view; today attack data is mostly commands, not intent | pattern-targeted examples written independently of the corpus authors |
| **Non-shell attacks** (exfiltration via APIs, injected instructions in arguments) | NAVIGATOR's corpus covers these OWASP-style items but we have no test data for them | AgentHarm/ASB with a harness (Phase C) |
| **A calibration set kept apart from evaluation** | to set any threshold without grading on the same examples | split new benign data three ways: calibration / diagnosis / reserved |

## 6. A safe, measurable improvement plan

**Principles.** One change at a time. Fix the metrics and the acceptance rule *before* looking at results. Calibrate on one split, report on another, and use the reserved split once per candidate. Never report numbers from a tuning split as evidence.

**Data roles.**

| Role | Used for | Allowed to look at | Current content |
|---|---|---|---|
| Diagnosis (done here) | understand causes | yes | Phase A `diagnosis` split |
| Calibration | choose thresholds or parameters | yes, only to choose | to be built from the new benign data in §5 |
| Reserved | confirm a chosen change, once | **no** until the change is frozen | Phase A `reserved` split (717 items incl. duplicates) |
| Independent | the only data that can support external claims | no | not yet established (see `docs/test-suite-roadmap.md`) |

**Metrics (fixed in advance).** For benign: ESCALATE rate and BLOCK rate with 95% intervals on *distinct* examples. For attacks: catch rate (ESCALATE-or-BLOCK) and BLOCK rate overall and **per pattern/scenario**, plus score separation (the AUC above) and attack catch at a fixed benign escalation rate. Always report ESCALATE separately from BLOCK.

**Candidate changes, in the order I would test them** (each is a hypothesis, not a recommendation to adopt):

| # | Hypothesis | What changes | What it must not break |
|---|---|---|---|
| 1 | The wrapper adds a constant offset | score the argument content, or subtract a per-tool wrapper baseline | attacks that depend on the tool name (for example a `powershell` call) |
| 2 | The thresholds are inside the noise band | express the grey threshold relative to the benign distribution of the best similarity (a percentile from the calibration set), not as a fixed 0.50 | BLOCK-level attacks (those already ≥ 0.70) |
| 3 | BM25 rewards structural tokens | exclude wrapper and generic tokens from the lexical score, or weight tokens so that "command" cannot select a document; make tie-breaking deterministic and meaningful | patterns whose recall relies on literal tokens |
| 4 | Hub documents (NAV-093 L3, NAV-073 L2, NAV-042 L3, NAV-026 L3) are too generic | review and tighten those documents, or require the lexical gate to agree | each hub pattern's own true-positive examples |
| 5 | Level mix matters | compare L3-only vs L1+L2+L3 on calibration data | per-pattern recall |
| 6 | Benign negatives are missing from the corpus | add a benign "anti-document" set and score the margin between the best attack and best benign match | missed attacks near the benign set |

**Regression tests that must exist before any change** (they can be written now):
1. **Frozen baseline.** Record the current per-item score, verdict and selected document for every example in the development, diagnosis and reserved sets (the `navigator_diagnosis_items.jsonl` format), under a version label. A change must report differences against it.
2. **No new misses.** Every attack item that the baseline ESCALATEs or BLOCKs on the development attack sets, and every pattern's own L3/L2/L1 text, must keep at least the same verdict, unless a human has reviewed and accepted the item. A *reduction* in BLOCKs is a failure even if escalations fall.
3. **Per-pattern canaries.** For each of the 100 patterns, its own documents and at least one independent attack example must still retrieve that pattern with a score above the grey line.
4. **Matched-pair test.** For each reviewed benign/malicious pair, the malicious member must score strictly higher than its benign twin.
5. **Determinism.** The same input gives the same score and document on repeated runs, independent of ordering of ties.
6. **Separation guard.** The score separation (AUC) on the calibration and reserved sets must not fall below the baseline value.
7. **Cross-minister isolation.** VAULT, EXECUTOR and CHANNEL verdicts are unchanged for every item.
8. **Latency.** NAVIGATOR's per-call time stays within the current budget.

**Acceptance rule (to be fixed before testing; proposal).** A change is adopted only if, on the reserved split, benign ESCALATE falls by a pre-stated margin with the interval excluding "no change", **and** tests 2-4 and 6-7 pass, **and** no per-pattern canary regresses. If a change helps only on the calibration split it is rejected.

**What not to do:** tune on the reserved split; present development-set results (where the AUC is 0.93 because of dataset shape) as evidence; fix the threshold from the what-if table.

## 7. Next steps

1. Freeze the baseline (regression test 1) and write tests 2-5, 7 and 8; they need no new data.
2. Build the §5 benign data (distinct commands, non-shell calls, matched pairs, benign scripts) and split it into calibration/diagnosis/reserved.
3. Pre-register the metrics and the acceptance rule.
4. Test hypotheses 1-3 first (they change scoring, not the corpus), then 4-6.
5. Ask the corpus authors which patterns are meant to be generic (NAV-093, NAV-073) and whether benign negatives were ever considered.
6. Only then consider changing the MVP; until then the escalation noise should be reported alongside any NAVIGATOR result.

## 8. Reproduce

```bash
python review/phase-a-candidates/diagnose_navigator.py --chroma-path <scratch chroma dir>
```
It loads the MVP's own NAVIGATOR (unchanged) and writes `navigator_diagnosis_results.json` and `navigator_diagnosis_items.jsonl`. It takes about 6 minutes on a laptop CPU.

## 9. Status: baseline frozen and regression tests written

Following section 7 step 1, the baseline is frozen in `review/navigator-baseline/` (see its README) and tests exist in `tests/test_navigator_baseline.py` (current behaviour and guard mechanism) and `tests/test_navigator_desired.py` (ten strict-xfail tests that specify the desired behaviour and fail today). NAVIGATOR itself is unchanged. Open items: matched benign/malicious pairs (no reviewed pairs exist yet, so regression test 4 is not written), a calibration split, the pre-registered acceptance margin, and the new benign data in section 5.

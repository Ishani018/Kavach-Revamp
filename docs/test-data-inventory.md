# Test-data inventory and evaluation-reliability audit

Inventory of every test, fixture, dataset, benchmark and recorded result I could find, judged against the question: *what can this data actually tell us about the Kavach MVP?* Read-only audit. No detection code, dataset, test, Supabase record, dependency or existing report was changed; nothing was committed.

**Labels used.** **Measured** = I computed or executed it and can reproduce it. **Documented** = stated in a repo file I read, not independently re-derived. **Estimate** = my own judgement or heuristic. **Unresolved** = could not be established.

**Where the data lives.** The MVP branch (`mvp-core`) carries only 9 test files and two small fixtures. Nearly all datasets and recorded results sit on `main` (commit 3eb7b7e, 865 files), which I extracted into a scratch directory and read there. Paths below are relative to the repo root; "on main" means the file exists only on `main`, not in the MVP tree. The AgentDojo run logs that several results rely on (a sparse clone of the AgentDojo repository, 111 MB) are **not in the repo at all** (git-ignored; see `.gitignore` on main), so those results cannot be re-derived from what is committed.

## 0. Summary of findings

1. **The MVP's own tests are unit tests, not evaluation.** 59 pytest tests plus two script-style suites (37 checks). Only 2 data files back them (32 attack cases, 22 benign sessions). Nothing in the MVP tree can support a precision, recall or false-positive claim.
2. **The large benchmarks on `main` were produced by an older pipeline** (cosine triage, COMPASS, trajectory, router, LLM tiebreaker). 650 of 2,108 decisions in the most recent InjecAgent run were decided by `TRAJECTORY`, a component the MVP removed. Those results do not describe the MVP.
3. **The headline "544/544 strict recall, 0% FPR" rests on 32 distinct attacks.** 544 = 32 data-stealing attacker cases × 17 benign user cases. The matching benign side (1,054 cases) contains only the 17 distinct user actions. **Measured** (`benchmarks/data/*.jsonl`).
4. **The Kavach-PB benchmark is not held out from rule authoring.** Its 519 attack cases are the Atomic Red Team and GTFOBins "capped" training pairs (519/519 identical call strings), and the repo's own README says the VAULT/EXECUTOR rules were written by mining detection misses on those same corpora. **Measured** overlap; circularity **Documented**.
5. **Benign evidence is thin and concentrated.** The agent-shaped benign set is 55 rows but only 32 unique calls, all from one local 7B model on a banking suite. Zero benign coverage exists for other AgentDojo suites (**Documented** in `VALIDATION_PROTOCOL.md`).
6. **Source URLs and licences are largely undocumented.** Only AgentHarm has a recorded URL, licence note and fetch date. InjecAgent, AgentDojo, Atomic Red Team, GTFOBins, BFCL: no URL or licence recorded in the files I read.
7. **Replaying the existing labelled sets through the MVP (new, measured, §8) shows large escalation on benign traffic** (e.g. 20 of 22 benign banking sessions escalate) and detection gaps on the author-written generalization audit (0 of 9 VAULT and NAVIGATOR attacks flagged). This is a smoke test on non-independent data, not an evaluation.
8. **Most active rules have no labelled attack example.** Across 561 labelled attack strings from three sets, 44 of 63 VAULT and 32 of 64 EXECUTOR rules match none of them. **Measured** (§6).

---

## 1. Reconciling "127 rules" with "294 executed records"

`docs/runtime-rule-coverage.md` says both "127 runtime rules" and "294 catalogue records classified as executed". They count different things, and the figures reconcile exactly. **Measured.**

| Component of the 294 | Count | Is it one of the "127"? |
|---|---:|---|
| VAULT regex rules (`VAULT_PATTERNS`) | 63 | **yes** |
| EXECUTOR regex rules (`EXECUTOR_DENYLIST`) | 64 | **yes** |
| VAULT parser tables (`_CRED_PATH_STRONG`, `_CRED_EXT`, `_CRED_GLOB_RE`) | 3 | no |
| EXECUTOR parser tables (fetch-to-disk regexes, AST call tables) | 11 | no |
| CHANNEL definitions (32 source tools, 10 destination tools, 4 source rules, 6 behaviour constants) | 52 | no |
| NAVIGATOR corpus patterns | 100 | no |
| NAVIGATOR MVP thresholds | 1 | no |
| **Total** | **294** | 127 of them |

63 + 64 + 3 + 11 + 52 + 100 + 1 = **294**. Per minister: VAULT 66, EXECUTOR 75, CHANNEL 52, NAVIGATOR 101.

- "127" counts only the VAULT and EXECUTOR **regex rules**. It is the number to quote when asking "how many deterministic regexes run".
- "294" counts every **catalogue record whose definition appears verbatim in the running code**, of any type. "Executed" there means *the definition is loaded by the MVP*, not *it has fired*. The word was ambiguous in the earlier report; "loaded" is more accurate.
- Neither number is a count of detectors. NAVIGATOR's 100 records become 300 embedded documents; CHANNEL's 52 records feed two stateful mechanisms.

---

## 2. Inventory

### 2.1 In the MVP tree (`mvp-core`)

| Source | Purpose | Records | Used by / minister | Data origin |
|---|---|---:|---|---|
| `tests/test_speaker.py` | Speaker policy | 17 tests | Speaker | hand-written synthetic |
| `tests/test_coordinator.py` | Coordinator, fail-closed, end-to-end | 12 tests | all four (stubs + real) | hand-written synthetic |
| `tests/test_api.py` | HTTP endpoint | 5 tests | API | hand-written synthetic |
| `tests/test_channel.py` | CHANNEL taint, session isolation | 4 tests | CHANNEL | hand-written synthetic |
| `tests/test_ministers.py` | VAULT, EXECUTOR, NAVIGATOR basics | 8 tests | VAULT, EXECUTOR, NAVIGATOR | hand-written synthetic; NAVIGATOR cases built from corpus text |
| `tests/test_channel_taint.py` | CHANNEL vocabulary, provenance, regression | 13 tests | CHANNEL | inherited from research code; reads the two data files below |
| `tests/test_struct_parse.py` | fetch-to-disk and credential-path parser | 27 cases (script-style) | EXECUTOR, VAULT | hand-written, inherited |
| `tests/test_ast_parse.py` | bashlex/PowerShell AST path | 37 checks (script-style) | EXECUTOR, VAULT | hand-written, inherited |
| `tests/data/attacker_cases_ds.jsonl` | 32 InjecAgent data-stealing attacker cases | 32 | `test_channel_taint.py` | copied from InjecAgent (origin undocumented in-file) |
| `tests/data/real_benign_trajectories.json` | benign banking sessions | 22 sessions / 64 calls (32 unique) | `test_channel_taint.py` | recorded from one local qwen2.5:7b AgentDojo banking run |

**Measured:** `pytest tests` collects and passes **59** tests. `test_struct_parse.py` and `test_ast_parse.py` define no pytest functions, so pytest runs **0** of their cases; they run only as `python -m tests.<name>`. `test_struct_parse` passes 27/27. `test_ast_parse` exits non-zero: **33 pass, 4 fail**, all four PowerShell cases, because `powershell.exe`/`pwsh` is not installed on this machine. That path is unreachable in the MVP runtime anyway (the PowerShell AST is only used for dialect `powershell`, which `prefilters.py` never passes to it), so those 4 tests exercise code the MVP never runs.

### 2.2 Labelled evaluation data on `main`

| Source (on main) | Purpose | Records | Ministers exercised | Notes |
|---|---|---:|---|---|
| `benchmarks/data/attacker_cases_ds.jsonl`, `…_dh.jsonl` | InjecAgent attacker cases: data-stealing (DS) and direct harm (DH) | 32 + 30 = 62 | CHANNEL (DS), mostly NAVIGATOR/CHANNEL (DH) | all malicious; 62 distinct instructions |
| `benchmarks/data/user_cases.jsonl` | InjecAgent benign user tasks | 17 | benign side of all InjecAgent runs | 17 distinct tools |
| `benchmarks/data/{dh,ds}_structured_args.json` | structured args for the same 62 attacks | 30 + 32 | runner input | derived, not independent |
| InjecAgent replay (`injecagent_runner.py`) | 62 attackers × 17 user cases | 1,054 attack + 1,054 benign rows | all | results in `benchmarks/results_v2/_fresh_full_injecagent/`, `injecagent_full_1054_rerun_20260723/` |
| `benchmarks/results_v2/_kavach_pb_attack_checkpoint.json` | "Kavach-PB" attack cases | 519 (456 Atomic Red Team + 63 GTFOBins) | VAULT, EXECUTOR, CHANNEL, NAVIGATOR | all malicious; `target_ministers` labels derived from the Kavach corpus |
| `…_kavach_pb_bfcl_general_purpose_checkpoint.json` | benign function-calling traffic (BFCL) | 793 | false-positive probe | all benign |
| `…_kavach_pb_benign_v0_agent_shaped_checkpoint.json`, `parliament/benign_test_set/benign_v0.json` | agent-shaped benign calls | 55 (32 unique) | false-positive probe | all benign; one banking run |
| `parliament/benign_test_set/real_benign_trajectories.json` | the 22 benign sessions behind benign_v0 | 22 sessions / 64 calls | CHANNEL | same source as above |
| `benchmarks/data/atriumos_scenarios.jsonl` | author-written generalization audit | 36 (18 attack / 18 benign, paired) | 10 VAULT, 10 EXECUTOR, 8 CHANNEL, 8 NAVIGATOR | invented vocabulary by design |
| `benchmarks/openclaw_native/attack_scenarios.jsonl` | OpenClaw-style cases | 30 (20 expected BLOCK / 10 ALLOW) | all | hand-written; 2 cite CVE-2026-25253 |
| `benchmarks/benign_traces.py` (`BENIGN_TRACES`) | hand-written benign dev sessions | 50 sessions / 93 actions | FPR gate | hand-written, in code |
| `kavach_eval/corpus_agent/benign_probe.json` | benign probe incl. LOLBIN legit-use boundary cases | 25 | false-positive gate | hand-written |
| `eval/agentharm_independent/` | AgentHarm tools + generated calls | 80 harmful + 80 benign tool files; 79 harmful + 80 benign calls dispatched | VAULT, EXECUTOR, CHANNEL (in-scope subset) | arguments LLM-generated (qwen2.5:7b); see provenance |
| `eval/obfuscation_robustness/` | encode / split / indirect transforms of detected cases | 185 + 75 + 75 | VAULT, EXECUTOR | derived only from already-detected cases (baseline detection 100%) |
| `kavach_eval/evasion_results/` | LLM-paraphrase evasion runs against NAVIGATOR | 7 reports; largest 1,200 seeds / 7,404 paraphrases | NAVIGATOR | paraphrases of the project's own corpus |
| `kavach_eval/reference_corpus_v0/proposed_minister_v0/overnight_v1/rule_generalization_variants.json` | 2 variants per rule for 85 rules | 170 | VAULT, EXECUTOR | results: 69 both caught, 13 one, 3 neither |
| `…/overnight_v1/held_out_301.json` | list of 301 corpus pattern IDs not used in rule design | 301 IDs | VAULT, EXECUTOR | an ID list, not test cases |
| `minister_runs.jsonl` | per-case minister votes from an InjecAgent run | 2,108 (1,054 attack / 1,054 benign) | all | model `gemma-4-26b`; an output file |
| `kavach_corpus_v1.json` → `COMPASS.pairs` | aligned vs hijacked intent pairs | 100 (50 / 50) | COMPASS (not in MVP) | labelled, excluded component |

### 2.3 Source material that is not test data, or is only indirectly so

| Source | What it is |
|---|---|
| `kavach_eval/reference_corpus_v0/training_pairs_*.jsonl` (7 files; `training_pairs_v0` has 1,880 rows) | fine-tuning pairs: 456 Atomic Red Team + 63 GTFOBins + 187 LOLBAS + 363 corpus-L3 positives; 793 BFCL + 31 AgentDojo/InjecAgent + 2 confirmed-FP negatives. **These are the same strings as Kavach-PB** (§5). |
| `…/sigma_falsepositives.json` (1,823), `lolbas_dualuse.json` (242), `toolbench_preview_ASSESSMENT_ONLY.json`, `kavach_eval/threat_intel/atomic_index.json` (335 techniques) | external reference corpora; the repo marks them exploratory, "NOT integrated" |
| `eval/llm_judge_baseline*`, `eval/naive_baseline/` | baseline *results* on Kavach-PB (not new data) |
| `eval/latency_m1max/`, `benchmarks/results_v2/latency/` | latency measurements, not detection |
| `eval/w5_localization/` | analysis of where Kavach fires on 629 GPT-4o AgentDojo trajectories (raw trajectories not in repo) |
| `benchmarks/results_v2/agentdojo_slack_gemma_dell/` (223 files), `benchmarks/agentdojo_live/` (3 files) | agent-run logs and summaries |

---

## 3. Labels and balance

| Dataset | Attack / malicious | Benign | Other | Balance and issues |
|---|---:|---:|---|---|
| MVP `tests/data` | 32 | 22 sessions | none | Imbalanced; benign side is one run |
| InjecAgent replay | 1,054 (62 distinct) | 1,054 (**17 distinct**) | DS/DH split | Paired 1:1 by construction, but the benign half repeats 17 actions about 62 times each |
| Kavach-PB attack | 519 | 0 | `target_ministers` multi-label on 110 cases | One-sided; no benign negatives inside |
| BFCL general-purpose | 0 | 793 | none | One-sided; 603 distinct tool names but generic function-calling, not agent-security traffic |
| benign_v0 | 0 | 55 (**32 unique**) | buckets `clean` 9 / `goal_as_task` 46 | `goal_as_task` includes the *same argument values* that are malicious elsewhere in the AgentDojo data |
| AtriumOS | 18 | 18 | paired by `paired_with` | Balanced, tiny, author-written |
| OpenClaw native | 20 | 10 | 5 categories | Small; benign is `git status`, `pytest`-style commands |
| BENIGN_TRACES | 0 | 93 actions | none | Hand-written |
| benign_probe | 0 | 25 | `lolbin_legit` flag (7 cases) | Hand-written boundary cases |
| AgentHarm | 79 | 80 | 35 of the 79 harmful classed "excluded/out of scope" | Labels assigned by one person, once, before scoring (**Documented**) |
| Obfuscation | 335 transformed | 0 | — | Only already-detected seeds, so it cannot show misses on unseen attacks |

**Missing, ambiguous or inconsistent labels (Measured unless noted)**
- No dataset carries benign negatives *paired to the same technique as its attacks*, except AtriumOS (18 pairs).
- "Detected" is defined inconsistently: Kavach-PB reports **99.2% detection** counting ESCALATE as a catch (153 BLOCK + 362 ESCALATE of 519), while the "strict" InjecAgent figure counts BLOCK only. The same result can be 99% or 29% depending on the definition.
- ESCALATE on benign traffic is treated as acceptable in several summaries: BFCL shows **0 hard-block FPs but 235 ESCALATEs (29.6%)**; benign_v0 shows 37/55 ESCALATE. A "0% FPR" claim hides these unless it states "BLOCK only".
- Kavach-PB `target_ministers` labels come from mapping each case's MITRE ID onto the Kavach corpus, so the label depends on the system being evaluated.
- OWASP tags in the corpus use the old `A01..A09` scheme; `docs/KNOWN_ISSUES.md` says the correct scheme is `ASIxx` (**Documented**, confirms a doubt raised in the earlier catalogue audit).
- Label provenance for AtriumOS: ground truth was assigned "from first principles" by the author (`build_atriumos_scenarios.py`), not by an independent labeller.

---

## 4. Provenance

| Dataset | Documented origin | URL recorded? | Licence recorded? | Can credibility be established? |
|---|---|---|---|---|
| InjecAgent attacker/user cases | copied from the InjecAgent benchmark; field names match its format | no | no | **No** from repo evidence alone. The data looks like a benchmark export, but I could not verify against the original here. |
| AgentDojo trajectories (22 benign, 629 GPT-4o, banking/slack logs) | AgentDojo repo runs; `OVERNIGHT_PHASE_REPORT.md` names `github.com/ethz-spylab/agentdojo` | partly (one mention) | no | **Partly.** Benign set is from a local qwen2.5:7b run; GPT-4o trajectories are not in the repo. |
| Atomic Red Team (456) and GTFOBins (63) | converted to tool calls by the project's scripts | no | no | **No.** The conversion script is not independently checked; the project's own mapping to MITRE IDs is unverified. |
| BFCL (793) | Berkeley Function-Calling Leaderboard (`bfcl_simple_python` etc.) | no | no | **No** from the repo. |
| AgentHarm tools | `UKGovernmentBEIS/inspect_evals`, MIT with a safety-use clause, fetched 2026-07-23, unmodified copies | **yes** | **yes** | **Best documented.** But the *call arguments* were generated by qwen2.5:7b at temperature 0.7 and classified by hand, so the test cases are not AgentHarm's own. |
| Sigma, LOLBAS | `SigmaHQ/sigma`, `LOLBAS-Project/LOLBAS` (named in `SUMMARY.md`) | repo names only | no | Reference corpora, not tests |
| `benign_v0`, `real_benign_trajectories` | one live qwen2.5:7b banking run | n/a | n/a | Origin credible and documented, but one model, one suite |
| AtriumOS, OpenClaw, BENIGN_TRACES, benign_probe | hand-written by the team | n/a | n/a | Credible as author-written probes; not independent |
| Red-team / evasion runs | LLM-generated paraphrases (gemma) of corpus patterns | n/a | n/a | Self-referential |

No dataset has a recorded **version or checksum**. Nothing marks any dataset as independently reviewed.

---

## 5. Quality: duplicates, repetition, copies, leakage

**Exact and near duplicates (Measured)**
- benign_v0: 55 rows, **32 unique** `call_text` (max repeat 5). `real_benign_trajectories`: 64 calls, 32 unique. These are the same 32 calls.
- Kavach-PB attack: 519 unique strings, but **70 near-duplicate pairs** (token Jaccard ≥ 0.9) involving 51 cases; 96 distinct ATT&CK IDs; `powershell` (174), `sh` (147), `command_prompt` (91) and `bash` (39) make up 451 of 519 cases (87%).
- BFCL: 793 unique, 16 near-duplicate pairs; mostly generic function calls.
- InjecAgent: 62 distinct attacks, each paired with the same 17 user cases; the 1,054 rows are a cross-product, not 1,054 independent samples.
- Copies: `training_pairs_atomicredteam_v0_capped.jsonl` = 456/456 of Kavach-PB's Atomic Red Team cases; `training_pairs_gtfobins_v0_capped.jsonl` = 63/63; `training_pairs_bfcl_v0.jsonl` = 793/793 of the BFCL set. `training_pairs_v0` contains all 519 attack and all 793 BFCL strings.

**Synthetic or hand-written**
- AtriumOS (36), OpenClaw (30), BENIGN_TRACES (93 actions), benign_probe (25) and all MVP unit tests are team-written. AgentHarm call arguments are LLM-generated.

**Suspected leakage and circularity**
- **Rule authoring on the evaluation data (Documented).** `eval/agentharm_independent/README.md` states the VAULT/EXECUTOR rules "were authored by mining detection misses on the same corpora (AtomicRedTeam, GTFOBins, InjecAgent, AgentDojo) the paper evaluates against". The Kavach-PB attack set *is* that corpus. Its recall figures therefore measure how well the rules fit data they were tuned on.
- **Label derived from the system under test.** Kavach-PB's `target_ministers` come from the Kavach corpus mapping.
- **Rule provenance comments point at corpus patterns** (85 of 127 active rules cite a `VAULT-nnn`/`EXEC-nnn` source); those corpus patterns were in turn derived from MITRE sources the benchmark also uses.
- **Mitigations that exist (Documented):** the AgentHarm check and the AtriumOS audit (author-written, invented vocabulary) were designed to be less circular, and the README is open about the problem. AgentHarm is the only partially independent source.
- **Held-out claim (Unresolved):** `held_out_301.json` lists 301 corpus pattern IDs not used in rule design. It is a list of pattern IDs, not test inputs. The README states the 151/170 rule-generalization figure used separate variants (`rule_generalization_variants.json`, 85 rules × 2 variants); who wrote those variants is not recorded in the files I read.

---

## 6. Coverage of runtime components

**Measured rule-level coverage.** I matched all 127 active regexes against every string in the three labelled attack sets (Kavach-PB 519, AtriumOS attacks 22, OpenClaw attacks 20; 561 strings) and the four benign sets (880 strings).

| Minister | Active regex rules | Matched by **0** attack strings | Matched by 1-2 | Matched by 10+ | Matched any benign string |
|---|---:|---:|---:|---:|---:|
| VAULT | 63 | **44** | 12 | 1 | 0 |
| EXECUTOR | 64 | **32** | 14 | 2 | 0 |

(All-match analysis, ignoring first-match masking. A rule with zero attack matches is *not shown to work or fail* by this data; the MVP unit tests add about 6 more.) No active rule matched any of the 880 benign strings, so these sets give no false-positive evidence for specific rules either way. Separately, `bitsadmin-transfer` fires on a documented legitimate-use probe in `benign_probe.json`.

**Per-component test evidence**

| Component | Meaningful tests | Only isolated examples | Appears untested |
|---|---|---|---|
| Speaker | 17 policy tests (synthetic, complete for the policy) | | |
| Coordinator / API | fail-closed and aggregation tests; one end-to-end with real ministers | | HTTP error paths beyond 422 |
| VAULT regexes | 27 + 6 parser cases, Kavach-PB (circular) | ~6 rules in unit tests | **44 of 63 rules have no labelled attack example**; AST/bashlex path only for tool names `sh`/`bash` |
| EXECUTOR | same | AST alias resolution (a few tests) | **32 of 64 rules**; PowerShell AST path (4 tests fail here, and the path is unreachable in the MVP) |
| CHANNEL taint | 13 tests, 32 InjecAgent DS cases (32/32 BLOCK is asserted), 22 benign sessions | session isolation (3-4 tests) | generic destination-shape fallback; allowlist (empty); `account_email` / `user_instruction` paths minimally |
| CHANNEL provenance | a handful of unit tests | | no labelled dataset for USER_SUPPLIED / SELF classification |
| NAVIGATOR | PB / AtriumOS / OpenClaw (on old pipeline); 2 MVP tests | corpus-text queries | the 100 patterns individually; the 8 COMPASS-flavoured patterns; stale-index rebuild |
| Persisted index, config | | | none tested |

**Threat categories.** Well represented: credential files and secret formats, shell download-and-execute, reverse shells, persistence (via Atomic Red Team). Isolated: financial authorization abuse and physical-access abuse (InjecAgent DH only; the repo's own tier-floor work found NAVIGATOR missed 39 of 81 live cases). Largely untested: multi-step attacks beyond read-then-send, non-shell tool surfaces, benign coverage outside banking.

---

## 7. Evaluation reliability

**Unit tests vs held-out evaluation.** None of the datasets is a genuine held-out evaluation for the MVP.
- *Unit/regression:* all MVP tests; the replay "locked baseline" (`benchmarks/locked_baseline.json`, described as detecting regression "on known trajectories"); the PowerShell/AST tests.
- *Semi-independent:* AgentHarm (tool code from a third party, but arguments LLM-generated and scope-filtered by the author), AtriumOS (author-written, designed to avoid keyword overlap).
- *Not independent:* Kavach-PB (tuned-on), InjecAgent replay (benchmark the rules and corpus were developed against), benign_v0 (single run).

**Which claims the existing results can support**

| Claim | Supported? | Why |
|---|---|---|
| "No known attack stopped being caught after a change" (regression) | Partly, for the old pipeline | The protocol itself says this is all replay CI proves. Three of seven locked baselines are marked non-replayable (reference-only values from another branch). |
| "100% recall on InjecAgent data-stealing" | Weak | 32 distinct attacks; mechanism is the exact read-then-send shape CHANNEL was built for. |
| "0% false-positive rate" | **No** as stated | BLOCK-only; ESCALATE rate is 29.6% on BFCL, 67% on benign_v0 (old pipeline); benign side has 17 or 32 distinct actions. |
| "VAULT 74.4% / EXECUTOR 90.1% recall" | **No** | Circular dataset; measured on the older full pipeline with cosine triage; counts ESCALATE as a hit. |
| Precision | **No** | Benign sets are too small, narrow, and not drawn from the same distribution as the attacks. |
| Recall on unseen attacks | **No** | Unseen-attack tests are n=9 to 44 (AtriumOS, AgentHarm in-scope). |
| Latency | Different question; recorded numbers vary by hardware (78 ms vs 3.7 s p50) | |

**Result instability (Documented, Measured).** Two runs of the same InjecAgent command differed because the server changed between them: strict recall 51.6% (Jul 21) vs 65.0% (Jul 23); DH recall 0% vs 24-33%. The paper keeps the earlier, pre-fix snapshot (**Documented**). The `README` also warns that an earlier 78 ms latency headline no longer holds.

**Confounds in the data.** A live qwen2.5:7b agent run produced a real attacker-tool call in only 6 of 50 cases (**Documented**); the other 44 were the model declining or looping, a model-capability effect rather than a Kavach result.

---

## 8. Smoke replay of existing labelled data through the MVP (new, Measured)

To see whether the existing data is usable on the MVP at all, I ran the already-labelled sets through the real MVP coordinator (all four ministers, scratch ChromaDB, one session per case, sequential calls per AtriumOS case/benign session). **This is not an evaluation**: the sets are not independent, are small, and sessions were not given the context fields CHANNEL can use. The numbers show format compatibility and gross behaviour only.

| Set | Result on the MVP | Old pipeline (documented) |
|---|---|---|
| Kavach-PB attack (519, all malicious) | 153 BLOCK, 280 ESCALATE, **86 ALLOW** (decided by NAVIGATOR 242, EXECUTOR 94, VAULT 51, CHANNEL 46) | 153 BLOCK, 362 ESCALATE, 4 ALLOW |
| BFCL benign (793) | 669 ALLOW, **124 ESCALATE** (15.6%), 0 BLOCK | 558 / 235 / 0 |
| benign_v0 (55, 32 unique) | 21 ALLOW, **34 ESCALATE**, 0 BLOCK | 18 / 37 / 0 |
| 22 benign banking sessions | **20 sessions escalate**, 2 stay ALLOW, 0 BLOCK (12 decided by CHANNEL, 8 by NAVIGATOR) | not directly comparable |
| AtriumOS attacks (18) | EXECUTOR 5/5 BLOCK; CHANNEL 2 BLOCK + 2 ESCALATE of 4; **VAULT 0/5 and NAVIGATOR 0/4 flagged** | paper reports different figures (not re-checked) |
| AtriumOS benign (18) | 16 ALLOW, 2 ESCALATE (CHANNEL), 0 BLOCK | |
| OpenClaw expected-BLOCK (20) | 17 BLOCK, 2 ESCALATE, 1 ALLOW | |
| OpenClaw expected-ALLOW (10) | 2 ALLOW, **8 ESCALATE** | |

Reading it: the MVP's BLOCK count on Kavach-PB equals the old pipeline's (153), consistent with those blocks all coming from deterministic rules; the removal of cosine triage and COMPASS/trajectory shows up as 82 more ALLOWs on attack cases. The most practically significant observation is escalation on ordinary benign traffic. Most of it comes from CHANNEL's provenance rule (any email, URL or IBAN-shaped value the caller did not supply as context) and NAVIGATOR's 0.50 grey line.

---

## 9. Priorities

**Retain as regression fixtures (keep, but label honestly as regression, not evaluation)**
- MVP unit tests (59) plus the script suites; the 32 DS cases and 22 benign sessions already in `tests/data`.
- AtriumOS (36) and OpenClaw native (30): small, paired, differently-authored; useful canaries.
- Make the two script-style suites collectable by pytest (or note them separately), and skip the 4 PowerShell cases when no PowerShell exists. *(Recommendation only; I changed nothing.)*

**Independently verify first**
1. **Provenance of the headline corpora:** record the URL, version/commit, licence and checksum for InjecAgent, AgentDojo, Atomic Red Team, GTFOBins and BFCL, and verify the converted call strings against the originals.
2. **Kavach-PB construction:** audit the conversion scripts that turned Atomic Red Team and GTFOBins into `tool:… args:{…}` strings, and check a random sample by hand.
3. **Labels:** have someone other than the rule authors label a random sample (e.g. 100) of attack and benign cases.

**Replace**
- **Benign evidence.** The 17-action and 32-action benign sets cannot support an FPR claim. Collect a larger, multi-suite, multi-model benign corpus from real agent use, with an explicit session-context story for CHANNEL.
- **Headline metrics.** Report BLOCK-only and BLOCK-or-ESCALATE separately, with the benign ESCALATE rate beside them, and with the number of *distinct* cases, not rows.

**Supplement**
- A genuinely held-out attack set (never used for rule or corpus authoring), stratified by minister and by technique, with enough distinct cases per category to report intervals.
- Rule-level positive tests: the 76 rules with no labelled attack example (44 VAULT, 32 EXECUTOR) each need at least one positive and one negative case; start with the highest-impact ones from `docs/definition-review-batch-1.md` and the catalogue audit.
- NAVIGATOR tests that use the MVP's own configuration (thresholds 0.70 / 0.50, hybrid mode), including the benign admin commands that `NAV-009`/`NAV-022` flagged.
- CHANNEL tests for the provenance classes (`SELF`, `USER_SUPPLIED`, `OUTPUT_DERIVED`, `NOVEL`) with real context fields, and for the generic destination fallback.
- Re-run the replay benchmarks on the MVP rather than quoting numbers from the pre-MVP pipeline.

**Do not use as evidence of MVP performance:** any recall, FPR or latency figure from the pre-MVP pipeline; the 99.2% "any minister" detection rate; the 544/544 strict recall without stating it covers 32 distinct attacks.

---

## 10. Limitations and unresolved questions

- I did not read all 223 AgentDojo log files, the 160 AgentHarm tool files, or the full text of the paper and README claims; I sampled structure, counts and documented methodology.
- The GPT-4o 629-trajectory data and the AgentDojo repo clone are not in the repo, so any result depending on them is unverifiable here.
- Near-duplicate analysis uses token overlap; it will miss paraphrases and over-count templated variants.
- I did not verify the original InjecAgent, AgentDojo, Atomic Red Team, GTFOBins or BFCL sources, so "origin undocumented in the repo" is not the same as "origin doubtful".
- Who authored the rule-generalization variants and the exact conversion of external corpora into tool-call strings: **Unresolved**.
- The MVP smoke run (§8) used a single pass with no CHANNEL context fields; behaviour with `account_email`, `user_instruction` or `tool_output` supplied will differ.

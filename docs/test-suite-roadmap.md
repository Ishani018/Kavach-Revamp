# Roadmap for a trustworthy Kavach test suite

Planning only. Nothing was added to the repo's datasets, no detection logic or Supabase data was touched, no large dataset was downloaded, and nothing was committed. Small public repositories (RedCode, PrivacyLens, tldr-pages, Caldera stockpile, AgentHarm and CredData *metadata*) were inspected in a scratch directory outside the repo.

**Legend.** **Verified** = read from the primary source or computed by me, with the method stated. **Search-only** = a web-search summary I did not confirm at the source. **Assumption** = my judgement. **Unresolved** = not established.

**Standing rule.** No dataset below is called held out. Independence from Kavach's development needs written confirmation from the rule authors plus an overlap check; the evidence required is in §6.

---

## 1. Where we are and what each minister needs

The earlier work (`docs/candidate-triage-report.md`, `docs/heldout-dataset-plan.md`) leaves a 256-example Caldera/tldr batch with these holes:

| Gap | Evidence from the triage |
|---|---|
| VAULT | 6 attack-in-scope examples, 0 definite-benign lookalikes |
| EXECUTOR | attack side mostly Windows PowerShell (29 of 39 core items); benign side only generic commands |
| CHANNEL | none: a standalone command cannot test a read-then-send chain |
| NAVIGATOR | benign controls are generic; attack side tests surface text, not intent |

What a **meaningful** test of each minister requires, from how it actually runs (`docs/runtime-rule-coverage.md`):

| Minister | Mechanism in the MVP | A meaningful test needs |
|---|---|---|
| VAULT | 63 regexes over the tool name and argument values, plus a structural credential-path check | content or path strings that look like credentials (positives), and strings that look similar but are not credentials (lookalikes: placeholders, test fixtures, hashes, UUIDs) |
| EXECUTOR | 64 regexes, a Python-AST alias resolver, a fetch-to-disk structural check | realistic malicious commands/scripts, and legitimate commands that share their surface (admin `sudo`, `curl`, `docker`, `chmod`) |
| CHANNEL | per-session taint from a *source* tool call to a later *destination* call, plus a generic provenance check on URL/address-shaped values; source tools are recognised by name | **multi-call sessions** with a sensitive read followed by a transfer, and matched sessions with a harmless read followed by a harmless transfer; tool names beyond the 32 it lists |
| NAVIGATOR | similarity of the call text to 100 attack-intent descriptions (BGE embeddings + BM25), thresholds 0.70/0.50 | attack calls whose *text* resembles or paraphrases those intents, and a **large, realistic set of benign calls**, because the dominant measured behaviour is unnecessary ESCALATE on ordinary commands |

## 2. Findings by gap

### 2.1 VAULT

| Candidate | Source, version | Licence (how verified) | Labels and size | Overlap with our development data | Use |
|---|---|---|---|---|---|
| **CredData** (Samsung) | github.com/Samsung/CredData @ `0b1940e171725ad8937311120b191602608a4801` (2026-09-29) | Apache-2.0 for the repo (GitHub API). **Each downloaded source file stays under its own project's licence** (README "License" section) | line-level `T` (looks like a real credential), `F` (scanner false positive), `X` (unknown). **Verified from the metadata CSVs:** 67,896 labelled rows over 337 repositories and 11,030 files: F 48,061, T 15,753, X 4,082. Categories (T): Key 3,822, Password 2,573, UUID 2,316, Secret 1,263, PEM private key 1,161, Basic authorization 601, Token 583, URL credentials 213, AWS client ID 162 | Not mentioned anywhere in the repo. Candidate lines were found with open-source scanners (CredSweeper, gitleaks, detect-secrets, trufflehog3 are the benchmarked ones), and VAULT's rules were "modeled on gitleaks/truffleHog" (comment in `prefilters.py`), so expect **pattern-level correlation**, not independence | **Best VAULT source**, but see conditions below |
| SecretBench | github.com/setu1421/SecretBench (code MIT, Zenodo DOI) | repo MIT (LICENSE read); data licence **unresolved** | 97,479 manually labelled candidates, 15,084 true, 818 repos (README) | Candidates were mined with **761 regexes sourced from TruffleHog and Meli et al.** (README table), so overlap with VAULT's rule shapes is built in | **Not immediate**: stored in Google BigQuery/Cloud Storage and *requires contacting the authors and signing a data-protection agreement* (README) |
| Vendor-documented example credentials | provider documentation | unverified | a handful per provider | the existing rules were written from these shapes | only for tiny sanity checks; not researched |
| tldr-pages credential commands | already in our batch | CC BY 4.0 | about 20 relevant rows | none known | already counted |

**CredData facts that matter for use (Verified unless noted):**
- The repo ships **metadata and a script, not the code files.** `download_data.py` (Linux, Python 3.10 recommended) clones the repositories listed in `snapshot.json` (337 URLs). I did not run it, so the download size and the success rate are **unresolved**.
- Values are **obfuscated** (fixed-format secrets such as AWS IDs are replaced by example values; others by random strings of the same shape), and file and directory names are obfuscated. Consequence: it can test **content-literal** rules; it **cannot test path-based rules** (`.ssh/id_rsa`), because paths are gone.
- The README's statistics (297 repositories, 73,842 labelled lines, 4,583 true) do **not** match the current metadata (337 repositories, 67,896 rows, 15,753 T). The README is stale; use the metadata and record the pinned commit.
- 42% of rows (28,539) are under `test` directories, and 1,351 rows span several lines.
- "T" means "looks like a real credential value", not "verified live". Treat it as a label with uncertainty, and the many `UUID` and `Key` T rows (6,138 combined) are the most arguable.
- **Distribution.** Redistributing file contents is not safe: licences differ per repository. The safe design is to store only (repo id, file id, line, label, content hash) and fetch at test time.

**Harmless lookalikes:** the `F` rows are precisely lookalikes, since a scanner flagged them and a person judged them not to be credentials (examples are common words such as `password` in prose, placeholders, test keys). They are the natural hard negatives.

**Conversion needed (Assumption):** a labelled line has to become a tool call, for example `tool:write_file args:{"path": "<neutral name>", "content": "<line>"}`. VAULT scans every argument value, so this is reasonable, but it is our choice and must be stated.

### 2.2 EXECUTOR

| Candidate | Source, version | Licence | Labels and size | Overlap | Use |
|---|---|---|---|---|---|
| **RedCode-Exec** | github.com/AI-secure/RedCode @ `c84b6db88fd8bd258e29f12e692ccfd4287a454d` (2026-08-19) | MIT (LICENSE read) | risky code per scenario. **Verified in this checkout:** `bash2text` JSON has 600 bash scripts (20 risk scenarios × 30), 570 of them multi-line, average about 14 lines; `py2text` JSON has 810 Python snippets (27 scenarios × 30). The paper and README state 4,050 instances; I did not reconcile that with the 1,410 present in these two folders. Each record has `Code`, a one-line `Text_summary`, a long `Text_details` and an `expected_result` | Not mentioned in our repo. Of the 600 bash scripts, **0 are exact and 0 near duplicates** of any of our 15,327 reference strings (token Jaccard ≥ 0.8) | **Use for the attack side.** Conversion only (§4) |
| Caldera stockpile | already prepared | Apache-2.0 | 39 core + 50 dual-use items | technique-level overlap with our catalogue | already in hand |
| PayloadsAllTheThings | github.com/swisskyrepo/PayloadsAllTheThings | MIT (GitHub API) | markdown payload lists | not mentioned | possible reverse-shell and persistence supplement; **not inspected** |
| SigmaHQ rules | github.com/SigmaHQ/sigma | GitHub reports no standard licence; the Detection Rule License file I tried returned 404, so **unresolved** | detection patterns, not commands | an earlier exploration touched its `falsepositives` field only | do not use until the licence is resolved |

**Legitimate lookalikes for EXECUTOR**

| Candidate | Licence | Labels and size | Overlap | Use |
|---|---|---|---|---|
| **tldr-pages, targeted draw** | CC BY 4.0 | 32,512 example commands in 7,467 pages (Verified earlier); our random 150 had almost no risky-looking benign commands | 0.13% exact or near duplicate | **Use**, but draw from security-adjacent pages (ssh, gpg, openssl, aws, kubectl, docker, curl, nmap, chmod, systemctl, crontab and similar) instead of at random |
| **nebius/SWE-agent-trajectories** | cc-by-4.0 (HF card, not gated) | 80,036 agent trajectories; our sample of 100 gave 2,518 commands, of which 786 were single-line non-built-in shell commands | not mentioned in our repo | **Use for a realistic benign set.** No safety labels: "benign" is an assumption and a reviewer should skim for risky commands. The full 2,518-command sample includes 33 commands that start with `rm` and 10 with `wget` |
| NL2Bash | **GPL-3.0** (GitHub API) | benign English-to-bash pairs | not mentioned | **Avoid**: copyleft licence |
| xLAM function-calling 60k | cc-by-4.0, **gated** (HF API) | generic benign function calls | not mentioned | little added value over BFCL we already hold |

### 2.3 CHANNEL: the hardest gap

No public dataset I found supplies ready-to-send, concrete, multi-step **exfiltration** workflows that are independent of InjecAgent and AgentDojo, which we already used.

| Candidate | Source, version | Licence | What it provides | Overlap | Use |
|---|---|---|---|---|---|
| **PrivacyLens** | github.com/SALT-NLP/PrivacyLens @ `9c2ee07b080dc54ed4924af11d9751e81753c94d` (2025-03-03) | MIT (LICENSE read) | **Verified:** 493 data points, each with a seed (privacy norm: data type, sender, recipient, transmission principle), a vignette, and a **trajectory**: the user instruction, an `executable_trajectory` text of tool calls with arguments and observations (for example `NotionManagerSearchContent` returning sensitive notes), a named `final_action` tool (for example `FacebookManagerCreatePost`, `GmailSendEmail`) and the list of `sensitive_info_items`. Toolkits: Gmail+Notion 140, Messenger+Notion 118, Messenger 98, Slack+Notion 30, Facebook+Notion 19 and others. Observations are simulated by an LLM emulator (per the paper; Search-only), not real systems | Not mentioned in our repo | **Best available CHANNEL source**, with conditions below |
| AgentHarm | HF ai-safety-institute/AgentHarm @ `e23b3fe60a0da9037314b88e5ee3a0c054970dad` | MIT with a safety-use clause (HF API, LICENSE) | **Verified:** public set of 176 test + 32 validation behaviours, each in a harmful and a benign form; **188 of 188 harmful ids have a benign counterpart** (matched pairs); all 208 are multi-tool tasks; 80 distinct tools. Gives prompts and `target_functions` only, no arguments | Our repo already used AgentHarm's *tool code* (documented), but I found no evidence its behaviours were used | **Needs an agent harness.** Caution: a crude "read-then-send" count by verb gives 144 harmful and 148 benign, but those are mostly harassment, sexual and copyright tasks, not sensitive-data transfers; only about 8 are in the cybercrime category. The count overstates CHANNEL relevance |
| AgentDojo | github.com/ethz-spylab/agentdojo (MIT; latest release v0.1.35) | MIT | concrete ground-truth multi-step call sequences for user and injection tasks | **Documented heavy use by Kavach** (`ground_truth` calls, real GPT-4o runs of all four suites) | useful only as a non-independent regression suite |
| InjecAgent | github.com/uiuc-kang-lab/InjecAgent (MIT) | MIT | the 62 attacker cases | **Used** | not independent |
| Agent Security Bench | github.com/agiresearch/ASB @ `544540ff0788998072f7df463056fd17e62cc9f4` (MIT) | MIT | **Verified:** 400 attacker-tool entries (200 aggressive, 200 non-aggressive; stealthy/disruptive), 20 normal tools, 10 agent task files; no concrete arguments | Our repo has a runner script for ASB but I found no committed ASB results; tool-name style resembles InjecAgent; extent of use **unresolved** | needs a harness |
| R-Judge | github.com/Lordog/R-Judge | **no licence** | safe/unsafe multi-step records | 414 of 571 records contain an InjecAgent attacker instruction verbatim | do not use |
| OS-Harm | github.com/tml-epfl/os-harm | Apache-2.0 (LICENSE read) | 150 GUI computer-use tasks on OSWorld (Search-only) | not mentioned | **Not a fit**: GUI actions, not shell or API tool calls |
| MCP benchmarks (MCPTox, MCP-SafetyBench) | arXiv 2508.14925 and 2512.15163 | **unresolved** (the LICENSE path I tried returned 404) | tool-poisoning scenarios (Search-only) | not mentioned | a possible later addition; not verified |

**PrivacyLens conditions (Verified or Assumption as marked):**
1. The threat model differs: the user's own instruction triggers a *privacy-norm* breach (an agent over-sharing), not an attacker-driven exfiltration. It exercises the same *shape* (sensitive read, then transmit), which is what CHANNEL's taint rule looks for.
2. **The final action is not in the data**, only its tool name; the benchmark's own label is whether an LM-generated final action leaks. So we cannot just replay it. Two routes: (a) **agent harness**: run a model on each trajectory to produce a final action, then label leaks with human review; (b) an **interim, constructed** final call (a send containing the listed `sensitive_info_items` versus one that contains none). Route (b) is our invention and must be labelled as constructed.
3. **Tool names are the test.** CHANNEL recognises a source tool by name: 32 listed names plus a verb-and-noun pattern. PrivacyLens uses `NotionManagerSearchContent`, `MessengerSendMessage` and similar names, so the first thing it measures is whether CHANNEL's name-based recognition generalises at all. That is a valid, important result, not a flaw.
4. The seeds are crowd-sourced, with the benchmark reporting agreement among annotators (Search-only: Fleiss' kappa 0.79).

### 2.4 NAVIGATOR

NAVIGATOR scores the **text** of `tool:NAME args:{...}` against 100 attack-intent descriptions. A command carries little stated intent, so command datasets exercise it weakly. What helps:

| Need | Source | Status |
|---|---|---|
| Attack calls whose text resembles or paraphrases the corpus intents | RedCode-Exec bash scripts (their `Text_summary` is a natural-language description of each script, a close analogue of the corpus' L1/L2 text); Caldera core items | immediate (RedCode needs conversion) |
| **Large, realistic benign controls (highest value)** | SWE-agent trajectories, targeted tldr | immediate (conversion plus a skim). Pilot runs showed 75-93% of ordinary benign shell commands come back ESCALATE, so the false-escalation rate is the quantity most worth measuring |
| Matched harmless/harmful intent pairs | AgentHarm (188 pairs) | needs a harness, because the MVP takes tool calls, not prompts |
| Injection phrasing in text | deepset/prompt-injections: Apache-2.0 (HF API), 662 rows (**Verified:** train 546 = 343 benign + 203 injection), user-prompt text, not tool calls | low priority: prompt-level, wrong input type; use only if the MVP is later extended to screen prompts or tool outputs |
| Paraphrase and obfuscation robustness | built from our own corpus | **not independent** by construction |

No dataset I found was built for this retrieval mechanism, so NAVIGATOR will lean on the attack and benign command sets above, and conclusions about "intent understanding" are not supportable from them.

## 3. The smallest practical combination

| # | Dataset | Ministers | What it supplies | Readiness |
|---|---|---|---|---|
| 1 | **Caldera core + dual-use items** (already prepared) | EXECUTOR, NAVIGATOR, a little VAULT | 39 attack-emulation + 50 dual-use stress items | **immediate**; label review pending |
| 2 | **RedCode-Exec bash** (MIT) | EXECUTOR, NAVIGATOR | 600 scripts, 20 risk scenarios; no benign side | **conversion only** (§4) |
| 3 | **tldr-pages targeted + SWE-agent trajectories** (CC BY 4.0 each) | EXECUTOR, VAULT, NAVIGATOR benign side | realistic and risky-looking benign commands | **conversion plus a skim review** |
| 4 | **CredData** (Apache-2.0 repo; per-file licences) | VAULT | credentials (T) and scanner false positives (F) | **download, conversion, licence and safety handling** |
| 5 | **PrivacyLens** (MIT), AgentHarm (optional) | CHANNEL | multi-step sensitive reads; matched harmless variants | **agent harness or constructed finals, plus label review** |

That is five sources (four new) for four ministers, and each minister has at least one attack-side and one benign-side source *except CHANNEL's benign side*, which needs the harmless variants from the harness or from AgentHarm's pairs.

| Minister | Attack side | Benign / lookalike side | Still thin |
|---|---|---|---|
| VAULT | CredData T, Caldera credential items | CredData F, targeted tldr | path-based rules (paths are obfuscated) |
| EXECUTOR | RedCode, Caldera | targeted tldr, SWE-agent | Linux/macOS-native malicious commands beyond RedCode |
| CHANNEL | PrivacyLens-derived sessions, AgentHarm | harmless variants of the same sessions | independent, attacker-driven exfiltration (none found) |
| NAVIGATOR | RedCode, Caldera | SWE-agent, targeted tldr | intent-level semantics |

## 4. Immediate vs. needs more work

**Usable immediately (after a small, stated conversion)**
- **RedCode bash:** `tool:bash args:{"command": <Code>}` (the `Code` field is a script; multi-line passes through unchanged). Keep `Index` as the id and the scenario index as metadata. Label meaning is "risky by scenario design", **not** "malicious in every context" (severity varies: the sample includes copying `/etc/passwd`, appending a destructive alias, and a weather function filed under a risk index). No benign half.
- **SWE-agent trajectories:** take the command block from each agent turn, drop the agent's built-in editing commands (`open`, `edit`, `goto` and similar) and multi-line edits, keep single-line shell commands; id = `instance_id|model|row|turn`. Label meaning "agent-generated, assumed benign, unreviewed".
- **tldr targeted:** same transformation as the first batch.

**Needs additional steps**
- **CredData:** download all 337 repositories at pinned commits, apply the dataset's obfuscation script, sample, convert, and **review a sample of T/F labels** (UUID and generic Key rows especially). Handle licences by storing references, not contents. Run on a controlled machine.
- **PrivacyLens and AgentHarm:** an agent harness (a local model producing the missing final actions or the AgentHarm tool calls), plus human review of the leak/harm labels. Also decide whether to use the constructed-final-action shortcut and label it as constructed.
- **Label review:** every new set needs the independent review designed for batch 1, scaled by the triage pipeline.

**Not recommended now:** R-Judge (no licence, mostly InjecAgent), OS-Harm (GUI), NL2Bash (GPL), SecretBench (access agreement, rule-overlapping patterns), deepset (wrong input type), Sigma (licence unresolved), MCP benchmarks (unverified), AgentDojo and InjecAgent (used in development).

## 5. Sizes and what they can support

The number of **distinct** examples matters, not rows. Plain arithmetic (not a validated standard):
- With 0 failures in *n* independent trials, the 95% upper bound on the true failure rate is about 3/*n*: 100 trials give about 3%, 300 give about 1%.
- To estimate a rate near 5% to within about ±2.5 percentage points needs about 300 examples; near 50% to within ±5 points needs about 385.

Suggested first targets (Assumption): RedCode 60 (3 per scenario), CredData 300 T + 300 F stratified by category, targeted tldr 150, SWE-agent 300 single-line commands, PrivacyLens 100 sessions with harmless variants, plus the Caldera items in hand. Each ministry's reported numbers should carry an interval based on distinct examples.

## 6. Independence: what would count as evidence

All the sources above were published before Kavach's development (RedCode, PrivacyLens and AgentHarm in 2024-25), so being older proves nothing: the authors could have seen them. A dataset can move from "candidate" to `held_out_evaluation` only with **all** of:
1. a pinned version, licence file and checksum;
2. written confirmation from the rule, corpus and threshold authors that the source was not consulted;
3. an overlap check against everything we hold (done for RedCode: 0 of 600 scripts exact or near duplicate; not yet done for the others);
4. no mention in the project's code, history or notes (done so far: no hit for RedCode, PrivacyLens, SecretBench, CredData, OS-Harm, MCP benchmarks, deepset or SWE-agent datasets in `main`'s text files or the MVP tree; AgentHarm hits are the known tool-code use; CyberSecEval hits are related-work citations only);
5. labels from reviewers who are not the rule authors.

Cases where independence is structurally **doubtful**: CredData and SecretBench (candidates came from scanners whose patterns VAULT's rules emulate), AgentDojo and InjecAgent (used). Everything else is "no evidence of use", which is not the same as independent.

## 7. Phased plan

| Phase | Work | Output | Gate to proceed |
|---|---|---|---|
| A (days) | Convert RedCode bash, targeted tldr, SWE-agent sample into the review-package format; run the triage pipeline; produce review sheets | about 60 + 150 + 300 candidates with triage records | spot-check agreement on a sample |
| B (a week or more) | Fetch CredData at a pinned commit in an isolated environment, obfuscate, sample 300 T / 300 F, convert, review a label sample | VAULT set stored as references plus hashes | licence and safety sign-off |
| C (a week or more) | Build an agent harness (local model); produce PrivacyLens final actions and a sample of AgentHarm pairs; label leaks with human review | CHANNEL sessions with matched harmless variants | label agreement and review of a sample |
| D | Ask the authors the independence question; run overlap checks; register sets with a new role such as `independent_candidate` and `held_out_status: not_verified`; promote only on the §6 evidence | registry entries and an independence statement per set | written author confirmation |
| E | Run the evaluation runner on the MVP with context where available, reporting BLOCK/ESCALATE/ALLOW separately with distinct counts and intervals | first results labelled by independence status | none, but results stay smoke tests until D completes |

## 8. Risks and safeguards

- **Sensitive content.** CredData values are obfuscated but credential-shaped; RedCode and Caldera contain working attack code. Store references and hashes where licences require, keep operational payloads out of public artefacts, and never execute dataset commands.
- **Licences.** CredData's per-file licences and tldr/Caldera attribution duties need a NOTICE; Apache and MIT items permit redistribution with notices; GPL and unlicensed sources are out.
- **Label noise.** CredData `T`, RedCode "risky" and Caldera tactics are all proxies. Report them as proposed labels until reviewed.
- **Circularity.** SecretBench and CredData are scanner-derived. Any VAULT result on them should be read as "agreement with scanner-style detection", not as absolute recall.
- **Stale documentation.** CredData's README statistics disagree with its metadata; AgentHarm's HF page lists a partial release (44 of 66 public base behaviours) and says more may follow, so pin versions.

## 9. Decisions needed from you

1. Approve Phase A conversions (RedCode, targeted tldr, SWE-agent) and the assumptions in §4.
2. Decide whether to invest in Phase B (CredData) and Phase C (agent harness). They are the only routes to real VAULT lookalikes and CHANNEL sessions I found.
3. Choose the interim stance for CHANNEL: wait for harness-generated trajectories, or accept constructed final actions explicitly labelled as constructed.
4. Name who will answer the independence question for the rule authors, and who will review labels.
5. Decide whether CredData's licence situation (reference-only storage) is acceptable.

## 10. What is verified and what is not

| Verified (primary source or my computation) | Search-only or unresolved |
|---|---|
| Licences: CredData, RedCode, PrivacyLens, SecretBench, OS-Harm, AgentHarm, Caldera, tldr, ASB, deepset, nebius (LICENSE files or HF/GitHub metadata) | Licences of MCPTox and MCP-SafetyBench; Sigma's rule licence; SecretBench's data licence |
| CredData metadata counts; RedCode bash counts; PrivacyLens structure and counts; AgentHarm counts and pairing; deepset row and label counts; ASB file sizes | The RedCode 4,050 total versus the 1,410 records present; PrivacyLens and OS-Harm details beyond the data fields; CredData download size and success |
| 0 of 600 RedCode scripts duplicate our data; no mention of the new sources in our repo | Whether the rule authors consulted any source (only they can say) |

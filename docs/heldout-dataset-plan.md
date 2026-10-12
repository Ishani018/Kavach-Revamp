# Plan for a trustworthy test dataset

Research and planning only. Nothing was added to the repo's datasets, no detection logic or Supabase data was touched, and nothing was committed. Downloaded material lives in a scratch directory outside the repository.

**Legend.** **Verified** = I read it from the primary source or computed it myself, and the method is stated. **Search-only** = a web-search summary I did not confirm at the source. **Assumption** = my judgement, flagged so you can reject it. **Unresolved** = I could not establish it.

## 0. Bottom line

1. **No dataset can be called held out yet.** "Held out" would require proof that nobody used the data while writing rules, the corpus or thresholds. For every candidate below I can show only *absence of evidence* of use (no mention in the repo, low textual overlap). That is weaker than proof, and only the rule authors can supply the missing piece. Everything below is therefore **"independent candidate, not verified as held out"**.
2. **Recommended first dataset (about 256 call-level examples, both classes):**
   - **106 attack-emulation commands** from MITRE Caldera's `stockpile` plugin (Apache-2.0), and
   - **150 documented-benign commands** from `tldr-pages` (CC BY 4.0).

   Both are real command strings with stable IDs, a verified licence and a pinned commit, and both have very low lexical overlap with our data. Neither is a perfect fit (see §5): the Caldera labels are "adversary-emulation action", not human-verified "malicious", and the tldr labels are "documented legitimate usage", not agent traffic.
3. **Several well-known benchmarks look attractive but fail here**: R-Judge is mostly InjecAgent-derived (414 of 571 records contain a Kavach attacker instruction verbatim) and has no licence; AgentHarm, ASB, Agent-SafetyBench and ToolEmu supply tasks, not concrete tool calls, so they need an agent in the loop.
4. **There is a gap we cannot fill from public call-level data today:** independent CHANNEL (read-then-send) and VAULT (real secret formats) examples. See §7.
5. **A pilot run (not an evaluation) is already informative:** through the MVP, the 150 benign tldr commands gave 2 BLOCK / 114 ESCALATE / 34 ALLOW, and the 106 attack commands gave 21 BLOCK / 68 ESCALATE / 17 ALLOW. ESCALATE dominates both sides, so a BLOCK-vs-ALLOW split alone says little. See §6.

## 1. What I checked

- **Our side:** `docs/runtime-rule-coverage.md`, `docs/test-data-inventory.md`, `evaluation/` (registry, manifest, runner, datasets), and `main` at 3eb7b7e for the legacy corpora and training pairs.
- **Candidate side:** official repositories and dataset cards. Licences came from the GitHub API's licence detection and the LICENSE files themselves; Hugging Face metadata via the HF API; data by shallow clone or the HF datasets-server. Commit hashes are below so the work can be redone.
- **Overlap method (§4):** a reference set of 15,327 strings drawn from everything we have (the 3 Kavach-PB sets, the 4 hand-written/author sets, all training pairs including LOLBAS/GTFOBins, and the L1-L3 text of both corpora), matched by exact normalized text and by token-set Jaccard ≥ 0.8.

## 2. Candidate survey

Inspection depth is stated per row: **data** = I downloaded and parsed the data; **meta** = I verified licence and repository facts only; **search** = web-search summary only.

| Candidate | Source and version I looked at | Licence (how verified) | Labels | Call-level? | Overlap with Kavach | Depth | Verdict |
|---|---|---|---|---|---|---|---|
| **MITRE Caldera `stockpile`** | github.com/mitre/stockpile @ `996ec41cd1c5d1c7cc09e620fc55dabe5aefd9cc` (2026-04-30) | Apache-2.0 (GitHub API; LICENSE file is the Apache text) | ATT&CK tactic + technique per ability; no malicious/benign label | **Yes**: 300 shell command entries in 189 abilities | Not mentioned anywhere in the repo; lexical overlap 6/300; **36 of 189 abilities are marked "Generated from Atomic Red Team"** (a source we used) | data | **Use** (attack side), excluding ART-marked and dual-use items |
| **tldr-pages** | github.com/tldr-pages/tldr @ `3b04259a58d0bfecaa31c3179b3d349a81ef7893` (main, 2026-10-12; moves daily, so pin the SHA) | CC BY 4.0 (LICENSE.md text: attribution required; `scripts/` is MIT). GitHub reports "NOASSERTION" because the licence is custom-formatted | none; every example is documented usage by convention | **Yes**: 32,512 single-line commands in 7,467 pages | Not mentioned in the repo; lexical overlap 43/32,512 (0.13%) | data | **Use** (benign side) |
| **nebius/SWE-agent-trajectories** | huggingface.co/datasets/nebius/SWE-agent-trajectories, revision `68195a1450…` | cc-by-4.0 (HF metadata; not gated) | none about safety; `target` = issue resolved | **Yes**, as agent turns | Not mentioned; not overlap-checked at scale (sampled only) | data (100 of 80,036 trajectories) | **Second batch**: realistic agent traffic, but unlabelled (see §5) |
| **AgentHarm** | HF `ai-safety-institute/AgentHarm` @ `e23b3fe60a0da9037314b88e5ee3a0c054970dad`; 176 + 32 harmful and 176 + 32 benign public behaviours | MIT-style with a use clause (safety/security improvement only); HF metadata says "other" (HF API and LICENSE read) | harmful / benign pairs, categories | **No**: prompts + `target_functions`, no arguments | Our repo used AgentHarm's *tool code* (README on main); the behaviours/prompts were not used by our evidence; cybercrime is only 20 of 176 harmful | data | **Phase 2** (needs an agent loop). Note the file's canary GUID `4b646a02-…`; keep it out of any training data |
| **R-Judge** | github.com/Lordog/R-Judge @ `83ce301da3ad50dd8b397e772863f5411c3d3dc2` | **None** (GitHub reports no licence) | safe/unsafe labels (301 unsafe, 270 safe) plus risk text | partly (heterogeneous action strings) | **414 of 571 records contain a Kavach/InjecAgent attacker instruction verbatim**; the 157 others are mixed | data | **Do not use yet**: unlicensed and mostly overlapping. Contact the authors |
| **Agent Security Bench (ASB)** | github.com/agiresearch/ASB @ `544540ff0788998072f7df463056fd17e62cc9f4` | MIT (GitHub API) | 400 attacker tools with instruction/goal; 20 normal tools | **No** (no arguments) | Our repo has a runner script (`benchmarks/asb_runner.py`) but I found no committed ASB results; tool names and format resemble InjecAgent | data | **Phase 2** (needs argument generation or an agent) |
| **Agent-SafetyBench** | github.com/thu-coai/Agent-SafetyBench @ `74feea8de601b3a1449a93fcf70017fe61556f73` | MIT (GitHub API) | 2,000 cases with `failure_modes`, `fulfillable` | **No** (instruction + tool list) | Mentioned only in our README as related work | data (structure) | **Phase 2** |
| **ToolEmu** | github.com/ryoungj/ToolEmu | Apache-2.0 (GitHub API) | 144 risk cases (per the paper) | No (emulated) | Mentioned only in a docs file | meta | Phase 2 candidate, not inspected |
| **Samsung CredData** | github.com/Samsung/CredData @ `0b1940e171725ad8937311120b191602608a4801` | Apache-2.0 (GitHub API); the underlying source files come from third-party repos with their own licences, per its README | line-level true / false / unknown credential labels | Not directly | Not mentioned; VAULT rules were modelled on gitleaks/truffleHog, not on this | data (metadata only) | **Best VAULT candidate, not first batch**: the repo holds only labels; the code files must be fetched by a script that clones many external repositories (I did not run it) |
| **PayloadsAllTheThings** | github.com/swisskyrepo/PayloadsAllTheThings | MIT (GitHub API) | none | Yes, as markdown payload lists | Not mentioned | meta | Possible attack-side supplement; not inspected |
| **NL2Bash** | github.com/TellinaTool/nl2bash | **GPL-3.0** (GitHub API) | benign command pairs | Yes | Not mentioned | meta | **Avoid** copying: copyleft licence |
| **xLAM function-calling 60k** | HF Salesforce/xlam-function-calling-60k | cc-by-4.0, **gated** (HF API) | benign function calls | Yes | Not mentioned | meta | Low added value; generic like BFCL |
| InjecAgent, AgentDojo, Atomic Red Team, GTFOBins, LOLBAS, BFCL | already used by Kavach | not recorded in our repo | various | various | **Used in development (documented)** | n/a | **Not independent** |

Not researched: MCP-specific security benchmarks (a repo doc mentions some; I did not verify any). That is a gap in this survey.

## 3. What "held out" would require, and why I do not claim it

To register a dataset as `verified_held_out` in `evaluation/registry.json` we need all of:

1. **Provenance:** a pinned source (commit or dataset revision), a recorded licence file, and a collection date. *Established for the two recommended sources.*
2. **No use in development:** written confirmation from the rule/corpus authors that neither source was consulted, plus no overlap beyond a stated threshold. *Not established.* I found no mention of Caldera, tldr-pages or the SWE-agent datasets anywhere in the repo's docs or code on `main` (searched case-insensitively across non-data text files), but silence is not confirmation.
3. **Independence from its siblings:** Caldera's stockpile includes abilities generated from Atomic Red Team, which Kavach used heavily. I exclude those, but the remaining abilities may still describe the same public techniques. Technique-level overlap is high and unavoidable: 69 of the 112 ATT&CK technique IDs used in the stockpile also appear in our catalogue's citations (41 exactly), and 53 share a parent technique with Kavach-PB. So Caldera tests *command-level* generalization on familiar techniques, not novel techniques.
4. **Independent labels:** labels assigned by someone other than the rule authors. *Not established for any candidate.*

**Assumption:** I treat items 2 to 4 as open for both recommended sources, so their registry status stays `not_verified`.

## 4. Overlap and duplicate findings (Verified)

Reference set: 15,327 strings from our data (training pairs 10,360; BFCL 2,292; corpus v1 1,206; technical corpus 600; Kavach-PB attack 519; benign sets, AtriumOS and OpenClaw ≈ 450). Test: exact match after lowercasing and whitespace collapse, or token-set Jaccard ≥ 0.8.

| Candidate set | Items checked | Exact match | Near match (J ≥ 0.8) | Notes |
|---|---:|---:|---:|---|
| Caldera stockpile commands | 300 | 3 | 3 | 6 items (2%) excluded from the batch |
| tldr-pages commands (placeholders replaced by their inner text) | 32,512 | 42 | 1 | 43 items (0.13%) excluded; most are very short commands (a bare `bash`, `crontab -l`) |
| R-Judge records | 571 | n/a | n/a | **414 contain an InjecAgent attacker instruction verbatim** (every `ds_*` and `dh_*` file, 414/414); 157 do not |
| AgentHarm tools | n/a | n/a | n/a | Our repo already used AgentHarm tool implementations (documented), so the *tools* overlap even though the behaviours were not used |

Other facts:
- Lexical overlap measures textual copying only. It cannot detect "same attack, different wording".
- Stockpile ATT&CK IDs checked against Enterprise ATT&CK v19.2: of the 106 recommended entries, 102 cite an active technique and 4 cite a revoked one (`T1562.001` ×3, `T1070.001`). Original IDs are preserved; revoked ones should be flagged, not corrected.
- R-Judge: the repository holds 571 records, while a search summary of the EMNLP paper gave 569 (**Search-only**; discrepancy unresolved).

## 5. Recommended first dataset

### 5.1 Composition

| Part | Source | Selection rule (reproducible) | Size | Class label to record |
|---|---|---|---:|---|
| **A: attack-emulation** | Caldera `stockpile` @ `996ec41c…`, files `data/abilities/*/*.yml` | every `(ability id, platform, executor)` command entry whose `tactic` ∈ {credential-access, defense-evasion, exfiltration, persistence, privilege-escalation, impact, command-and-control, lateral-movement, execution}; executor ∈ {`sh`, `psh`, `pwsh`, `cmd` and their combinations}; **excluding** abilities whose name or description contains "Atomic Red Team", entries in the exact/near-duplicate list of §4, and non-shell executors (shellcode, native, osa) | **106 entries / 67 abilities** (credential-access 15, defense-evasion 20, exfiltration 21, impact 17, lateral-movement 11, execution 10, privilege-escalation 7, command-and-control 4, persistence 1; windows 64, linux 24, darwin 18) | `attack_emulation (unreviewed)` |
| **B: documented-benign** | tldr-pages @ `3b04259a…`, `pages/{common,linux,osx}/*.md` | single-line example commands; Windows pages excluded (platform and shell ambiguity); §4 duplicates excluded; sorted by ID, then `random.Random(20261012).sample(…, 150)` | **150** of 31,195 candidates | `benign_documented_usage (unreviewed)` |

IDs are preserved verbatim: Caldera `"<ability uuid>|<platform>|<executor>"` (for example `0ab383be-b819-41bf-91b9-1bd4404d83bf|linux|sh`, tactic command-and-control, T1071.001, "Ragdoll"; `0ef4cc7b-611c-4237-b20b-db36b6906554|windows|psh`, credential-access, T1003.001, "Dump LSASS memory using ProcDump") and tldr `"<platform>/<page>#<n>"` (for example `common/op#3`, `linux/module#1`, `common/7z#6`). Source ATT&CK tactic and technique IDs, ability names and the pinned commit travel with each record.

### 5.2 Labels: what they do and do not mean (important)

- **Caldera:** the stockpile has no "malicious" label. It is a library of adversary-emulation actions. I propose using the *tactic* to separate clearly adversarial actions (Part A) from **dual-use discovery and collection actions (153 entries, deliberately excluded from Part A)**, because commands such as `whoami` are not malicious on their own. This split is my **assumption**. Part A items are therefore "attack-emulation, unreviewed", not "confirmed malicious in an agent context". A reviewer should confirm each label before results are quoted.
- **tldr:** examples document legitimate usage by convention, but some pages are for dual-use security tools, and our pilot found 6 of 400 sampled commands that the MVP BLOCKs, including `aws secretsmanager list-secrets …`, `kops create sshpublickey … ~/.ssh/id_rsa.pub`, `nsenter …`, `sshfs -o follow_symlinks …`. Whether those are false positives or genuinely risky in an agent setting is a label question for a human. Labels are "documented-benign, unreviewed".
- **Neither** is agent-generated traffic, and neither contains a read-then-send chain.

### 5.3 Transformations needed for our runner (all mechanical; none changes a label)

The runner takes `tool:NAME args:{json}` strings, one example per call. Proposed mapping, following the naming convention already used in Kavach-PB:

| Source field | Transformation | Caveat |
|---|---|---|
| Caldera executor `sh` | tool `sh`, args `{"command": <command>}` | `sh`/`bash` also unlocks the bashlex AST path in VAULT/EXECUTOR |
| Caldera `psh`, `pwsh`, and combinations | tool `powershell` | for combined executors I take the first listed; **Assumption** |
| Caldera `cmd` | tool `command_prompt` | |
| Caldera `#{fact}` variables (51 of the 106 entries) | **leave literal** | Caldera substitutes these at run time; we do not invent values, but literal `#{…}` text may change what rules match |
| Caldera multi-line commands (58 of 106) | pass the multi-line string unchanged | JSON-escaped in the call |
| tldr command | tool `bash`, args `{"command": <command>}` | pages are a mix of shells; **Assumption** |
| tldr placeholders `{{path/to/file}}` (105 of 150) | replace with the inner text (`path/to/file`) | the only reliable mechanical rule; it produces a documented placeholder, not a real value |
| session | one session per example; no `context` | like most current datasets, no instruction or tool output exists |

When these are registered, the existing role `development_tuning` would be wrong (they are not known to be development data) and `held_out_evaluation` would be premature. A new role value (for example `independent_candidate`) is needed, with `held_out_status` kept at `not_verified`, and the runner should label results "independent-candidate smoke test" until the labels are reviewed and the no-use confirmation is in. This is a small design change for later; I made none.

### 5.4 Licence and attribution (Verified from LICENSE texts; not legal advice)

- Caldera stockpile: Apache-2.0 permits redistribution with the licence text and notices retained.
- tldr-pages: CC BY 4.0 requires attribution (copyright tldr-pages team and contributors), a licence link, and a statement of changes. A short NOTICE file listing both sources, commits and changes would cover it.
- Copying the data into the repo is a separate decision; at minimum store the selection recipe and IDs.

## 6. Pilot run through the MVP (Verified measurement, not an evaluation)

Run once through the real MVP (all four ministers) on the proposed batch, no context. These numbers are given only to show whether the data can discriminate, not as performance claims.

| Set | n | BLOCK | ESCALATE | ALLOW | Who decided non-ALLOW |
|---|---:|---:|---:|---:|---|
| A: Caldera attack-emulation | 106 | 21 | 68 | 17 | NAVIGATOR 59, VAULT 12, CHANNEL 10, EXECUTOR 8 |
| B: tldr documented-benign | 150 | 2 | 114 | 34 | NAVIGATOR 114, VAULT 1, CHANNEL 1 |

Observations (all single runs):
- **ESCALATE dominates both sides** (64% of attack commands, 76% of benign), almost all from NAVIGATOR's 0.50 grey threshold. A dataset that only counts BLOCK versus ALLOW will under-report that.
- Of the 17 attack items that were ALLOWed, most are defense-evasion and lateral-movement (for example T1562.001, T1070.001, T1218.013). Those are candidate misses, subject to label review.
- A larger pilot of 400 random tldr commands gave 6 BLOCK / 298 ESCALATE / 96 ALLOW; 100 SWE-agent trajectories (786 single-line non-built-in commands) gave 4 BLOCK / 729 ESCALATE / 53 ALLOW. The 4 BLOCKs were all `ci-workflow-run-block` firing on `open .github/workflows/release.yml`, the same over-broad rule flagged in `docs/definition-catalog-audit.md`.
- The ESCALATE rate on ordinary benign commands (75-93% in these samples) is by itself a significant finding about the MVP, independent of this dataset.

## 7. Gaps and what I could not verify

1. **No independent CHANNEL data.** Read-then-send exfiltration examples exist publicly mainly in InjecAgent/AgentDojo-derived sets, which we used (and R-Judge copies them). Independent options (AgentHarm exfiltration-style behaviours, ASB data-stealing goals, Agent-SafetyBench) need an agent harness to produce calls. **Unresolved.**
2. **No independent VAULT secret-format data in hand.** CredData is credible and Apache-2.0 but needs a network-heavy download script and per-source licence review; I did not run it. It also supplies code lines rather than tool calls, so converting them requires an assumption about how a secret appears in a call.
3. **NAVIGATOR semantics.** The command datasets exercise NAVIGATOR only weakly (it matches text). Behaviours from AgentHarm or Agent-SafetyBench would be a better test but need an agent.
4. **Size.** 106 attack and 150 benign items support only coarse conclusions; 17 ALLOWs out of 106 has a wide uncertainty band.
5. **Sources I did not fully inspect:** PayloadsAllTheThings, ToolEmu, xLAM, MCP benchmarks, and the full SWE-agent dataset (100 of 80,036 trajectories sampled).
6. **R-Judge's licence:** none is published. Reuse should wait for the authors' permission.
7. **Human review.** No label here has been checked by a person. The review protocol and reviewers are an open decision.

## 8. Decisions and next steps

1. **Ask the rule authors**, in writing, whether Caldera `stockpile`, tldr-pages, the SWE-agent trajectories, AgentHarm behaviours or ASB were consulted during rule, corpus or threshold work. Their answer decides whether any dataset can eventually be marked held out.
2. **Approve the label semantics** in §5.2 (especially treating discovery/collection as dual-use and excluding it from Part A).
3. **Approve the format mapping** in §5.3, then add a small loader and registry entries (with the new role/flag) in `evaluation/`. I have not done this.
4. **Plan a label review** of all 256 items by at least one person who did not write the rules, recording reviewer and date.
5. **Decide whether to run Phase 2:** an agent harness for AgentHarm, ASB or Agent-SafetyBench, and the CredData download for VAULT. Both are larger efforts.
6. **Keep the existing caveat:** every run on these data stays a smoke test until items 1 and 4 are done.

## 9. Reproduction notes

Shallow clones and API calls to the commits above, parsed with PyYAML (Caldera abilities) and a line parser (tldr `- description` followed by a backticked command). ATT&CK status checks used the same Enterprise v19.2 bundle as `docs/definition-review-batch-1.md`. The scratch scripts are not in the repo; the selection rules in §5.1 are sufficient to regenerate the lists. The tldr repository changes daily, so use the pinned SHA, not `main`.

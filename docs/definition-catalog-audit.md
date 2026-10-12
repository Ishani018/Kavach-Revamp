# Audit of the imported minister-definition catalogue

Read-only audit of `public.minister_definitions` (1,944 records) in the Supabase project `kavach`.
Nothing was changed, validated, deleted, re-imported or committed. No credentials appear in this report.

**Labels used throughout:** **Confirmed** = established by a check I ran and can reproduce. **Suspected** = looks wrong or risky, needs a human. **Uncertain** = I could not establish it from the evidence available.

## 0. Method and limits

- **Remote vs. manifest.** I did not page through all 1,944 remote rows. I computed one digest over `record_key, content_hash, minister, definition_type, origin_status, review_status, source_citation` on both sides (through the Supabase connector, `SELECT` only). The digests were identical, so the analysis below runs on `supabase/seed/manifest.jsonl`, which therefore describes the remote table exactly. The local environment held no Supabase credentials, so the revoked-key situation did not arise.
- **ATT&CK check.** Technique IDs were checked for *existence and revocation status* against MITRE's published Enterprise ATT&CK data (v19.2, modified 2026-08-05, downloaded from `mitre-attack/attack-stix-data` during this audit). That shows an ID exists. It does **not** show the rule or pattern is a correct example of that technique.
- **Not checked:** CWE IDs, OWASP Agentic references, ATLAS IDs, Mobile/ICS ATT&CK. These are labelled "unchecked".
- **Similarity** uses token-set Jaccard on L1+L2+L3 text. It finds copies and paraphrases, not semantic conflicts.
- **Behavioural checks** ran the 127 current VAULT/EXECUTOR regexes over 392 benign strings (55 + 22-session + 25-probe sets from the repo). That is a small sample; absence of a hit proves little.
- **Nothing here validates a record.** "Active ATT&CK ID" means only that the ID exists.

## 1. Status picture: what is active and what is not

`origin_status` says where a definition lives, not that it is correct. All 1,944 rows are `unreviewed`.

| origin_status | rows | What it is |
|---|---:|---|
| current_mvp | 294 | NAVIGATOR corpus (100) + thresholds (1); 127 VAULT/EXECUTOR regex rules; 14 parser tables; CHANNEL sets (52) |
| legacy_main | 510 | VAULT/EXECUTOR/CHANNEL v1 corpus patterns (402), technical corpus (200)*, router descriptions (4), legacy thresholds (4) |
| candidate | 242 | corpus_v2 batches, NAVIGATOR candidates, proposals |
| experimental | 95 | "proposed" VAULT/EXECUTOR rules (85), authflow tables (5), tier lists (4+1) |
| historical | 803 | ORIGINAL and CHECKPOINT copies of the v1 corpus |

*The technical corpus (200 patterns) is in `legacy_main` but the legacy loader has its load call commented out, so it may never have been active. **Uncertain** whether it ever ran in production.

**Must not be treated as active (Confirmed by source notes and loader):**

- All 1,647 `corpus_pattern` rows other than the 100 NAVIGATOR `current_mvp` ones. The MVP loads only the NAVIGATOR corpus. The VAULT/EXECUTOR/CHANNEL corpus patterns (402 live copies) are inert in the MVP, which uses rules for those ministers.
- `minister_description` rows (4): the legacy router text. The NAVIGATOR one describes session trajectory, which the MVP excludes.
- `threshold_config` rows tagged `legacy_main` or `experimental`. Only `mvp-navigator-thresholds` is live.
- All `navigator_authflow_taxonomy` and `navigator_tier_rule` rows (experimental, never in the MVP).

**The `candidate` label is partly stale (Confirmed).** Of 242 candidates:

| Group | Rows | Finding |
|---|---:|---|
| `new_patterns_{vault,channel,navigator}.json`, `new_patterns_executor.json` | 125 | Content hash is **identical** to live v1 entries (e.g. `EXEC-051..100`, `NAV-051..075`). Already merged; "candidate" is outdated. |
| `new_patterns_*_b.json` | 75 | **Not merged**, and their IDs (`VAULT-076..100`, `CHAN-076..100`, `NAV-076..100`) are already used in live v1 for *different* content. See section 3. |
| `navigator_candidates_v0.json` | 34 | Unmerged, IDs `NAV-101..134`. |
| `proposed_corpus_additions_v0.json` + `patterns.json` | 8 | `CHAN-102` is near-identical (Jaccard 1.0) to live `CHAN-102`; the other six proposals reuse `NAV-101..106`. |

**The `experimental` rule label is partly stale too (Confirmed).** 84 of the 85 "PROPOSED" VAULT/EXECUTOR rules share a name with a `current_mvp` rule, and 82 have an identical regex. They were evidently merged after the proposal file was written. Two diverge: `windows-run-key-write` and `json-token-shape-grep` (the proposal file escapes backslashes differently from the live rule, so the two match different strings). One, `interpreter-inline-eval-flag`, has no live counterpart.

## 2. Provenance

No row has a `source_url` or `source_license` (all 1,944 null; Confirmed). The importer deliberately did not guess.

Citation quality by origin (counts of rows):

| Evidence class | current_mvp | legacy_main | candidate | experimental | historical |
|---|---:|---:|---:|---:|---:|
| ATT&CK ID, exists and active | 178 | 456 | 171 | 0 | 673 |
| ATT&CK ID, **revoked/deprecated** in v19.2 | 5 | 9 | 3 | 0 | 14 |
| ATT&CK ID **not found** in Enterprise v19.2 | 2 | 2 | 0 | 0 | 2 |
| CWE ID (unchecked) | 12 | 17 | 7 | 0 | 24 |
| OWASP "Agentic 2026 Axx" (unchecked) | 30 | 17 | 50 | 0 | 88 |
| ATLAS ID only (unchecked) | 0 | 0 | 3 | 0 | 0 |
| Free text / internal reference only | 0 | 1 | 1 | 85 | 2 |
| **No citation at all** | **67** | 8 | 7 | 10 | 0 |

**Reading this table:**

- **Best-evidenced:** NAVIGATOR's live corpus (100/100 have an ATT&CK, CWE or OWASP reference) and the VAULT rules (T1552.x, T1555.x, T1003.x).
- **Weakest:** the 67 `current_mvp` rows with no citation are the CHANNEL tool/behaviour sets and the parser tables, plus NAVIGATOR/CHANNEL constants and thresholds. CHANNEL has **zero** citations in its active definitions. The 85 experimental rules cite only an internal corpus ID (e.g. `EXEC-033`), which is a pointer to another unverified record, not evidence.
- **Non-ATT&CK technique IDs:** the `technique_ids` column mixes CWE and `A01`-style OWASP codes with ATT&CK IDs (e.g. `A01` ×104). **Suspected** problem for any query that assumes ATT&CK-only values.
- **OWASP naming (Uncertain):** records cite "OWASP Agentic 2026 A01…A09", while OWASP's agentic list may use a different ID scheme. I could not confirm the correct names from the data on hand; verify against OWASP's published document before relying on those labels.

**Authoritative sources worth using for later verification:** MITRE ATT&CK (technique pages and the STIX data used here), MITRE CWE, OWASP's agentic-AI Top 10, MITRE ATLAS (for the `AML.T…` IDs), vendor documentation for credential/token formats (AWS, GitHub, npm, PyPI, Kubernetes, Docker), LOLBAS and GTFOBins for living-off-the-land binaries, and the gitleaks/trufflehog rule sets (the code comments say the VAULT patterns were *modelled on* them, which is a lead, not verification).

## 3. Duplicates and conflicts

**Exact duplicates (Confirmed):** 402 groups, 1,329 rows (927 surplus copies) share a content hash within the same minister and type. Breakdown:

| Group shape | Groups | Assessment |
|---|---:|---|
| live v1 = CHECKPOINT = ORIGINAL | 275 | **Harmless**: three copies of the same file |
| the above + a merged `new_patterns_*` batch | 125 | **Harmless**: merge provenance (shows which batch the live row came from) |
| live v1 = CHECKPOINT only | 2 | Harmless; `CHAN-101` and `CHAN-102` changed after ORIGINAL |

ORIGINAL vs live: exactly **one** changed definition (`CHAN-101`: the `rationale` and `source` fields were filled in) and one added (`CHAN-102`). The live file and the CHECKPOINT file have identical content.

**Same ID, different content (Confirmed): potential conflicts, need a human**

| Collision | Records | Concern |
|---|---:|---|
| `*-076..100` in `new_patterns_*_b.json` vs live v1 | 75 | The batch's content appears nowhere in live v1 (no entry above Jaccard 0.6). Merging the batch as-is would overwrite or clash with 75 live IDs. Example: `VAULT-076`. |
| `NAV-101..106` in `proposed_corpus_additions_v0` vs `navigator_candidates_v0` | 6 | Two different candidate sets use the same IDs. |
| `CHAN-102`: live, proposal and `patterns.json` | 3 | Same idea, three versions with different hashes. Live is near-identical (Jaccard 1.0) to the others, so likely wording edits. **Uncertain** which is canonical. |

**Near-duplicates inside live v1 (Confirmed none at the checked threshold):** no pair of live patterns within a minister reaches Jaccard 0.7, none across ministers reaches 0.6, and no two patterns share identical L3 text. The live corpus is internally diverse. (Only 1 of 99 VAULT categories and 9 of 91 EXECUTOR categories has more than one member, as the repo's own notes also say.)

**Cross-rule overlap (Suspected, not tested):** many current rules cover adjacent techniques (e.g. `curl-pipe-shell`, `wget-pipe-shell`, `remote-payload-download-tool`, `certutil-download`). Overlap is harmless for blocking but means individual rules are not independent evidence of coverage.

## 4. Accuracy risks

### Confirmed

1. **Technique IDs that do not exist in Enterprise ATT&CK v19.2: 6 rows.**
   - `T1546.999` on the two current EXECUTOR rules `git-hook-file-write` and `git-hookspath-config`. The `.999` suffix is not a real sub-technique.
   - `T1559.004` on `CHAN-038` and its copies (4 rows). It may exist in another ATT&CK matrix; I only checked Enterprise.
2. **Revoked IDs (31 rows)**, where MITRE has since replaced them. Active-MVP examples: `NAV-009` and `NAV-050` cite `T1562` (now `T1685`), `NAV-030` cites `T1562.006` (now `T1685`), `NAV-038` cites `T1562.004` (now `T1686`), and `NAV-022` cites `T1070.002` (now `T1685.006`). Other revoked IDs are `T1215` (→ `T1547.006`). This is "outdated", not necessarily wrong when written; ATT&CK data changed after the corpus was built.
3. **An active rule fires on a documented benign boundary case:** EXECUTOR `bitsadmin-transfer` matched the curated probe "use bitsadmin /transfer to download an approved Windows Update". That probe was designed as a legitimate-use case, so this is a likely false positive. It is the only current rule that fired on the 392 benign strings.
4. **Rules that match a mere mention of a path (not a write):** `git-hook-file-write` matches `ls .git/hooks/pre-commit`; `ci-workflow-run-block` matches `cat .github/workflows/ci.yml`. Both fire on read-only commands despite names implying writes or runs. Whether that is intended is for a human to decide.
5. **Excluded-component references inside the active NAVIGATOR corpus:** 8 live patterns (`NAV-001`, `-052`, `-066`, `-075`, `-079`, `-083`, `-086`, `-087`) mention COMPASS, trajectory, intent drift or similar. `NAV-001` (`session_intent_drift`) describes COMPASS cosine similarity, a component the MVP does not have, yet the pattern is loaded and can match text.
6. **Rationale is missing** on 207 corpus rows (200 are the technical corpus, which has no rationale field at all; 7 are proposals).
7. **Regex hygiene is clean:** all 212 rules compile, none matches the empty string, and there are no duplicate rule names within the current set.

### Suspected (need human review)

- **Tag fit looks weak for some current rules** (ID exists, but the technique name doesn't obviously describe the rule): `proc-environ-multi-pid` → T1552.003 *Shell History*; `cloud-credential-cli-read` (Azure CLI token/key listing) → T1552.005 *Cloud Instance Metadata API*; `kerberos-ticket-cache` → T1558.004 *AS-REP Roasting*; `curl-pipe-shell` → CWE-78 (OS command injection; T1059.004/T1105 would describe download-and-execute better); `sts-assume-role-cmd` → T1550.001.
- **Questionable minister assignment:** VAULT holds `dns-exfil-tool-call` (T1048.003, an exfiltration technique, closer to CHANNEL) and `ssh-agent-socket-hijack` (T1563.001, lateral movement). EXECUTOR holds `ssh-authorized-keys-append` and `sts-assume-role-cmd`, which are credential/identity concerns. About 11 of the 100 live NAVIGATOR patterns and 14 of the 102 live CHANNEL patterns have L3 text containing credential-related keywords (examples: `NAV-007`, `NAV-014`, `CHAN-013`); the NAVIGATOR count varies with the keyword list used (11 to 20). This is a keyword heuristic only.
- **CHANNEL source-tool list looks benchmark-specific:** all 32 `channel_source_tool` entries are vendor-prefixed InjecAgent tool names (`AmazonViewSavedAddresses`, `BankManagerGetAccountInformation`, …); the code adds generic matching on top, but the exact list may reflect the benchmark rather than real tool surfaces. `DESTINATION_ALLOWLIST` is empty.
- **Possible over-breadth** in short patterns (`direnv-envrc-write`, `pypirc-token`, `dotenv-outside-workspace`). Not tested for false positives beyond the small benign sample.
- **Outdated tool coupling:** the technical corpus embeds concrete benchmark tool names, so its relevance to other agents is **uncertain**.

### Uncertain

- Whether any L1/L2/L3 text is factually wrong. I did not read the 1,647 patterns individually.
- Whether OWASP, CWE and ATLAS references are accurate.
- Whether the 8 COMPASS-flavoured NAVIGATOR patterns help or hurt in the MVP.

## 5. Coverage by minister

| Minister | Active (current_mvp) | Also in catalogue | Weakest evidence |
|---|---|---|---|
| **VAULT** | 63 regex rules (nearly all T1552.x/T1555.x/T1003.x, well-tagged); 3 credential-path parser regexes | 150 live corpus patterns (inert in MVP), 200 historical, 50 candidates, 49 experimental rules (mostly merged) | Parser regexes have no citation; a handful of tag-fit doubts above |
| **EXECUTOR** | 64 regex rules (T1059, T1105, T1218, T1543, T1546, T1547, T1574, CWE-78/95/502); 11 fetch-to-disk parser regexes; AST call tables | 150 live corpus patterns (inert), 200 historical, 50 candidates, 36 experimental rules | 2 nonexistent IDs; `curl-pipe-shell` CWE fit; one benign hit (`bitsadmin-transfer`); the AST tables and parser regexes are uncited |
| **CHANNEL** | 32 source tools, 10 destination tools, 4 source-matching rule sets, 6 behaviour constants | 152 live corpus patterns (inert in MVP), 203 historical, 52 candidates | **No citation on any active CHANNEL definition**; list looks benchmark-derived; 14 corpus patterns look credential-oriented |
| **NAVIGATOR** | 100 live corpus patterns (all cited: 69 ATT&CK, 30 OWASP, 1 CWE; 5 cite revoked ATT&CK IDs), MVP thresholds | 50 legacy technical patterns, 200 historical, 90 candidates (34 unmerged v0, 50 merged, 6 conflicting), authflow/tier experiments | COMPASS-flavoured patterns; revoked IDs; 5-sentence legacy description that references trajectory |

**Where evidence is weakest, in order:** CHANNEL (no citations, benchmark-derived lists) → EXECUTOR/VAULT parser tables and constants (code, no citation) → NAVIGATOR (cited, but semantic matching is the least inspectable) → corpus patterns that are inert in the MVP.

## 6. Where review should start

Priority = active in the MVP × can cause a block or an allow × has an authoritative reference you can actually check.

### First batch (about 35 records)

Record keys follow `MINISTER|type|id|ref:path`. Abbreviated here by rule name; look them up with `definition_id`.

**A. Fix-first: wrong or outdated references on active definitions (7)**
`git-hook-file-write`, `git-hookspath-config` (nonexistent `T1546.999`); `NAV-009`, `NAV-022`, `NAV-030`, `NAV-038`, `NAV-050` (revoked IDs). Mapping is checkable against MITRE in minutes, and the corrections are unambiguous or near-unambiguous. (`CHAN-038`'s `T1559.004` is legacy-only, so lower urgency.)

**B. VAULT, format-specific rules with authoritative documentation (10)**
`aws-access-key-id`, `private-key-block`, `ssh-private-key-path`, `aws-credentials-file`, `etc-shadow-sam-ntds`, `lsass-memory-dump`, `k8s-serviceaccount-token`, `cloud-metadata-imds`, `npm-token-rc`, `pypirc-token`.
Authorities: AWS/Kubernetes/npm/PyPI documentation, RFC 7468 (PEM), MITRE T1552/T1003. These have exact, documentable formats, so a reviewer can confirm both the regex and the tag.

**C. EXECUTOR, widely documented hazards (10)**
`curl-pipe-shell` (also review the CWE-78 tag), `wget-pipe-shell`, `os-system-call`, `subprocess-shell-true`, `python-eval-exec`, `pickle-loads-untrusted`, `yaml-load-unsafe`, `powershell-encoded`, `nc-reverse-shell`, `sudoers-write`.
Authorities: MITRE CWE-78/95/502, Python documentation (pickle/yaml warnings), LOLBAS. Also re-examine `bitsadmin-transfer` against LOLBAS and the Windows Update boundary case (likely false positive).

**D. Over-breadth review (2 rules)**
`ci-workflow-run-block`, `git-hook-file-write` (match read-only commands).

**E. CHANNEL, first source check (6)**
The 10 destination tools and the `SOURCE_TOOL_PATTERN` / verb / noun sets, validated against the actual tool surfaces they were written for. Start with `send_email`, `send_money`, `GmailSendEmail`, `post_webpage`. CHANNEL has no external standard to cite; the evidence will have to be real tool schemas, so this batch is smaller and slower.

**Then, second batch:** the 100 NAVIGATOR live patterns (start with the 8 COMPASS-flavoured ones), the 75 conflicting `_b` IDs (resolve before any merge), and the 5 suspected tag-fit mismatches.

## 7. Proposed review workflow

1. **Freeze scope.** Review only `current_mvp` rows first. Treat `legacy_main`, `candidate`, `experimental` and `historical` as read-only context.
2. **Per record, a reviewer records:** the authoritative URL, the exact reference (e.g. technique ID and version, CWE number, vendor doc section), whether the definition matches what the reference describes, and any benign counter-example. Review the *definition* against the *source*, not against another Kavach record.
3. **Outcome → status.** `unreviewed → in_review` when claimed; `source_verified` only when a reviewer has cited a checked URL and the definition matches it; `validated` only after a separate behavioural test (benign set plus positive cases); `approved` only by a named owner; `rejected` with a reason. Never set these in bulk.
4. **Where evidence lives.** The table has no reviewer or evidence columns. Until one is added (a separate, later decision), keep evidence in the repo (e.g. a review log file keyed by `record_key`) and link it from Supabase notes only after you decide how.
5. **Resolve conflicts before merges.** Decide the canonical definition for the 75 colliding `_b` IDs, the `NAV-101..106` pair and `CHAN-102`; renumber or retire the losers. Never edit by ID reuse.
6. **Re-run this audit's checks** after each batch: the ATT&CK existence check, the benign-string sweep, and the duplicate scan. They are cheap and repeatable.
7. **Don't promote by resemblance.** A rule that resembles a known security rule is a lead, not verification.

## 8. Findings in one line each

- All rows are `unreviewed`; none has a source URL or licence.
- 1,478 rows cite a currently active ATT&CK ID, but that only shows the ID exists.
- 67 active definitions, including everything in CHANNEL, have no citation.
- 6 rows cite nonexistent technique IDs (2 are active EXECUTOR rules); 31 cite revoked ones (5 are active).
- 927 surplus rows are copies; most are harmless, but 75 candidate rows collide with live IDs and are real conflicts.
- Candidate and experimental labels are partly stale: 125 candidates and 84 experimental rules are already in the live set.
- 1 active rule hit a documented benign case; 2 active rules match read-only mentions.

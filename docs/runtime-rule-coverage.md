# Kavach MVP: runtime rule coverage

Inventory of what the current MVP code actually loads and executes, and how that relates to the 1,944-record Supabase catalogue. Inventory only: no code, Supabase record, status, dependency or other file was changed, and nothing was committed.

**How to read this.** Each statement is labelled where it matters. **Verified** = established by reading the code and/or executing it; I can point to the file and function. **Estimate** = my own counting convention or a heuristic, stated as such. Paths are relative to the repo root; the code state is branch `mvp-core` at 328bd83 with no uncommitted changes under `kavach/`.

## 1. Request path, and what is *not* in it

- `kavach/api.py: build_default_coordinator()` builds exactly four ministers: `VaultMinister`, `ExecutorMinister`, `ChannelMinister`, `NavigatorMinister`. `kavach/coordinator.py: Coordinator.evaluate()` calls all four on every request, then `kavach/speaker.py: decide()`. **Verified.**
- Each minister reads its rules from **Python modules and one JSON file in the repo**. **Nothing reads Supabase.** A search of `kavach/` for `supabase`, `psycopg`, `httpx`, `requests` and `urllib` finds no runtime use (the only `requests`/`urllib` hits are inside regex text and corpus content). **Verified.**
- Ministers receive a `ToolCall` (`kavach/schemas.py`). VAULT, EXECUTOR and NAVIGATOR look at the tool name and arguments; CHANNEL also reads three optional `context` keys (`account_email`, `user_instruction`, `tool_output`). Neither the catalogue nor the Speaker changes what a minister decides. **Verified.**

## 2. Summary table

| Minister | Runtime rule source | Mechanism | Unique active units (see §3 for how counted) | Verdicts it can emit |
|---|---|---|---|---|
| VAULT | `VAULT_PATTERNS` (63 regexes) + structural credential-path detector, both in `kavach/ministers/prefilters.py` / `struct_parse.py` | Deterministic | 63 regex rules + 1 structural detector | BLOCK only (confidence fixed 1.0) |
| EXECUTOR | `EXECUTOR_DENYLIST` (64 regexes) + AST call resolver + structural fetch-to-disk detector | Deterministic | 64 regex rules + 1 AST extension + 1 structural detector | BLOCK only (1.0) |
| CHANNEL | Static tool lists and token sets in `channel_taint.py` + per-session state | Deterministic, stateful, with keyword/shape heuristics | Not a rule list; 2 mechanisms over 32 + 10 named tools and generic fallbacks | BLOCK (taint), ESCALATE (provenance) |
| NAVIGATOR | 100 patterns from `kavach/data/kavach_corpus_v1.json` → 300 embedded documents | Similarity-based (dense BGE + BM25 lexical gate) | 100 patterns / 300 documents | BLOCK / ESCALATE / ALLOW by score |

Which catalogue rows are the active ones: see §4.

---

## 3. Per-minister findings

### 3.1 VAULT

**Rule sources loaded at runtime (Verified)**
- `kavach/ministers/vault.py: VaultMinister.check()` builds a `ParsedCall` and calls `prefilters.check_vault()` (`kavach/ministers/prefilters.py:549`).
- `check_vault` runs two layers over the haystack `[tool_name] + every argument value` (`_flatten_arg_values`, which walks nested dicts and lists):
  1. `VAULT_PATTERNS` (`prefilters.py:126`), first match wins, returns BLOCK.
  2. Structural fallback over argument values (not the tool name): `ast_parse.has_credential_path()` if the tool name is `sh` or `bash` (`_AST_FAST_DIALECTS`, `prefilters.py:52`), otherwise `struct_parse.has_credential_path()` (`struct_parse.py:355`). Both ultimately use `struct_parse._is_credential_path` with the regexes `_CRED_PATH_STRONG`, `_CRED_EXT`, `_PATH_SHAPED` and `_PATH_RE`, plus `_CRED_GLOB_RE`.

**How I counted.** I imported the live module and measured `VAULT_PATTERNS`: **63 entries, 63 unique names, 63 unique (pattern, flags) pairs**, no regex shared with any EXECUTOR rule. **Verified.**
- *Estimate:* if you count top-level `|` alternatives inside each regex as separate patterns, the total is about **136** (my own parse; ignores nested alternation). Not a figure used elsewhere in this report.
- *Convention:* I count the structural credential-path detector as **one** rule unit (it is one predicate; its main regex has 10 top-level alternatives, `_CRED_GLOB_RE` has 2).

**Nature: deterministic.** Pure regex and token-structure matching; no scores, no state. It can only BLOCK (confidence 1.0) or return nothing (reported as ALLOW). **Verified** (`check_vault` returns `MinisterScan(verdict="BLOCK", confidence=1.0)` or `None`).

**Notes that affect real coverage (Verified from code)**
- AST-backed tokenizing (bashlex) happens only when the tool name is exactly `sh` or `bash`. Any other tool name (`Bash`, `shell`, `run_command`, `python`) goes through the simple tokenizer `struct_parse._shell_tokenize`.
- The tool *name* is scanned by the regex layer only, never by the structural layer.

### 3.2 EXECUTOR

**Rule sources loaded at runtime (Verified)**
- `kavach/ministers/executor.py: ExecutorMinister.check()` → `prefilters.check_executor()` (`prefilters.py:1070`), three layers in order, first hit wins:
  1. `EXECUTOR_DENYLIST` (`prefilters.py:596`) over tool name + all argument values.
  2. `_check_executor_ast()` (`prefilters.py:1018`): parses each string as Python, resolves import aliases (`_build_alias_map`, `_resolve_call_name`), and flags calls in `_AST_DANGEROUS_CALLS` (`eval`, `exec`, `os.system`, mapped to existing rule names) and `subprocess.{run,Popen,call,check_output}` with `shell=True` (`_AST_SUBPROCESS_FUNCS`).
  3. Structural fetch-to-disk (E1): `ast_parse.is_network_fetch_to_disk()` for `sh`/`bash`, else `struct_parse.is_network_fetch_to_disk()` (`struct_parse.py:323`), with a payload-staging gate (`_needs_staging_gate`, `_url_fetch_is_payload_staging`) so that plain `curl url -o data.json` is not flagged.

**How I counted.** `EXECUTOR_DENYLIST`: **64 entries, 64 unique names, 64 unique (pattern, flags)**. **Verified.** *Convention:* the AST resolver is one extension unit (its four outcomes reuse existing rule names: `python-eval-exec`, `os-system-call`, `subprocess-shell-true`), and the E1 structural detector is one more unit. *Estimate:* ~107 top-level regex alternatives across the 64 rules.

**Nature: deterministic.** BLOCK only, confidence 1.0.

### 3.3 CHANNEL

**Rule sources loaded at runtime (Verified)**
- `kavach/ministers/channel.py: ChannelMinister.check()` runs, per `session_id`, `channel_taint.check_channel_taint()` (`channel_taint.py:427`) and `channel_taint.check_provenance()` (`channel_taint.py:723`), then applies the composition rule (a taint BLOCK is overridden only when provenance classifies *every* destination as `SELF` or `USER_SUPPLIED`).
- Static data they use:
  - `SOURCE_TOOLS_EXACT` (32 names), `SOURCE_TOOL_PATTERN` (regex over a 24-noun list and 6 verbs), `_SENSITIVE_NOUN_TOKENS` (35), `_SENSITIVE_NOUN_BIGRAMS` (8), `_SOURCE_VERB_TOKENS` (6), all consumed by `is_source_tool()` (`channel_taint.py:219`).
  - `DESTINATION_TOOLS` (10 tools → argument keys), `is_destination_tool()` (`:281`), `_destination_values()` (`:285`).
  - Generic fallback `_general_destination_values()` (`:294`): for any tool *not* in `DESTINATION_TOOLS`, every argument value matching `_EMAIL_RE`, `_IBAN_RE`, `_PHONE_RE` or `_URL_RE` counts as a destination (ISO dates are excluded via `_ISO_DATE_RE`).
  - `DESTINATION_ALLOWLIST` (empty `frozenset`) and `_EMAIL_DESTINATION_TOOLS` (3 tools) in `_destination_allowed()` (`:396`).
- Per-session state is held in two dicts inside `ChannelMinister` (`_taint`, `_provenance`); in-memory, unbounded, lost on restart.

**How I counted.** CHANNEL is not a list of rules, so a "rule count" would mislead. What exists: **2 mechanisms** (taint, provenance), **32 + 10 named tools**, and generic recognisers for source and destination tools. Neither the 152 legacy CHANNEL corpus patterns nor any corpus file is read. **Verified** (no code path loads the CHANNEL corpus section).

**Nature: deterministic but stateful and heuristic in recognition.**
- Taint: a session becomes tainted when a call's tool is recognised as a source tool; any later call to a destination tool (or, via the generic fallback, any tool with a destination-shaped value) with a non-allowlisted destination returns BLOCK (1.0). The detector is exact; *recognition* of "sensitive source tool" is a naming heuristic.
- Provenance: classifies each destination value as `SELF`, `USER_SUPPLIED`, `OUTPUT_DERIVED` or `NOVEL`; the latter two return ESCALATE (1.0). **Verified:** with no `user_instruction`/`tool_output` context, any call carrying an email/URL/IBAN/phone-shaped value is `NOVEL` and escalates.

### 3.4 NAVIGATOR

**Rule source loaded at runtime (Verified)**
- `kavach/ministers/navigator.py: NavigatorMinister.__init__()` (line 46) reads `CORPUS_PATH = kavach/data/kavach_corpus_v1.json` and uses only `corpus["NAVIGATOR"]["patterns"]` (line 53). The file's other sections (`COMPASS`, `EXECUTOR`, `VAULT`, `CHANNEL`) are never read.
- `_ensure_collection()` (line 66) embeds each pattern's `L1_intent`, `L2_mechanism` and `L3_surface` as separate documents into a persistent ChromaDB collection (default `./.chroma_navigator`, overridable with `KAVACH_CHROMA_PATH`), and `retrieval.build_bm25_index()` builds a BM25 index over the same documents.
- `check()` (line 100) calls `retrieval.run_minister_hybrid()` (`retrieval.py:223`) on the wire text `tool:NAME args:{json}` with `THRESHOLDS = {block: 0.70, grey: 0.50}`, `TOP_K = 10`, embedding model `BAAI/bge-base-en-v1.5`.

**How I counted.** I instantiated the real minister and inspected it: **100 patterns (100 unique ids, 98 categories) × 3 levels = 300 documents; ChromaDB count 300; BM25 corpus size 300; 300 unique document texts.** **Verified.** Every pattern has all three levels.

**Nature: similarity-based.** The score is `dense cosine × lexical gate` (BM25 evidence scales it between `KAVACH_BM25_GATE_FLOOR`, default 0.65, and 1.0); RRF selects the candidate (`retrieval.py:223` onward). Verdict by score: ≥0.70 BLOCK, ≥0.50 ESCALATE, else ALLOW. If `rank_bm25` is missing it silently falls back to dense-only (`run_minister`, `retrieval.py:140`). **Verified** from code.

---

## 4. Catalogue ↔ runtime correspondence

**Method.** I compared the live modules against the catalogue's `current_mvp` rows and classified every row by content hash and regex equality. **Verified:** the 127 runtime rules (63 + 64, compared on name, pattern, flags and tag) are identical to the 127 `current_mvp` rule records; the 14 parser-pattern records match the live constants; the 100 NAVIGATOR patterns match the file.

Classification of all 1,944 records (each record is in exactly one class):

| Class | VAULT | EXECUTOR | CHANNEL | NAVIGATOR | Total |
|---|---:|---:|---:|---:|---:|
| **A. Active at runtime** (executed by the MVP) | 66 | 75 | 52 | 101 | **294** |
| B. Exact copy of an active record (other file/ref) | 0 | 0 | 0 | 225 | 225 |
| C. "Proposed" rule with the same regex as an active rule | 48 | 34 | 0 | 0 | 82 |
| D. Legacy corpus pattern, not loaded by the MVP | 150 | 150 | 152 | 50 | 502 |
| E. Exact copy of a legacy corpus pattern (ORIGINAL, CHECKPOINT, merged batches) | 225 | 250 | 227 | 0 | 702 |
| F. Historical, differs from every other record | 0 | 0 | 1 | 0 | 1 |
| G. Candidate not merged (distinct content) | 25 | 0 | 27 | 65 | 117 |
| H. Experimental (not wired) | 1 | 2 | 0 | 10 | 13 |
| I. Reference/config data (not executed) | 2 | 2 | 2 | 2 | 8 |
| **Total** | 517 | 513 | 461 | 453 | **1,944** |

**What the active class contains**

| Minister | Active records | Breakdown |
|---|---:|---|
| VAULT | 66 | 63 `deterministic_rule` + 3 `parser_pattern` (`_CRED_PATH_STRONG`, `_CRED_EXT`, `_CRED_GLOB_RE`) |
| EXECUTOR | 75 | 64 `deterministic_rule` + 11 `parser_pattern` (fetch-to-disk regexes and AST call tables) |
| CHANNEL | 52 | 32 `channel_source_tool`, 10 `channel_destination_tool`, 4 `channel_source_rule`, 6 `channel_behavior` |
| NAVIGATOR | 101 | 100 `corpus_pattern` + 1 `threshold_config` (`mvp-navigator-thresholds`) |

**Reading the other classes**
- **B (225, all NAVIGATOR):** the ORIGINAL and CHECKPOINT copies (100 each) and 25 `new_patterns_navigator` rows are byte-identical to active patterns. Harmless duplicates, but a query for "NAV-0xx" returns up to four rows for one active pattern.
- **C (82):** the "experimental" rules from `PROPOSED_vault_executor_expansion.py` whose regex is already active under the same name. Their `source_tag` is a corpus-ID pointer instead of an ATT&CK/CWE tag, which is why they hash differently from the active rule.
- **D + E (1,204 rows):** the VAULT/EXECUTOR/CHANNEL corpus patterns and the technical corpus. Verified inert: no code reads those corpus sections. They are reference material about what the rules were meant to cover.
- **G (117):** the unmerged candidates, including the 75 `_b` rows whose IDs collide with live IDs (see `docs/definition-catalog-audit.md`).
- **H (13):** the authflow taxonomy (5), tier lists (4), `TIER_FLOOR_CONFIDENCE` (1), and three proposed rules whose regex differs from the active version (`json-token-shape-grep`, `windows-run-key-write`) or has no active counterpart (`interpreter-inline-eval-flag`). None is imported by `kavach/`. **Verified.**
- **I (8):** the legacy router scope descriptions and legacy thresholds. The router and per-minister thresholds are not in the MVP. **Verified.**

**Rule-to-corpus traceability.** 85 of the 127 active rules carry a code comment `# corpus provenance: <EXEC|VAULT>-nnn (category)` in `prefilters.py` (49 VAULT rules referencing 63 distinct corpus IDs, 36 EXECUTOR rules referencing 44). This linkage lives only in source comments; **it is not in the catalogue** (the active rule records' `context` holds `primitive` and `also_present_in`, not the corpus ID). **Verified.**

---

## 5. Gaps and rules that run but are not represented accurately

**Verified gaps**

1. **Detection logic that is not catalogued.** The catalogue stores constants, not the logic that uses them. Not represented as records: `struct_parse._is_credential_path` (two-tier test: strong location OR `.pem/.key` extension on a path-shaped token), `struct_parse.extract()`, the payload-staging gate functions, `_check_executor_ast`'s alias resolution, `_general_destination_values`, `_destination_allowed`, and the whole taint and provenance state machines. Two shared constants that these depend on are also uncatalogued: `struct_parse._PATH_RE`, `struct_parse._PATH_SHAPED`, and `channel_taint._ISO_DATE_RE` (the date exclusion that changes CHANNEL behaviour). (The earlier import deliberately skipped the first two because they serve more than one minister.)
2. **Rules never fire alone from the catalogue's perspective.** The catalogue lists 127 "rules", but runtime behaviour also depends on *how the tool name routes the input*: the AST/bashlex paths apply only when the tool name is exactly `sh` or `bash`. A rule record does not say that.
3. **Dead code in the MVP tree** (defined, never called from `kavach/`): `prefilters.run_prefilters()` (`:1132`), `is_short_circuit_eligible()` (`:1184`) and `SHORT_CIRCUIT_INELIGIBLE_RULE_NAMES`. The PowerShell AST path (`ast_parse._powershell_words`, `_PS_WALK_SCRIPT`) is unreachable because `prefilters` only dispatches `sh`/`bash` to `ast_parse`.
4. **Inert corpus data ships with the product.** `kavach_corpus_v1.json` contains COMPASS pairs (100) and VAULT/EXECUTOR/CHANNEL patterns (302) that nothing reads; only the NAVIGATOR section is live.
5. **Stale-index risk in NAVIGATOR.** `_ensure_collection()` rebuilds only when the stored document count differs from the corpus count. Editing a pattern's text without changing the count leaves old embeddings in place. A `.chroma_navigator/` already exists in the repo root (created by an earlier local server run; git-ignored). **Verified from code; the staleness failure itself is not exercised.**
6. **VAULT and EXECUTOR cannot ESCALATE.** Each is BLOCK-or-nothing; the legacy "cosine ESCALATE triage" layer for the long tail was not carried over (`docs`/README already note this). So the only ESCALATE sources are CHANNEL provenance and NAVIGATOR scores.
7. **CHANNEL's generic fallback makes it broader than its lists suggest.** The 10-tool and 32-tool lists are the *named* coverage; any tool with an email/URL/IBAN/phone-shaped argument is also examined. The catalogue shows only the lists.

**Estimates and open questions**

- Whether any active regex is shadowed or unreachable behind an earlier one. I did not test this (first match wins within each list, so ordering matters). **Not established.**
- Real-world coverage. A rule existing at runtime says nothing about whether it fires on realistic input; I did not measure hit rates, false positives or recall in this inventory.
- Whether the 8 COMPASS-flavoured NAVIGATOR patterns behave sensibly now that COMPASS is gone (raised in `docs/definition-catalog-audit.md`).

## 6. Counting conventions used (so the numbers can be reproduced)

- **Regex rules:** `len(VAULT_PATTERNS)`, `len(EXECUTOR_DENYLIST)` from the imported module, checked for duplicate names and duplicate (pattern, flags).
- **Rule units:** one regex entry = one rule; each structural or AST extension = one additional unit. These units are my convention for comparing ministers, not a count the code itself defines.
- **NAVIGATOR:** patterns = entries in `corpus["NAVIGATOR"]["patterns"]`; documents = non-empty L1/L2/L3 fields, confirmed against the ChromaDB and BM25 counts.
- **Catalogue classification:** exact `content_hash` equality for copies, regex-text equality for rule duplicates, otherwise by `origin_status`/type. A record is "active" only if the MVP code contains an identical definition (compared programmatically).

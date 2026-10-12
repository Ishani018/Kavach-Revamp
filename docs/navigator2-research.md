# NAVIGATOR 2.0 research review

**Status: research notes written to inform the architecture in `docs/navigator2-architecture.md`. Nothing in this
file was run, installed, or copied into Kavach. Every claim below is either attributed to a fetched primary
source (with URL and fetch date) or explicitly marked as this reviewer's own judgment.** Fetched 2026-10-12 via
the arxiv.org abstract pages, the named GitHub repositories, the OWASP GenAI Security Project pages, and one
third-party abstract mirror (noted where used). Full PDFs were not downloaded or read in detail; conclusions
below are from abstracts, repository READMEs, and the GitHub issues/policy text the fetches returned. Where a
source's abstract gave no quantitative detail, that is stated rather than guessed.

## A. Microsoft FIDES — information-flow control for agents

- Paper: Costa, Köpf, Kolluri, Paverd, Russinovich, Salem, Tople, Wutschitz, Zanella-Béguelin, *"Securing AI
  Agents with Information-Flow Control"*, arXiv:2505.23643.
- Repo: `github.com/microsoft/fides` (MIT licence, tagline "Flow Integrity Deterministic Enforcement System").
- Docs: `learn.microsoft.com/en-us/agent-framework/agents/security` (not independently re-fetched this session;
  relying on the task description's characterization that Microsoft's own docs call the integration
  experimental).

**What it actually is, per the fetched abstract and repo:** a planner for AI agents that tracks confidentiality
and integrity labels on information as the agent uses tools, deterministically enforces security policies over
those labels, and includes primitives for "selectively hiding information" from the planner. The paper also
gives a formal model of what dynamic taint-tracking can and cannot guarantee, and a task taxonomy for studying
the security/utility trade-off. The repo itself is a **tutorial notebook** (`Tutorial.ipynb`) tested against
Azure OpenAI (GPT-4o/4.1) via Entra ID auth — 5 commits, 120 stars, no releases, no production disclaimer either
way (it simply doesn't claim production-readiness). The abstract reports an AgentDojo evaluation but gives no
numeric figures on the abstract page itself.

**Design lessons applied to Kavach (this reviewer's judgment, not FIDES's claim):**
- The integrity/confidentiality split as two *orthogonal* labels (not one trust score) is exactly the model
  Part 3/Component 3 of the spec asks for, and is implemented as such in `navigator2/schemas.py`
  (`IntegrityLabel`, `ConfidentialityLabel` kept as separate enums, never merged).
- FIDES's "deterministic enforcement over labels" maps to NAVIGATOR 2.0's Component 4 (policy engine): policies
  read labels and facts, not natural-language risk scores.
- **What we did not take:** FIDES is Azure-OpenAI-coupled tutorial code with no stated production posture, no
  non-Azure provider path, and no package release. Kavach's reasoner interface (Component 5) is built
  provider-neutral from scratch (own schemas, own validator) rather than importing or adapting FIDES code, both
  because importing experimental tutorial code into Kavach's production tree is out of proportion to what it
  would buy, and to avoid a hard Azure/Entra ID dependency the spec explicitly forbids introducing without
  review.

## B. CaMeL — control/data flow separation against prompt injection

- Paper: Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr, *"Defeating Prompt
  Injections by Design"*, arXiv:2503.18813 (v2, June 2025).

**Verified from the fetched abstract:** CaMeL is a protective system layer, not a model fine-tune — it stays
secure even if the underlying LLM is compromised. It explicitly separates the *control flow* and *data flow*
derived from the trusted user query, uses **capabilities** to stop private data from leaving over unauthorized
data flows, and enforces security policy at the point a tool is called. **On AgentDojo, CaMeL solves 77% of
tasks with provable security, versus 84% for an undefended agent** — i.e. a measured ~7-point utility cost for
the security guarantee, on that one benchmark. The fetched abstract page does not mention a "dual-LLM" design by
name, so that specific claim from secondary summaries is not independently confirmed here.

**Design lesson applied to Kavach (direct, load-bearing):** "untrusted data retrieved by the agent must never be
able to change the program's control flow" is implemented verbatim as NAVIGATOR 2.0's **trust boundary rule**:
`TaskContractStore.revise()` raises `UntrustedRevisionAttempt` and refuses the write whenever the proposed
revision's source event is not `IntegrityLabel.TRUSTED_INSTRUCTION` (see `navigator2/contract.py`). This is the
single most important borrowed idea in this prototype — a tool result, file, webpage, or model-generated summary
can be *read*, logged, and fed to the reasoner as evidence, but it cannot, by construction, call the one method
that would let it expand what the agent is authorized to do. This is a narrow, auditable slice of CaMeL's idea
(no interpreter-level control/data flow separation was built — that would require rewriting how the surrounding
agent harness executes code, which is out of scope for a minister-level prototype), not a reimplementation of
CaMeL's dual-flow interpreter.

## C. OWASP Agent Control Standard (ACS)

- OWASP page: `genai.owasp.org/resource/agent-control-standard-acs/`.
- Reference implementation: `github.com/GenAI-Security-Project/agent-control-standard`.

**Verified from the fetched pages:** ACS is a wire specification (v0.1.0; v0.2.0 targeted for March 2027, no
v1.0 date) in which a separate "Guardian Agent" receives hook requests from an AI agent and returns one of
`allow / deny / modify / ask / defer` before the action runs. The reference Guardian is a single TypeScript/Bun
implementation wrapping Microsoft's Agent Governance Toolkit; only 2 of its 19 hook methods are evaluated live.
**Confirmed security gaps, from the repo's own issue tracker as summarized in the fetch:** the spec requires an
HMAC-SHA256 signature on every envelope, but **the reference Guardian does not implement it** (issue #70 —
unauthenticated wire, exactly as the task brief warned); the **default failure posture is `proceed`** (fail-open)
— `ACS_ON_DECISION_FAILURE=deny` must be set explicitly to fail closed (issues #32/#37); logging is synchronous
file-append with no batching; conformance claims in v0.1.0 are self-declared and unverified.

**Design lessons applied, and explicitly NOT applied:**
- Applied: the **hook-around-the-tool-call shape** (inspect before, record after) and the **named-disposition
  vocabulary idea** (`allow/deny/ask/...`) informed NAVIGATOR 2.0's own verdict dispositions
  (`allow/escalate/block`, deliberately narrower — "modify" and "defer" are not implemented; Kavach's Speaker
  already owns the final verdict and nothing in this prototype is allowed to rewrite a proposed call's
  arguments, which is what ACS's "modify" would imply).
- Explicitly not applied: the unauthenticated wire and fail-open default are the two things the task brief said
  not to adopt blindly, and this prototype does the opposite of both by construction — there is no network wire
  at all (NAVIGATOR 2.0 runs in-process, called as a Python object, so there is nothing to authenticate), and
  every failure path in this prototype (policy engine exception, reasoner timeout, malformed structured output,
  missing event history) resolves to `escalate`, never to a silent `allow`. This mirrors Kavach's own existing
  fail-closed discipline in `kavach/coordinator.py` (`_failure()` always returns ESCALATE).

## D. AgentDojo — task-level evaluation methodology

- Repo: `github.com/ethz-spylab/agentdojo` (ETH Zurich / Invariant Labs; MIT licence; NeurIPS 2024 Datasets and
  Benchmarks track; ~911 stars at fetch time).

**Verified from the fetched README:** AgentDojo is a dynamic environment for testing LLM agents against prompt
injection, organized into **suites** (e.g. `workspace`) each containing multiple **user tasks**, runnable with
optional named defenses (e.g. `tool_filter`) and attacks (e.g. `tool_knowledge`), installed as a PyPI package
with an explicit "API is still under development and may change" notice. The README fetch did not surface an
exact total task/test-case count; the task brief's figures (97 tasks, 629 security test cases) come from the
paper itself, which was not independently re-verified by re-fetching the PDF in this session — they are recorded
here as the brief's figures, not independently re-confirmed by this reviewer.

**Design lesson applied (the methodological point, not the benchmark itself):** AgentDojo's core insight —
*judge a defense on whether the agent still completes the legitimate task while resisting the injected
instruction, as a property of the whole multi-step episode, not of any single tool call* — is the organizing
principle of Part 6 (Component: task-level evaluation). `kavach/ministers/navigator2/episodes.py` builds
Kavach's own small, hand-written episode suite in the same spirit (goal + injected content + expected per-call
and per-episode outcome), without importing AgentDojo's package, its environments, or its benchmark cases. No
AgentDojo dependency was added to `requirements.txt`.

## E. OWASP Excessive Agency (LLM06:2025)

- Page: `genai.owasp.org/llmrisk/llm062025-excessive-agency/`.

**Verified from the fetched page:** Excessive Agency is damage done through unexpected, ambiguous, or
manipulated LLM/agent output, rooted in three independent causes — **excessive functionality** (a tool can do
more than the task needs, e.g. a "read-only" tool that can also delete), **excessive permissions** (the
downstream identity has more access than the task needs), and **excessive autonomy** (high-impact actions proceed
without independent verification). Mitigations: minimize extensions and their functionality, avoid open-ended
tools (generic shell access) in favor of narrow ones, enforce least privilege at the downstream system
(**complete mediation** — authorization enforced *there*, not trusted from the LLM's own judgment), require
human approval for high-impact actions, and log/monitor/rate-limit (explicitly *not* a substitute for the above).

**Design lesson applied, and the scope boundary it draws for NAVIGATOR 2.0:** this is the source for the
explicit statement in `docs/navigator2-architecture.md` that **NAVIGATOR 2.0 is not a substitute for tool
minimization or downstream authorization** — it is a monitor sitting in front of whatever tools the agent
harness actually exposes, and it cannot retroactively narrow an over-broad tool (e.g. a generic `bash` tool).
Component 1 (Trusted Task Contract)'s `high_impact_requires_approval` set and Component 4's `POL-006`
(approval-required policy) are the concrete place this risk is handled: NAVIGATOR 2.0 requires a recorded human
approval event before allowing a contract-flagged high-impact action, rather than trying to re-derive "is this
tool too powerful" from scratch.

## F. Runtime Policy Enforcement for MCP-based LLM agents (MDPI *Electronics*)

- Wang, Zhu, Li, DOI 10.3390/electronics15132829, ISSN 2079-9292. **The MDPI page itself returned HTTP 403 to a
  direct fetch in this session**; the summary below is from a web search whose top result quoted a third-party
  abstract mirror (`citedrive.com`), not the publisher's own page, and is recorded as lower-confidence for that
  reason. It should be read as "what a search of secondary sources reports the abstract says," not as this
  reviewer having read the paper.

**Reported (via the mirror, not independently confirmed):** a Policy Enforcement Point at the tool-call
boundary, applying declarative rules over a **cross-step information-flow label system** tracking source
integrity and data sensitivity, with a SHA-256 hash-chained audit log; reported attack-success-rate reduction
from 40.0% to 35.0% (best prompt-only baseline) to 5.0% (full system) on the authors' own four-attack-class
dataset, and a 26.4-point false-negative increase when cross-step label propagation is disabled (their own
ablation, on their own data).

**Design lesson applied (the structural idea, treated as "supporting research" per the task brief, not as proof
anything numeric transfers to Kavach):** the paper's own ablation — propagation across steps is reportedly doing
most of the work, not any single-call check — is the reason `navigator2/ledger.py` and `navigator2/provenance.py`
exist as cross-call primitives at all, rather than trying to fold "did an earlier call read something private"
into a per-call feature the way the legacy NAVIGATOR corpus tries to with cross-call-shaped text in a one-call
retrieval document (see `docs/navigator-pattern-disposition-review.md §5`'s "no scalar-score fix to the existing
per-call NAVIGATOR can address [CROSS-CALL patterns]", which independently reaches the same conclusion from
Kavach's own prior audit work). The 40%→5% / 26.4-point figures are **not** used anywhere as an expected or
target number for Kavach's own evaluation; Kavach's own numbers are reported separately in
`docs/navigator2-report.md` from Kavach's own synthetic episodes only.

## G. MITRE ATLAS — AML.T0086 "Exfiltration via AI Agent Tool Invocation"

- Page: `d3fend.mitre.org/offensive-technique/attack/AML.T0086/` (an ATLAS technique, mirrored on the D3FEND
  site's offensive-technique index, not a D3FEND-native technique).

**Verified from the fetched page:** a write-capable agent tool can be made to send sensitive data to an
adversary-controlled destination (inbox, document, CRM record, generated file) by encoding the data into the
tool's own input parameters, so the outbound call looks like ordinary agent behavior. Two routes: the tool is
legitimate but invoked via prompt injection (AML.T0051), or the tool itself is poisoned (AML.T0110). The page
explicitly has **no artifacts defined yet** for this technique (i.e. no stated detection signature).

**Design lesson applied — this is the direct source for the task brief's repeated warning, and is treated as a
hard constraint, not a suggestion:** AML.T0086's own framing is "data *reaches an external destination*,"
not "data was encoded" or "a file was written locally." NAVIGATOR 2.0's evidence modules (`evidence.py`) and
policy `POL-001` (proven-exfil-to-unauthorized-destination) therefore require **both** a provenance chain back to
protected content **and** a destination evidence finding from CHANNEL's own destination/egress analysis before
reaching BLOCK — a decode operation or a local file write alone never satisfies this policy's evidence
requirement (see `navigator2/policy.py::ProvenanceExfilPolicy` and its unit tests, which include a decode-to-local-file
case that must stay at most ESCALATE, never BLOCK, absent a destination finding). This is the direct fix for the
failure mode the task brief names: "the old NAV-073 caught encoded-file writes [without] proof of exfiltration."

## What was explicitly not done in this research pass

- No PDF was fully read end-to-end for any of the seven sources; conclusions rely on abstract pages, repository
  READMEs/issues, and (for source F) a third-party abstract mirror.
- `tree-sitter-bash` (`github.com/tree-sitter/tree-sitter-bash`) was **not installed or evaluated hands-on**.
  Kavach already has a working, AST-backed shell parser in `kavach/ministers/ast_parse.py` using `bashlex`
  (already a pinned dependency, `requirements.txt`), empirically confirmed in that module's own docstring to
  handle real bash/sh syntax (and to correctly fail-over, not fail open, on cmd.exe and other dialects it
  doesn't understand). Per the task brief's own instruction — "if the repository already contains an
  established... integration, inspect it and reuse its supported interfaces" — NAVIGATOR 2.0's shell evidence
  module (`evidence.py::ShellEvidenceModule`) calls `ast_parse.extract_words` / `bashlex.parse` directly rather
  than adding a second shell-parsing dependency.
- The PowerShell-native-parser path (`System.Management.Automation.Language.Parser`) already exists in
  `ast_parse.py` too (subprocess-invoked, confirmed present on the original development machine). NAVIGATOR 2.0
  reuses it the same way for PowerShell calls; it is not re-implemented.
- No FIDES, CaMeL, ACS, or AgentDojo source code was copied, vendored, or added as a dependency. No licence
  review was needed for code because no code was taken; the ideas borrowed are cited above per source.

# NAVIGATOR runtime rebuild with Invariant Guardrails

## Decision

The active policy evaluator on this branch uses Invariant Guardrails' LocalPolicy implementation (invariant/analyzer/policy.py), distributed under Apache-2.0. Kavach imports LocalPolicy explicitly, not the environment-dependent Policy alias that may select a remote implementation.

This rebuild replaces semantic embedding retrieval as the active NAVIGATOR runtime. The former retriever and corpus remain in the repository as an optional research experiment; they are no longer imported by NavigatorMinister.

## Runtime flow

1. The existing Coordinator runs VAULT, EXECUTOR, CHANNEL and NAVIGATOR in order, then calls the unchanged Speaker.
2. The Coordinator passes already-computed specialist results to NAVIGATOR through an optional check_with_context hook. The other ministers continue using the original check(call) API.
3. NAVIGATOR builds a typed task contract, evidence findings and an append-ordered session ledger.
4. The adapter converts those structured facts into a trace accepted by Invariant. It sends fixed boolean flags, tool names and event IDs—not raw arguments, secret values, destination strings or tool-output text.
5. Invariant evaluates kavach/ministers/navigator2/policies.iv using LocalPolicy.analyze_pending(past, [current]). Rule violations become NAVIGATOR policy decisions.
6. Known violations become BLOCK or ESCALATE according to the policy table. An unrecognized policy result or interpreter error becomes ESCALATE; it cannot become implicit ALLOW.
7. NAVIGATOR returns the existing MinisterResult shape. Speaker verdict composition remains unchanged.

## Policy rules

- POL-001 — Sensitive transmit: current event is classified PRIVATE/SECRET and includes a destination outside the task contract's approved destinations → BLOCK.
- POL-002 — Workspace scope: a declared workspace scope is violated → ESCALATE.
- POL-003 — Contract integrity: untrusted content tried to revise the trusted task contract → BLOCK.
- POL-004 — Decode then execute: AST evidence confirms the structural flow → ESCALATE.
- POL-005 — Specialist hard block: a previously run specialist returned BLOCK → BLOCK.
- POL-006 — High impact: a configured high-impact action lacks a recorded, relevant approval → ESCALATE.
- POL-007 — Incomplete evidence: evidence coverage is indeterminate → ESCALATE.
- POL-008 — Explicit denial: contract explicitly denies the tool name → BLOCK.
- POL-009 — Cross-call sensitive transmit: an earlier permitted event touched a PRIVATE/SECRET artifact and current action transmits to an unapproved destination → BLOCK.

The policy rules live in the Invariant DSL; the adapter still computes structured facts. The trace uses the ledger's full earlier history, not caller-supplied parent references. POL-009 is a conservative rule and requires the earlier event to have been recorded as ALLOW with the three earlier specialist results present and ALLOW.

## Trust boundary and session setup

The preferred integration calls NavigatorMinister.start_session(session_id, goal=..., workspace_scope=..., permitted_categories=..., denied_categories=..., approved_destinations=..., high_impact_categories_requiring_approval=...) from a trusted orchestrator before actions begin.

When there is no explicit contract, NAVIGATOR retains an unscoped version-0 contract with unresolved ambiguity; the default deterministic mock reasoner should escalate rather than broadly authorize.

The optional context.user_instruction seed path is safe only if the host guarantees that this field came directly from a trusted user/orchestrator boundary. The current HTTP endpoint does not authenticate clients, so this repo alone cannot prove that origin. Tool output takes precedence as untrusted content and is never allowed to seed a contract.

Approval events must be written by a trusted host that can verify a human approval and specify which action was approved. A source_kind=approval flag by itself is not cryptographic proof that a person approved an action.

## Zero-LLM and dependency behaviour

- Runtime policy evaluation uses invariant.analyzer.policy.LocalPolicy and does not call an LLM or hosted detector.
- invariant-ai==0.3.5 is pinned in requirements.txt. Invariant's dependency metadata includes an OpenAI client library; its presence does not imply this local-policy path calls it.
- Python 3.10+ is required by the upstream project.
- Runtime requirements no longer include BGE, ChromaDB, BM25, or NumPy for semantic retrieval. These remain in requirements-research.txt for the retired retriever only.
- This branch imports upstream code as a dependency rather than copying it into Kavach. Preserve the required license and notice if the dependency is redistributed.

## Limitations

- This is an engine integration and policy-rule rewrite, not evidence that every real-world attack is detected.
- Task contracts must be supplied accurately by the trusted orchestration layer. The policy engine cannot reliably infer arbitrary natural-language authorization from tool calls alone.
- Path sensitivity and source integrity are heuristic labels; they are not byte-level taint tracking.
- The ledger stores what Kavach observed and decided, not proof that an external tool executor completed an action. Enforcement must happen before the tool executes, and the host must honour BLOCK and ESCALATE.
- Session history and contracts are in memory, not durable across restarts.
- No reserved/held-out evaluation split was used for this rewrite. Real-world effectiveness remains INCONCLUSIVE until independently controlled evaluation is run.

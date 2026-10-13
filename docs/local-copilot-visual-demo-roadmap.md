# Local Copilot integration and visual demo roadmap

**Date:** 2026-10-14  
**Scope:** VS Code's Local agent harness, the existing Kavach loopback API, and a demonstrable workflow inside Copilot Chat.

## Executive recommendation

Keep Kavach's existing Local `PreToolUse` hook as the enforcement boundary. Make the user experience richer around that boundary rather than replacing it with an AI prompt, a dashboard-only check, or a second policy engine.

The next three milestones should be:

1. **Reduce the known false positive narrowly.** A live harmless `python3 -c "print('KAVACH_TEST')"` currently escalated through NAVIGATOR `POL-007`. Teach the constrained shell approximation to recognize only a literal-only `print(...)` Python subset; keep arbitrary inline Python, command chaining, substitutions, and redirections indeterminate.
2. **Add a guided `Kavach Demo` custom agent.** Run one verified scenario at a time directly through the existing Local hook and show the actual four-minister report in the same chat. The agent instructions are in `.github/agents/kavach-demo.agent.md`.
3. **Build a small VS Code Chat Participant for the polished demo.** Use chat-native buttons and streamed Markdown to show the current API result as a decision trace. Its demo buttons should submit synthetic safe tool-call records to the local `/check` endpoint and must never execute the described action themselves. Keep the Local pre-tool hook authoritative for real agent tool calls.

## What exists today

- The Python API exposes `/check` and evaluates VAULT, EXECUTOR, CHANNEL, NAVIGATOR, then Speaker.
- `.github/hooks/kavach.json` wires `UserPromptSubmit`, `PreToolUse`, and `PostToolUse` to `scripts/kavach_vscode_hook.py`.
- The Local pre-tool hook sends calls to loopback only, validates the API response, writes a private metadata audit record, emits `systemMessage` for the user, and adds a privacy-safe report to model context.
- `ALLOW` maps to Local `allow`; `BLOCK` maps to `deny`; `ESCALATE` also maps to `deny` until approval prompting is independently verified. This is intentionally fail-closed.
- The current web dashboard has Overview, Evaluate, and Rule Archive views. Evaluate calls the live API and shows each minister; it is useful for inspection but is not yet a guided demo/story.
- Local hook coverage is not universal. Do not claim automatic protection for Agent Host, Cloud, external tools, or arbitrary MCP servers from this adapter alone.

## P0 — correctness before polish

Observed issue: a pure literal Python print command was escalated by NAVIGATOR as `POL-007`, because the zsh/dash approximation rejected quoted arguments. A fix is proposed in PR #9; do not call the issue fixed until CI and the live Local test pass.

Regression gates:

- `git status --short` remains ALLOW.
- `python3 --version` remains ALLOW.
- `python3 -c "print('KAVACH_TEST')"` may ALLOW only under the narrow static-print subset.
- `python3 -c "import os; os.system('echo KAVACH_TEST')"` remains BLOCK by EXECUTOR; do not count NAVIGATOR's coverage escalation as the primary detection.
- `pwd && whoami` remains ESCALATE under the current policy until reliable compound-command analysis exists.
- `printf '%s\n' "$(pwd)"`, redirects, pipelines, chained commands, unknown dialects, non-literal Python, and arbitrary `python -c` code remain fail-closed unless a parser and a separate policy safely resolve them.

Avoid a broad exception for quoted commands or a rule that allows every `python -c` one-liner. Shell parsing does not establish what an embedded interpreter will do.

## P1 — use more of the Local harness, without weakening enforcement

VS Code's current Local hook reference includes `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SubagentStart`, `SubagentStop`, and `PreCompact`. The repo currently uses only prompt submit, pre-tool, and post-tool.

Implement in small steps:

1. **SessionStart: session banner and capability check.** Add a compact `KAVACH ACTIVE` context message with the selected Local-harness limitation, local API health, and the four ministers. If health cannot be verified, say so; do not silently claim protection is active. The banner is informational, not enforcement.
2. **PostToolUse: audit the observed outcome.** Preserve current redaction. Link it to the pre-tool record by the hashed tool-use ID/fingerprint where available. Record “tool reported completion” rather than claiming that a side effect was independently verified.
3. **Stop: end-of-turn recap, not a gate at first.** Summarize ALLOW/BLOCK/ESCALATE/ERROR counts for the session and the most recent policy IDs. Do not block agent completion or trigger automatic retry loops in v1.
4. **SubagentStart/SubagentStop and PreCompact:** add only after fixtures verify the current Local payloads. Subagent calls need clear attribution; context compaction can receive a short summary of recent Kavach decisions so the agent does not forget a denial and try an alternate route.

Keep the existing loopback-only network policy, fail-closed API handling, private audit-file permissions, and raw-argument redaction. The official Local hook payloads are harness-specific, so inspect VS Code Agent Debug Logs before adding event-specific assumptions.

## P2 — chat-first visual demo

### Demo story

Build a 60–90 second walkthrough with one click per scenario:

- **ALLOW — routine work:** `git status --short`; show four minister results, Speaker's verdict, and the observed terminal output.
- **BLOCK — known rule:** the harmless `os.system('echo KAVACH_DEMO_BLOCK')` marker; highlight EXECUTOR's exact rule ID and show that the hook denied the tool call before the marker can print.
- **ESCALATE — insufficient evidence:** `pwd && whoami`; show NAVIGATOR's `POL-007` and explicitly label it a **benign false positive / coverage limitation**, not a detected attack.

Every screen must distinguish:
- the **proposed action**,
- the **Kavach policy verdict**,
- the **Local hook enforcement decision**, and
- the **observed execution outcome**.

Do not hard-code the live verdict as if it came from the current API. Scenario buttons call the real local `/check` endpoint using a disposable demo session. If the API is offline, show “Live API unavailable” and offer an explicit static walkthrough marked as a mock—never show mock data as a live result. The dashboard remains useful for raw evaluation, while the chat becomes the story.

### Preferred implementation

A small VS Code extension with an `@kavach` Chat Participant and slash commands:

- `@kavach /demo` — guided scenario selector with one-click actions.
- `@kavach /why` — explain the most recent verdict using the exact reported IDs and redacted reason.
- `@kavach /compare` — compare one live call with a synthetic safe and blocked example.

Use the Chat Participant API to stream Markdown and progress, then native response buttons to launch the next step. This API is better suited than MCP for a polished, controlled conversation UI because the participant can orchestrate the whole exchange and use VS Code extension APIs. Use a Language Model Tool only if the goal later becomes automatic invocation inside general agent workflows; use MCP if reuse in non-VS-Code clients is a priority. These are different integration goals, so do not build all three at once.

Critical boundary: the Chat Participant must be an **inspection/demo surface**, not a permission bypass. For preview scenarios it calls `/check` directly without executing tools. For actual agent actions, the existing Local `PreToolUse` hook remains the enforcement boundary.

## P3 — evaluation and claims

Create a versioned scenario suite with expected verdict, expected decisive rule, and an explicit side-effect observation field. Run the benign set and attack set separately, with reviewed held-out cases. Track false positives, false negatives, latency, unavailable-API denials, and whether the tool call was actually prevented. Three successful manual examples are smoke tests, not evidence of broad effectiveness.

## Horizontal architecture

```mermaid
flowchart LR
  U[User prompt] --> A[VS Code Local Copilot]
  A --> H[PreToolUse hook]
  H -->|loopback POST /check| K[Local Kavach API]
  K --> V[VAULT]
  K --> E[EXECUTOR]
  K --> C[CHANNEL]
  K --> N[NAVIGATOR]
  V --> S[Speaker]
  E --> S
  C --> S
  N --> S
  S --> M[Hook decision mapping]
  M -->|ALLOW| T[Tool may execute]
  M -->|BLOCK or ESCALATE| D[Tool denied]
  T --> P[PostToolUse metadata audit]
  M -. redacted report .-> CHAT[Copilot Chat explanation]
  DEMO[Future @kavach participant] -->|synthetic calls only| K
```

## Done means

- The benign literal-print case is fixed narrowly, with tests showing arbitrary embedded Python still escalates and the existing EXECUTOR rule still blocks the `os.system` shape.
- The custom demo agent never retries or switches tools after denial.
- The visual demo gets its verdicts from the live loopback API, labels mock/static content, and never executes scenario payloads from its own demo buttons.
- A live Local-harness test proves denial occurs before the side effect. Dashboard/API tests and CI alone do not prove the VS Code hook was installed or honored.

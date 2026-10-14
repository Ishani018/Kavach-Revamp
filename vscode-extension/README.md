# Kavach Chat Participant (preview)

A VS Code extension that brings Kavach's live four-minister decision trace into Copilot Chat and exposes an AI-callable local preflight tool. The deterministic local Kavach API supplies policy verdicts; Copilot can reason about the sanitized result, but it cannot invent or override a Kavach decision.

## What it adds

- `@kavach /demo` — show clickable scenario choices.
- `@kavach /demo allow` — inspect `git status --short`.
- `@kavach /demo block` — inspect a synthetic Python input containing `os.system`; this code is **sent as data only** and is never executed by the extension.
- `@kavach /demo escalate` — inspect harmless compound syntax (`pwd && whoami`) to demonstrate the current uncertainty rule.
- `@kavach /demo print` — verify the literal-only Python print false-positive fix.
- `@kavach /why` — show the last observed result with its rule IDs.
- `@kavach /compare` — run the routine, known-block, and uncertain scenarios and display their actual API results in a Markdown comparison.

The decision display includes the overall verdict, deciding minister, individual VAULT / EXECUTOR / CHANNEL / NAVIGATOR results, available rule and policy IDs, short redacted explanations, and a clear boundary statement.

## Safety boundaries

- The participant submits only fixed, synthetic JSON records to a loopback `/check` endpoint. It never invokes a terminal, runs a shell command, or dispatches the scenario to an agent tool.
- Non-loopback API URLs are rejected. Do not change the code to send commands or prompts to a hosted endpoint.
- If the API is offline or malformed, the participant shows an unavailable state. It never substitutes canned verdicts for a live result.
- The participant is a demonstration/inspection surface, not a replacement for `.github/hooks/kavach.json` and its Local `PreToolUse` enforcement hook.
- A live API verdict on a synthetic call does not prove a real VS Code tool invocation was blocked before execution. Validate the real hook separately.

## AI-assisted preflight tool

The extension contributes a Copilot language-model tool named `#kavachPreflight`. In agent mode, the model can submit the exact proposed terminal command plus a short statement of user intent to Kavach's local `/check` API, then use the structured result to explain the risk or uncertainty and choose what to tell the user.

- The tool sends the command as JSON data to loopback only. It never launches a terminal or executes the command.
- The response contains the overall verdict, deciding minister, minister verdicts, and rule IDs. Raw minister reason text is withheld from the model-tool response.
- The intent field is caller-supplied and is not independently authenticated. It cannot establish that the user authorized a side effect; the result is advisory and may differ from the real hook's verdict.
- On **BLOCK**, **ESCALATE**, or **UNVERIFIED**, the model is instructed to stop and not route around the result.
- Even when preflight returns **ALLOW**, the actual Local `PreToolUse` hook remains an independent, authoritative check of the real tool call.
- Model reasoning may explain evidence or suggest a safer plan, but it has no permission to overrule the deterministic policy result.

To use the workflow, open Copilot in agent mode and ask it to inspect a terminal command before proposing it. The model can call `#kavachPreflight` as part of the plan; the extension may show VS Code's tool confirmation UI before sending the local request. If the local API is unavailable or malformed, the tool returns `UNVERIFIED`, never a substitute ALLOW.

A ready-made profile is available at `.github/agents/kavach-guarded-engineer.agent.md` (select **Kavach Guarded Engineer**). The agent instructions tell the model to preflight proposed terminal commands and to stop on block, escalation, or an unavailable result. The hook still checks every real tool call independently; the agent instructions alone are not a security boundary.

## Requirements

- VS Code 1.100 or newer with GitHub Copilot Chat enabled.
- Node.js 20 or newer for the included extension checks.
- Kavach's local Python API running on `127.0.0.1:8088`.
- For the literal Python print result to match the tested macOS scenario, configure `KAVACH_TERMINAL_DIALECT=zsh` in the environment in which the API server starts. The extension doesn't execute the command itself.

## Run it from this repository

1. Pull the branch containing this directory into your Kavach clone.
2. In a terminal at the repository root, start the API with the project's virtual environment. On macOS with zsh, use:

   ~~~sh
   source .venv/bin/activate
   export KAVACH_TERMINAL_DIALECT=zsh
   python -m uvicorn kavach.api:app --host 127.0.0.1 --port 8088
   ~~~

   Keep this terminal running. In another terminal, check `curl --fail http://127.0.0.1:8088/health`.

3. Open the Kavach repository root in VS Code and trust the workspace. Ensure the Local harness hooks are enabled (`chat.useHooks`).
4. Open Run and Debug, select **Run Kavach Chat Participant**, and press **F5**. A second Extension Development Host window will open with the full Kavach repository as the workspace, so the extension and Local pre-tool hook can both be tested.
5. In the new window, open Copilot Chat and type `@kavach`. Choose a scenario button or type one of the slash commands above.

## Verify the extension code

From the repository root:

~~~sh
cd vscode-extension
npm run verify
~~~

The tests check API response validation, exact rule-ID display, no leakage of raw reason text, uncertainty wording, comparison output, and honest behavior when no prior result exists. They do not replace the live VS Code extension-host test.

## Known limitations

- `/compare` runs three separate live `/check` calls; it is not a benchmark and should not be interpreted as accuracy or detection-rate measurement.
- `workspaceState` stores the last inspection in the current VS Code extension storage. It is only used by `/why`.
- This is a workspace extension run locally in the Extension Development Host; it is not packaged or published to the Marketplace in this PR.

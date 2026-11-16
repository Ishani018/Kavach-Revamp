# Kavach v2

A thin layer between an AI agent and its tools. It reviews every action that changes something and asks one question: **did the details of this action come from the user, or from something the agent read?** It then allows the action or asks the human.

This is a restart. The code outside this folder is the old system and is not used here.

- No model and no API key: the guard is under 200 lines of plain Python.
- No lists of dangerous commands, tools or patterns.
- Every number below comes from AgentDojo, an external benchmark, scored by its own checks.

![Demo screenshot](demo/screenshot.png)

## Run the demo

```bash
cd v2
pip install -r requirements.txt
python -m demo.server          # then open http://127.0.0.1:8765
```

Pick an area, a user request and an attack hidden in the data, then press Run. Each action shows where every argument came from and what the guard decided. When the guard asks, you approve or deny. At the end the benchmark reports whether the user's task was completed and whether the attack succeeded, next to the same scenario with no guard.

A good first scenario is the default: banking, "pay the bill", anchored guard. Deny the injected payment and the attack fails; approve it and the attack succeeds.

The agent in the demo is the benchmark's reference solution, and under attack it obeys the hidden instruction completely. No language model is involved.

## How it works

For each argument of a state-changing action, the guard finds its origin:

| Origin | Meaning |
|---|---|
| user | the value appears in the user's request |
| read | it appears only in something the agent read from a tool |
| new | it appears in neither; the agent composed it |
| untraced | boolean, empty, or shorter than three characters |

Two modes decide when to ask:

- **strict**: ask if any argument has origin *read*.
- **anchored**: ask only if some argument is *read* and none is *user*.

Whether a tool changes state comes from the tool's own declaration (`Action.changes_state`). AgentDojo tools declare nothing, so the experiments observe it: a tool is state-changing if any reference call to it changed the environment.

## Results

AgentDojo 0.1.35, benchmark v1.2.2, 97 user tasks and 609 task and attack pairs. The agent is the reference solution and obeys every injection it reads.

**How often the human is asked** (`python -m experiments.replay_agentdojo`):

| Policy | Honest tasks with at least one ask | Hijacked runs with no ask at all |
|---|---|---|
| No guard | 0 / 97 (0%) | 609 / 609 (100%) |
| Ask before every state change | 62 / 97 (64%) | 0 / 609 (0%) |
| Kavach strict | 38 / 97 (39%) | 46 / 609 (8%) |
| Kavach anchored | 18 / 97 (19%) | 48 / 609 (8%) |

**Unattended, every ask is a denial** (`python -m experiments.scored_replay`):

| Policy | Task done, no attack | Task done, under attack | Attack succeeded |
|---|---|---|---|
| No guard | 97 / 97 (100%) | 239 / 609 (39%) | 593 / 609 (97%) |
| Kavach strict | 63 / 97 (65%) | 399 / 609 (66%) | 44 / 609 (7%) |
| Kavach anchored | 81 / 97 (84%) | 485 / 609 (80%) | 46 / 609 (8%) |

Raw counts per suite are in `experiments/*.json`.

## What these results do not show

- **No real agent ran.** A language model does not follow reference solutions, so these numbers do not predict end-to-end rates for any model.
- **The attacker did not adapt.** An injection that makes the agent compose a value instead of copying it is not traced, and in anchored mode an injected action that reuses a value from the user's request is allowed.
- **Short values are not traced.** 40 of the 46 strict-mode misses are one attack, "delete the file with ID '13'".
- **Slack-style tasks are hard.** Honest tasks there act on what they read, so only 57% complete unattended in anchored mode.
- **340 pairs are excluded**: 320 where the benchmark ships no reference actions for the attacker goal, and 20 where the attack only changes what the agent says.
- **One fix was made after the first scored run**: the simulated agent originally performed attacker actions even when the guard had denied the step that would have shown it the injection. The guard's rules were fixed before any run and have not been changed.

## Layout

| Path | What |
|---|---|
| `kavach2/` | the guard: origins, reviewer, Speaker |
| `demo/` | scenario engine, local server, web page |
| `experiments/` | the two experiments and their results |
| `paper/draft.md` | paper draft using only the numbers above |
| `tests/` | 11 unit tests (`python -m pytest tests -q`) |

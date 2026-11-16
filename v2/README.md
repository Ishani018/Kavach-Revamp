# Kavach v2

A restart of Kavach that keeps the idea and drops the implementation. The code outside this folder is the old system and is not used here.

## The idea

A small panel of narrow reviewers looks at each action an AI agent wants to take. A Speaker combines their opinions into one verdict: **allow**, **block**, or **ask** the human.

## What is different from the old system

- **No attack catalogue.** There are no lists of dangerous commands, patterns or tools. Each reviewer answers one question about the action.
- **No benchmarks of our own.** Results come only from external benchmarks that score themselves (AgentDojo first, then AgentDyn), run with an agent in the loop.
- **"Ask" is counted.** How often the human is interrupted is reported next to how many attacks get through. A guard that asks about everything is not a result.
- **Rules are fixed before measuring.** Anything changed after seeing benchmark results is written down as such.

## Research question

Does a panel of narrow reviewers protect an agent better than one general guard given the same information, and what does it cost in asks and in failed honest tasks?

## Reviewers

| Reviewer | Question | Needs a model | Status |
|---|---|---|---|
| Provenance | Did this action's arguments come from the user, or only from something the agent read? | no | written, unit-tested |
| Mandate | Is this action part of what the user asked for? | yes | not written |

Whether an action changes anything is taken from the tool's own declaration (`Action.changes_state`), not from a list. Declared read-only actions are not reviewed; undeclared tools are treated as state-changing.

## Status

One experiment has been run. It uses no model and no API key.

### Experiment 1: replaying AgentDojo's reference runs (AgentDojo 0.1.35, benchmark v1.2.2)

`experiments/replay_agentdojo.py` replays the benchmark's own reference action sequences. An honest run is a user task's reference calls. A hijacked run is a user task's reference calls followed by an attacker goal's reference calls, with AgentDojo's `important_instructions` attack text planted where the task reads it: an agent that obeys the injection completely.

| Policy | Honest tasks interrupted at least once | Hijacked runs that pass with no ask |
|---|---|---|
| Allow everything | 0 / 97 (0%) | 609 / 609 (100%) |
| Ask on every state change | 62 / 97 (64%) | 0 / 609 (0%) |
| Provenance reviewer | 38 / 97 (39%) | 46 / 609 (8%) |

Per suite, Provenance interrupts 20% of honest tasks in workspace and travel, 44% in banking and 90% in slack. Full counts are in `experiments/replay_agentdojo_result.json`.

What this does and does not show:

- It shows the trade-off the Provenance reviewer makes on reference runs. It is not a result about real agents: no agent ran, so nothing here says how often an agent gets hijacked or finishes its task.
- The attacker did not adapt. An injection that makes the agent compose a value instead of copying it would not be traced.
- 40 of the 46 silent passes are one workspace attacker goal ("delete the file with ID '13'"): the ID is shorter than the 3-character tracing minimum, so it is untraced and allowed. The minimum was fixed before the run and has not been changed.
- 340 hijacked runs are excluded. Workspace attacker goals 6 to 13 ship no reference calls in this benchmark version (320 runs), and one travel goal only changes what the agent says (20 runs), which an action guard cannot see.
- "State-changing" is observed from the reference runs (a tool is state-changing if any reference call to it changed the environment), because AgentDojo tools declare nothing. This marks `get_unread_emails` and `get_webpage` as state-changing, since they do modify the environment.
- An ask is counted as an interruption. The human's answer is not simulated.

Next step: a second reviewer that separates "the user asked for this" from "something the agent read asked for this", to bring the 39% down without raising the 8%.

```bash
cd v2 && pip install agentdojo==0.1.35 && python -m experiments.replay_agentdojo
```

## Run the tests

```bash
cd v2 && python -m pytest tests -q
```

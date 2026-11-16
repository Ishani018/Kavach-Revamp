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

**Nothing has been measured.** The 7 tests in `tests/` check that the code does what it says; they are not evidence that it stops attacks.

Next step: replay AgentDojo's own reference action sequences (honest tasks and attacker goals) through the Provenance reviewer. This needs no model and gives the ask rate on honest tasks and the share of fully hijacked runs that pass silently. That is the baseline the Mandate reviewer has to beat.

## Run the tests

```bash
cd v2 && python -m pytest tests -q
```

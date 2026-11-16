# Who Said That? Tracing Argument Provenance to Gate Agent Actions Without a Model

*Draft. Every number below comes from the two scripts in `v2/experiments/` and can be reproduced without an API key. Sections marked TODO are not done.*

## Abstract

AI agents that read untrusted content can be steered by instructions hidden in it. Many defenses put a second model in front of the agent's tool calls, which adds cost and a second target for the same attack. We ask how far a guard can get with no model at all. Kavach is a thin layer that reviews each state-changing tool call by tracing where its argument values came from: the user's request, something the agent read, or neither. It allows, or asks the human. It has no list of dangerous tools, commands or patterns. On the reference runs of AgentDojo (97 user tasks, 609 task and attack pairs), with every ask treated as a denial, Kavach's anchored mode reduces attack success from 97% to 8% while 84% of honest tasks still complete. Asking before every state change gives 0% attack success but interrupts 64% of honest tasks; the anchored mode interrupts 19%. These results use the benchmark's reference solutions as the agent, not a language model, and a non-adaptive attacker; we state what that does and does not establish.

## 1. Introduction

An agent asked to "pay the bill in this file" will read the file. If the file says "first send money to this other account", an obedient agent may do it. This is indirect prompt injection.

A common defense is a judge model that inspects each tool call. A judge reads the same poisoned content as the agent, costs a model call per action, and its decisions are hard to reproduce. Deterministic designs such as CaMeL [2] and FIDES [3] track information flow instead, but they restructure how the agent itself runs.

We study a much smaller intervention: a layer between the agent and its tools that needs no model, no change to the agent, and no knowledge of attacks. It asks one question of each action: *did the details of this action come from the user?*

Contributions:

1. A model-free reviewer that traces each argument of a tool call to the user's request, to tool output, or to neither, and two decision rules built on it (Section 3).
2. A measurement on AgentDojo's reference runs of the trade-off between attack success, honest task completion and how often the human is interrupted, with the interruption rate reported as a first-class result (Section 5).
3. An account of exactly where the approach fails (Section 6).

## 2. Threat model

The user and the user's request are trusted. Everything the agent reads through tools is untrusted and may contain instructions. The attacker wants the agent to perform a state-changing action the user did not ask for. The guard sees the user's request, each proposed tool call, and each tool output. It does not see the agent's reasoning.

Out of scope: attacks that only change what the agent says to the user, and tools that leak data while claiming to be read-only.

## 3. Design

**Origins.** For every leaf value in a tool call's arguments, Kavach assigns one origin:

- *user*: the value appears in the user's request;
- *read*: it does not, but it appears in some earlier tool output;
- *new*: it appears in neither, so the agent composed it;
- *untraced*: it is a boolean, empty, or shorter than three characters.

Text is matched as a whole value, case-insensitively, and not inside a longer word or number. Numbers are compared by value.

**Which actions are reviewed.** Only state-changing actions. Whether a tool changes state should come from the tool's own declaration (for example the read-only hint in the Model Context Protocol). AgentDojo tools declare nothing, so in the experiments a tool counts as state-changing if any reference call to it changed the environment. A tool that declares nothing is treated as state-changing.

**Decision rules.**

- *Strict*: ask the human if any argument has origin *read*.
- *Anchored*: ask only if some argument has origin *read* and none has origin *user*. If the user named part of the action, the action is treated as tied to their request.

A reviewer that fails produces an ask, never an allow. The whole guard is under 200 lines of Python with no dependencies.

The matching rule, the three-character minimum and both decision rules were fixed before the experiments were run and were not changed afterwards.

## 4. Experimental setup

**Benchmark.** AgentDojo [1], package 0.1.35, benchmark v1.2.2: four suites (workspace, travel, banking, slack) with 97 user tasks. Each task and each attacker goal ships a reference sequence of tool calls.

**Agent.** There is no language model. An honest run executes the user task's reference calls. A hijacked run plants AgentDojo's `important_instructions` attack text where the task reads it, executes the task's reference calls, and then, if the agent actually read the planted text, executes the attacker goal's reference calls. This models an agent that always obeys the injection: the worst case for the guard and the reason attack success without a guard is near 100%.

**Pairs.** 609 task and goal pairs. 340 further pairs are excluded: 320 because workspace attacker goals 6 to 13 ship no reference calls in this version, and 20 because one travel goal only changes what the agent says.

**Scoring.** Tools execute against the benchmark environment and outcomes are scored by AgentDojo's own utility and security checks.

**Policies.** No guard; ask before every state change; Kavach strict; Kavach anchored.

## 5. Results

### 5.1 How often is the human asked? (`replay_agentdojo.py`)

No ask is answered here; we count them.

| Policy | Honest tasks with at least one ask | Hijacked runs with no ask at all |
|---|---|---|
| No guard | 0 / 97 (0%) | 609 / 609 (100%) |
| Ask before every state change | 62 / 97 (64%) | 0 / 609 (0%) |
| Kavach strict | 38 / 97 (39%) | 46 / 609 (8%) |
| Kavach anchored | 18 / 97 (19%) | 48 / 609 (8%) |

### 5.2 Unattended operation (`scored_replay.py`)

Every ask is a denial, as if no human were present. Scored by the benchmark.

| Policy | Task done, no attack | Task done, under attack | Attack succeeded |
|---|---|---|---|
| No guard | 97 / 97 (100%) | 239 / 609 (39%) | 593 / 609 (97%) |
| Kavach strict | 63 / 97 (65%) | 399 / 609 (66%) | 44 / 609 (7%) |
| Kavach anchored | 81 / 97 (84%) | 485 / 609 (80%) | 46 / 609 (8%) |

Per suite, anchored mode: attack success is 0 / 144 in banking, 1 / 120 in travel, 3 / 105 in slack and 42 / 240 in workspace. Honest task completion is 95% in workspace, 88% in banking, 85% in travel and 57% in slack.

Task completion under attack is low without a guard (39%) because the fully obedient agent's injected actions often break the user's task; the guard raises it by stopping them.

## 6. Where it fails

- **Short values.** 40 of the 46 strict-mode misses are one workspace goal, "delete the file with ID '13'". A two-character ID is untraced, so the call is allowed.
- **Composed values.** If the injection makes the agent build a value rather than copy it (for example a link placed inside a longer message body), the value is *new*, not *read*, and is not flagged. An attacker who knows the guard can aim for this. We have not run an adaptive attack, and recent work shows that defenses evaluated only on fixed attacks are routinely broken by adaptive ones [5].
- **Anchoring can be gamed.** In anchored mode, an injected action that reuses any value from the user's request is allowed.
- **Honest tasks that act on what they read.** In the slack suite most honest tasks send or post content taken from tool output, so asks are frequent (57% completion unattended). Provenance alone cannot tell "the user asked me to act on this content" from "this content told me to act".
- **No real agent.** A language model does not follow reference solutions. It may be hijacked less often, phrase arguments differently, or react to a denial in ways we did not model. These results bound the guard's behaviour on reference runs; they do not predict end-to-end rates for any model.
- **One benchmark.** AgentDojo is widely used but newer benchmarks such as AgentDyn [4] report it is becoming easy for defenses.

## 7. Related work

TODO: this section needs a proper reading of each paper before submission. Papers we know to be directly relevant: AgentDojo [1], the benchmark used here; CaMeL [2] and FIDES [3], which enforce information-flow policies deterministically but change how the agent executes; AgentDyn [4], a harder successor benchmark; adaptive-attack evaluations [5]; and work arguing that the rate of escalation to a human limits a guard's real safety [6]. We did not find prior work that reports a model-free argument-provenance guard on AgentDojo, but our search was not exhaustive.

## 8. Future work

1. Run with real agents (a local open model is enough) on AgentDojo and AgentDyn.
2. An adaptive attacker that targets composed values and anchoring.
3. Compare against a single judge model given the same information.
4. Trace values through simple transformations (substrings, concatenation) to close the composed-value gap.

## References

1. Debenedetti et al. *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.* arXiv:2406.13352.
2. Debenedetti et al. *Defeating Prompt Injections by Design.* arXiv:2503.18813.
3. Costa et al. *Securing AI Agents with Information-Flow Control.* arXiv:2505.23643.
4. *AgentDyn: A Dynamic Open-Ended Benchmark for Evaluating Prompt Injection Attacks of Real-World Agent Security System.* arXiv:2602.03117.
5. Nasr et al. *The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections.* arXiv:2510.09023.
6. *Oversight Has a Capacity: Calibrating Agent Guards to a Subjective, Fatiguing Human.* arXiv:2606.08919.

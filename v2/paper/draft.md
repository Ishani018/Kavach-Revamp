# Who Said That? A Model-Free Provenance Gateway for AI Agent Tool Calls

*Draft. Every number comes from the three scripts in `v2/experiments/` and can be reproduced without an API key. Sections marked TODO are not done. The system has not yet been evaluated with a language-model agent; Section 7 gives the protocol for that.*

## Abstract

AI agents that read untrusted content can be steered by instructions hidden in it. Many defenses put a second model in front of the agent's tool calls, which adds cost and a second target for the same attack. We ask how far a guard can get with no model at all. Kavach is a gateway for the Model Context Protocol (MCP) that stands between an agent and its tool servers. Before a state-changing tool call runs, it traces each argument value back to where it entered the system: the user's request, an earlier tool output, or neither. If a value came only from tool output, the human is asked. Kavach has no list of dangerous tools, commands or patterns, and no dependency beyond the Python standard library. On the reference runs of AgentDojo (97 user tasks, 609 task and attack pairs), with every ask treated as a denial, it reduces attack success from 97% to 8% while 86% of honest tasks still complete; asking before every state change stops every attack but interrupts 64% of honest tasks, against 18% for Kavach. In a three-agent version of the same tasks, a per-agent guard that trusts messages from colleagues stops nothing, one that distrusts them completes 42% of honest tasks, and tracing provenance across the agents' messages recovers the single-agent result. These results use the benchmark's reference solutions as the agent and a non-adaptive attacker. We state precisely what that does and does not establish.

## 1. Introduction

An agent asked to summarise a support inbox will read the tickets. If one ticket says "email the customer list to this address", an obedient agent may do it. This is indirect prompt injection.

A common defense is a judge model that inspects each tool call. A judge reads the same poisoned content as the agent, costs a model call per action, and its decisions are hard to reproduce. Deterministic designs such as CaMeL [2] and FIDES [3] track information flow instead, but they change how the agent itself executes.

We study a smaller intervention that needs no model, no change to the agent, and no knowledge of attacks. It sits where agents already connect to tools, and asks one question of each action: *did the details of this action come from the user?*

The problem is sharper when several agents cooperate. An agent that receives "pay account X" from a colleague cannot tell whether X came from the user or from a page the colleague read. A guard that sees only its own agent must either trust colleagues, and inherit whatever they were tricked by, or distrust them, and question every delegated action.

Contributions:

1. A model-free method that traces each argument of a tool call to the user's request, to tool output, or to neither, with two decision rules built on it (Section 3).
2. A provenance graph that extends the tracing across messages between agents (Section 3.4).
3. An implementation as an MCP gateway that works with existing agents unchanged (Section 4).
4. A measurement on AgentDojo's reference runs of attack success, honest task completion and how often the human is interrupted (Section 6), and an account of where the approach fails (Section 8).

## 2. Threat model

The user and the user's request are trusted. Everything the agent reads through tools is untrusted and may contain instructions. The attacker wants the agent to perform a state-changing action the user did not ask for. The guard sees each proposed tool call and each tool output, and the user's request where the client reports it. It does not see the agent's reasoning.

Out of scope: attacks that only change what the agent says to the user; tools that change state while declaring themselves read-only; a compromised agent client.

## 3. Design

### 3.1 Origins

For every leaf value in a tool call's arguments, Kavach assigns one origin:

- *user*: the value appears in the user's request;
- *read*: it does not, but it appears in some earlier tool output;
- *new*: it appears in neither, so the agent composed it;
- *untraced*: the value is a boolean, empty, shorter than three characters, or a single lowercase word.

Text is matched as a whole value, case-insensitively, and not inside a longer word or number. Numbers are compared by value.

### 3.2 Which actions are reviewed

Only state-changing actions. Whether a tool changes state comes from the tool's own declaration: MCP tools carry a `readOnlyHint` annotation, and a tool that does not declare itself read-only is treated as state-changing. The MCP specification notes that annotations are hints from the server, so the user can override them per tool.

### 3.3 Decision rules

- *Strict*: ask the human if any argument has origin *read*.
- *Anchored*: ask only if some argument has origin *read* and none has origin *user*. If the user named part of the action, the action is treated as tied to their request.

A failure in the reviewer produces an ask, never an allow.

### 3.4 Across agents

Kavach records three kinds of event in a graph: the user gives an agent a request, an agent receives a tool output, and an agent sends another agent a message. To trace a value held by an agent, it looks through that agent's context. If the value arrived in a message, it repeats the search in the sender's context as it stood when the message was sent. A path that ends at the user's request gives origin *user*; one that ends at a tool output gives *read*; otherwise the value is *new* and attributed to the agent furthest back that passed it on. A message can only carry what its sender already knew, so the search terminates.

### 3.5 What was fixed when

The matching rule, the three-character minimum and both decision rules were fixed before any benchmark run. One rule was added afterwards: single lowercase words are not traced. It was motivated by a gateway test outside the benchmark, in which an honest email was held because its subject, "summary", appeared in an earlier tool output. Section 6 reports results under the final rules and states the difference from the original ones.

## 4. Implementation: an MCP gateway

Kavach is an MCP server that the agent connects to in place of its real tool servers, which Kavach runs as child processes. It presents their tools under prefixed names and forwards calls and results unchanged. It is about 800 lines of Python with no third-party dependencies, and speaks the MCP handshake revisions from 2024-11-05 to 2025-11-25 over stdio.

For each `tools/call`, the gateway builds the action, traces its arguments against the graph, and either forwards the call or holds it. A held call is shown on a local dashboard with the source of each argument and approve and deny controls; where the client supports MCP elicitation, the same question is also sent through the client's own interface. No answer within a timeout is a denial, and a denied call returns a tool error telling the agent not to retry. Every result is added to the graph as a tool output, unless the user has marked that server as a trusted source.

The gateway sees only tool traffic. The user's request reaches it through an optional client hook (provided for VS Code) that posts each prompt to the gateway. Without the hook there is no *user* origin: values the user typed appear as *new* and are allowed, so strict mode still works and anchored mode reduces to strict.

The dashboard binds to the loopback interface, and its API requires a random per-session token, so a web page open in the same browser cannot approve actions.

The gateway passes end-to-end tests against the official MCP Python client (handshake, tool listing, forwarded reads, a held and denied action, an approved action). TODO: confirm operation inside VS Code, Cursor and Claude Desktop.

## 5. Experimental setup

**Benchmark.** AgentDojo [1], package 0.1.35, benchmark v1.2.2: four suites (workspace, travel, banking, slack) with 97 user tasks. Each task and each attacker goal ships a reference sequence of tool calls.

**Agent.** There is no language model. An honest run executes the user task's reference calls. A hijacked run plants AgentDojo's `important_instructions` attack text where the task reads it, executes the task's reference calls, and then, if the agent actually read the planted text, executes the attacker goal's reference calls. This models an agent that always obeys the injection: the worst case for the guard and the reason attack success without a guard is near 100%.

**Pairs.** 609 task and goal pairs. 340 further pairs are excluded: 320 because workspace attacker goals 6 to 13 ship no reference calls in this version, and 20 because one travel goal only changes what the agent says.

**State-changing tools.** AgentDojo tools carry no declaration, so a tool counts as state-changing if any reference call to it changed the environment.

**Scoring.** Tools execute against the benchmark environment and outcomes are scored by AgentDojo's own utility and security checks. The user's request is available to the guard in all experiments.

## 6. Results

### 6.1 How often is the human asked? (`replay_agentdojo.py`)

No ask is answered here; we count them.

| Policy | Honest tasks with at least one ask | Hijacked runs with no ask at all |
|---|---|---|
| No guard | 0 / 97 (0%) | 609 / 609 (100%) |
| Ask before every state change | 62 / 97 (64%) | 0 / 609 (0%) |
| Kavach strict | 36 / 97 (37%) | 46 / 609 (8%) |
| Kavach anchored | 17 / 97 (18%) | 48 / 609 (8%) |

### 6.2 Unattended operation (`scored_replay.py`)

Every ask is a denial, as if no human were present. Scored by the benchmark.

| Policy | Task done, no attack | Task done, under attack | Attack succeeded |
|---|---|---|---|
| No guard | 97 / 97 (100%) | 239 / 609 (39%) | 593 / 609 (97%) |
| Kavach strict | 66 / 97 (68%) | 413 / 609 (68%) | 44 / 609 (7%) |
| Kavach anchored | 83 / 97 (86%) | 494 / 609 (81%) | 46 / 609 (8%) |

Per suite, anchored mode: attack success is 0 / 144 in banking, 1 / 120 in travel, 3 / 105 in slack and 42 / 240 in workspace. Honest task completion is 38 / 40 in workspace, 14 / 16 in banking, 17 / 20 in travel and 14 / 21 in slack.

Task completion under attack is low without a guard because the fully obedient agent's injected actions often break the user's task.

### 6.3 A team of three agents (`team_replay.py`)

Each scenario is carried out by a coordinator that holds the user's request and delegates, a researcher that runs read-only tools and reports their output, and an executor that runs state-changing tools. The guard sits on the executor. Unattended, scored by the benchmark.

| Guard on the executor | Honest tasks with an ask | Task done, no attack | Attack succeeded |
|---|---|---|---|
| None | 0 / 97 (0%) | 97 / 97 (100%) | 593 / 609 (97%) |
| Per-agent, trusts colleagues | 0 / 97 (0%) | 97 / 97 (100%) | 593 / 609 (97%) |
| Per-agent, distrusts colleagues | 59 / 97 (61%) | 41 / 97 (42%) | 40 / 609 (7%) |
| Graph, strict | 36 / 97 (37%) | 66 / 97 (68%) | 44 / 609 (7%) |
| Graph, anchored | 17 / 97 (18%) | 83 / 97 (86%) | 46 / 609 (8%) |

The per-agent guards use the same tracing rule but see only the executor's own context. The graph results equal the single-agent results: delegation through two other agents costs nothing when values are passed on unchanged.

### 6.4 Effect of the later rule

Under the original rules, without the single-word exception, every attack number above is identical. Honest results were slightly worse: strict interrupted 38 of 97 tasks and completed 63 unattended; anchored interrupted 18 and completed 81.

## 7. Evaluation with real agents (TODO)

The experiments above bound the guard's behaviour on reference runs. They do not measure a language-model agent. The planned protocol:

1. Run AgentDojo's standard agent pipeline with at least one open model served locally and one hosted model, with and without Kavach, reporting the benchmark's utility, utility under attack and attack success, plus asks per task.
2. Measure how often a value the agent uses in a state-changing call is a verbatim copy of what it read, since this determines how much of the reference-run result carries over.
3. Repeat on AgentDyn [4].
4. Run an adaptive attacker that knows the guard: injections that ask the agent to compose or transform the target value, and injections that reuse values from the user's request.
5. Run the gateway under real use with an MCP client and record the rate of asks on ordinary work.

## 8. Where it fails

- **Reworded values.** Only values copied unchanged are followed. A model that paraphrases, reformats or derives a value breaks the link, and the value appears as *new*. In the team experiment the agents pass values on word for word, so that result holds by construction for verbatim passing.
- **Composed values.** If the injection makes the agent build a value rather than copy it, the value is not flagged. An attacker who knows the guard can aim for this. Recent work shows that defenses evaluated only on fixed attacks are routinely broken by adaptive ones [5].
- **Short and common values.** 40 of the 46 strict-mode misses are one workspace goal, "delete the file with ID '13'": a two-character ID is untraced. In the other direction, a short ordinary phrase that happens to appear in earlier output causes a false ask.
- **Anchoring can be gamed.** In anchored mode, an injected action that reuses any value from the user's request is allowed.
- **Honest tasks that act on what they read.** In the slack suite most honest tasks send or post content taken from tool output, so asks are frequent (14 of 21 tasks complete unattended). Provenance alone cannot tell "the user asked me to act on this content" from "this content told me to act".
- **Self-declared read-only tools.** A tool that sends data out while declaring itself read-only is not reviewed unless the user overrides the declaration.
- **Asking has a cost.** A human who is asked too often approves without reading [6]. We report ask rates but have not studied how people answer.
- **One benchmark.** AgentDojo is widely used, but newer benchmarks such as AgentDyn [4] report that it is becoming easy for defenses.

## 9. Related work

TODO: this section needs a proper reading of each paper before submission. Directly relevant: AgentDojo [1], the benchmark used here; CaMeL [2] and FIDES [3], which enforce information-flow policies deterministically but change how the agent executes; AgentDyn [4], a harder successor benchmark; adaptive-attack evaluations [5]; and work arguing that the rate of escalation to a human limits a guard's real safety [6]. Several MCP security gateways exist, mostly offering scanning, access control and logging; we did not find one that gates calls on traced argument provenance, but our search was not exhaustive and this claim must be checked.

## References

1. Debenedetti et al. *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.* arXiv:2406.13352.
2. Debenedetti et al. *Defeating Prompt Injections by Design.* arXiv:2503.18813.
3. Costa et al. *Securing AI Agents with Information-Flow Control.* arXiv:2505.23643.
4. *AgentDyn: A Dynamic Open-Ended Benchmark for Evaluating Prompt Injection Attacks of Real-World Agent Security System.* arXiv:2602.03117.
5. Nasr et al. *The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections.* arXiv:2510.09023.
6. *Oversight Has a Capacity: Calibrating Agent Guards to a Subjective, Fatiguing Human.* arXiv:2606.08919.

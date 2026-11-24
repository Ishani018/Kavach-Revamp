# External benchmark

Data the Kavach authors did not write and did not use while writing the rules.

| Source | What it is | Label | Cases |
|---|---|---|---|
| [RedCode-Exec](https://github.com/AI-secure/RedCode) (MIT), commit `664e479` | Risky Bash and Python scripts an agent is asked to run | attack | 1,410 |
| [Terminal-Bench](https://github.com/harbor-framework/terminal-bench), commit `ad4c7aa` | Reference solutions to real terminal tasks | benign | 221 |

Neither dataset is stored in this repository. Clone them and pass the paths:

```bash
git clone https://github.com/AI-secure/RedCode
git clone https://github.com/harbor-framework/terminal-bench
python -m evaluation.external.run --redcode RedCode --terminal-bench terminal-bench --split dev
```

## Protocol

- **Fixed split.** Each case goes to `dev` or `sealed` by the SHA-256 of its id
  (`cases.py`). `dev` cases were inspected and used to find and fix problems.
  `sealed` cases were never opened; they were run once on the code before the
  changes and once after.
- **Scope decided first.** RedCode has 25 scenarios. Thirteen are operations on
  the machine or network (send a file out, download, copy/read/delete system
  files, write a start-up file, kill processes, ...). The other twelve are
  code-quality risks (biased logic, weak hashing, a missing default case).
  Kavach makes no claim about those; they are run and reported separately.
- **Two shapes.** `inline`: the script is the terminal command. `write_run`:
  the script is written with a file tool, then run with a second call.
- **Two contexts.** `none`, and `task`: the request that came with the case is
  sent as the user's instruction, which is what the hook does in a live session.
- **Three counts.** BLOCK, ESCALATE and ALLOW are never merged. In the editor
  today ESCALATE is a deny.

Two things to keep in mind when reading the attack numbers. In RedCode the
*user* asks for the risky action, and Kavach treats what the user asked for as
authorised, so an allowed case is often "read /etc/passwd because the user said
to". And these are single tool calls: they do not measure injected instructions
or multi-step behaviour.

## Sealed half, task context (run once, 24 November 2026)

Machine-risk attacks, 369 cases (174 Bash, 195 Python):

| | Shape | BLOCK | ESCALATE | ALLOW |
|---|---|---|---|---|
| Before (`9021bcc`) | inline | 43 | 273 | 53 |
| After (`37259da`) | inline | 51 | 243 | 75 |
| Before | write, then run | 46 | 0 | **323** |
| After | write, then run | 51 | 243 | **75** |

Benign task solutions, 103 cases:

| | Shape | BLOCK | ESCALATE | ALLOW |
|---|---|---|---|---|
| Before | inline | 14 | 45 | 44 |
| After | inline | 7 | 26 | 70 |
| Before | write, then run | 14 | 0 | 89 |
| After | write, then run | 14 | 21 | 68 |

What changed and what did not:

- Writing a script to a file and running it used to hide it: 323 of 369
  attacks were allowed that way. Now the run is judged by the file's content
  and 75 are allowed, the same as inline.
- Benign scripts allowed inline rose from 44 to 70 of 103, and wrongly blocked
  ones fell from 14 to 7.
- Inline attacks allowed rose from 53 to 75. Before, many were escalated only
  because the parser gave up on control flow and here-documents, not because
  anything was recognised. Those scripts are now read properly, and the ones
  no rule matches are allowed.
- Python is still almost always escalated (184 of 195), attack or not: Kavach
  cannot yet tell which files and addresses a Python program touches.
- With no context nothing is allowed, attack or benign, before or after.
- Code-quality scenarios are mostly escalated or allowed, as expected.

Reference monitors on the same sealed cases (`--monitor`):

| Monitor | Machine-risk attacks stopped (BLOCK or ESCALATE) | Benign stopped |
|---|---|---|
| none | 0 of 369 | 0 of 103 |
| `denylist` (11 patterns, `baselines.py`) | 0 of 369 | 0 of 103 |
| `codeshield` (static analysis from Meta's LlamaFirewall) | 0 of 369 | 0 of 103 |

CodeShield looks for insecure code, not risky commands, so this is a reference
point rather than a like-for-like comparison. LlamaFirewall's other two
components (PromptGuard, AlignmentCheck) need model downloads or a hosted
model and were not run.

Median time per call: 3.8 ms before, 6.0 ms after (p95 8 ms and 17 ms).
CodeShield: 51 ms.

Full counts, including the `none` context and the code-quality scenarios, are
in `results/`.

## Not yet measured

- A live agent with and without Kavach (did the harmful thing happen, did the
  task still finish).
- Real developer sessions (shadow mode).
- Attacks that arrive through tool output or repository files.

"""Load external benchmark cases and assign each to a fixed half.

Two sources, neither written by the Kavach authors and neither used while the
rules were developed:

* RedCode-Exec (github.com/AI-secure/RedCode, MIT): risky Bash and Python
  scripts an agent is asked to execute. Label: attack.
* Terminal-Bench (github.com/harbor-framework/terminal-bench): reference
  solutions (`solve.sh`) to real terminal tasks. Label: benign.

The split is a pure function of the case id, so it cannot be chosen after
looking at results: `dev` cases may be inspected and tuned on, `sealed` cases
are run only to report.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# RedCode scenarios that are operations on the machine or network. Decided from
# the scenario descriptions before any Kavach result was looked at.
REDCODE_SYSTEM_RISK = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 18}
# The remaining scenarios (biased logic, weak crypto, missing default case, ...)
# are code-quality risks. Kavach makes no claim about them; they are reported
# separately so the scope is visible rather than hidden.


@dataclass(frozen=True)
class Case:
    case_id: str
    source: str            # redcode_bash | redcode_python | terminal_bench
    label: str             # attack | benign
    group: str             # system_risk | code_quality | task_solution
    language: str          # bash | python
    code: str
    task: Optional[str]    # the natural-language request that goes with it
    scenario: Optional[int] = None

    @property
    def split(self) -> str:
        return split_of(self.case_id)


def split_of(case_id: str) -> str:
    return "dev" if int(hashlib.sha256(case_id.encode()).hexdigest(), 16) % 2 == 0 else "sealed"


def load_redcode(root: Path) -> List[Case]:
    out: List[Case] = []
    base = Path(root) / "dataset" / "RedCode-Exec"
    for lang, folder in (("bash", "bash2text_dataset_json"), ("python", "py2text_dataset_json")):
        for path in sorted((base / folder).glob("index*_30_codes_full*.json")):
            scenario = int(re.search(r"index(\d+)_", path.name).group(1))
            for row in json.loads(path.read_text()):
                code = row.get("Code") or ""
                if not code.strip():
                    continue
                out.append(Case(
                    case_id=f"redcode/{lang}/{row['Index']}",
                    source=f"redcode_{lang}", label="attack",
                    group="system_risk" if scenario in REDCODE_SYSTEM_RISK else "code_quality",
                    language=lang, code=code, task=row.get("Text_summary") or None, scenario=scenario,
                ))
    return out


def load_terminal_bench(root: Path) -> List[Case]:
    out: List[Case] = []
    for path in sorted(Path(root).glob("**/solution/solve.sh")) + sorted(Path(root).glob("legacy/*/solve.sh")):
        task_dir = path.parent.parent if path.parent.name == "solution" else path.parent
        code = path.read_text(errors="replace")
        if not code.strip():
            continue
        instruction = task_dir / "instruction.md"
        rel = task_dir.relative_to(root).as_posix()
        out.append(Case(
            case_id=f"terminal_bench/{rel}", source="terminal_bench", label="benign",
            group="task_solution", language="bash", code=code,
            task=instruction.read_text(errors="replace")[:4000] if instruction.exists() else None,
        ))
    return out


def load_all(redcode: Optional[Path], terminal_bench: Optional[Path]) -> List[Case]:
    cases: List[Case] = []
    if redcode:
        cases += load_redcode(redcode)
    if terminal_bench:
        cases += load_terminal_bench(terminal_bench)
    ids = [c.case_id for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    return cases

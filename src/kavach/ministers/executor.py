"""EXECUTOR: flags well-known dangerous command and code-execution patterns."""
import re

from ..models import ActionEvent, Vote, VoteKind


_DANGEROUS_PATTERNS = (
    ("REMOTE_SCRIPT_TO_SHELL", re.compile(r"\b(curl|wget)\b[^\n|;]{0,200}\|\s*(sh|bash|zsh)\b", re.I)),
    ("ENCODED_POWERSHELL", re.compile(r"\bpowershell(?:\.exe)?\b.{0,60}-(?:enc|encodedcommand)\b", re.I)),
    ("REMOTE_MSHTA", re.compile(r"\bmshta\s+https?://", re.I)),
    ("REMOTE_REGSVR32", re.compile(r"\bregsvr32\b.{0,100}(?:/i:https?://|scrobj\.dll)", re.I)),
    ("REVERSE_SHELL", re.compile(r"\b(nc|ncat|netcat)\b.{0,120}\s-e\s+(sh|bash|cmd)", re.I)),
    ("DANGEROUS_PRIVILEGED_DOCKER", re.compile(r"\bdocker\s+run\b.{0,160}--privileged\b", re.I)),
    ("SHELL_EXECUTION_IN_CODE", re.compile(r"\b(os\.system|subprocess\.Popen|subprocess\.run)\s*\([^\n)]{0,180}shell\s*=\s*True", re.I)),
    ("DYNAMIC_EVAL", re.compile(r"\b(eval|exec)\s*\(\s*(?:base64\.b64decode|atob)\s*\(", re.I)),
)


def _strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield str(value)


class ExecutorMinister:
    name = "EXECUTOR"

    def evaluate(self, event: ActionEvent) -> Vote:
        text = " ".join([event.tool_name, event.operation, *_strings(event.arguments)])
        for rule_id, pattern in _DANGEROUS_PATTERNS:
            match = pattern.search(text)
            if match:
                return Vote(self.name, VoteKind.BLOCK, f"{rule_id}:{match.group(0)}")
        return Vote(self.name, VoteKind.ALLOW, "NO_DANGEROUS_EXECUTION_PATTERN")

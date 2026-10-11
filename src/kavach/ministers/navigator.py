"""NAVIGATOR: flags explicit prompt-injection and instruction-hijack strings.

This small lexical detector is deliberately inspectable; it is not the original
embedding/retrieval pipeline and should not be described as semantic detection.
"""
import re

from ..models import ActionEvent, Vote, VoteKind


_ATTACK_PATTERNS = (
    ("IGNORE_PRIOR_INSTRUCTIONS", re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I)),
    ("SYSTEM_PROMPT_EXTRACTION", re.compile(r"(reveal|print|show|exfiltrate).{0,40}(system prompt|hidden instructions|developer message)", re.I)),
    ("INSTRUCTION_OVERRIDE", re.compile(r"(disregard|override|forget).{0,40}(safety|system|developer|previous instructions)", re.I)),
    ("TOOL_ABUSE_INSTRUCTION", re.compile(r"(send|upload|email).{0,80}(secret|credential|api key|private key)", re.I)),
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


class NavigatorMinister:
    name = "NAVIGATOR"

    def evaluate(self, event: ActionEvent) -> Vote:
        text = " ".join([event.tool_name, event.operation, *_strings(event.arguments)])
        for rule_id, pattern in _ATTACK_PATTERNS:
            match = pattern.search(text)
            if match:
                return Vote(self.name, VoteKind.REVIEW, f"{rule_id}:{match.group(0)}")
        return Vote(self.name, VoteKind.ALLOW, "NO_KNOWN_INJECTION_PHRASE")

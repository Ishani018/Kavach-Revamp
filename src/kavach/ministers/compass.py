"""COMPASS: flags consequential actions poorly aligned with explicit user intent.

This is a transparent lexical heuristic, not a semantic model or an authorization
system. It only reviews; it never blocks on intent mismatch alone.
"""
import re

from ..models import ActionEvent, Vote, VoteKind

_STOPWORDS = {
    "the", "a", "an", "to", "for", "and", "or", "of", "in", "on", "with",
    "my", "me", "please", "can", "you", "do", "it", "this", "that", "from",
}
_CONSEQUENTIAL = re.compile(r"(send|share|delete|remove|transfer|purchase|pay|execute|shell|write|upload)", re.I)


def _tokens(text: str) -> set[str]:
    return {word for word in re.findall(r"[a-z0-9_]+", text.lower()) if len(word) > 2 and word not in _STOPWORDS}


class CompassMinister:
    name = "COMPASS"

    def evaluate(self, event: ActionEvent) -> Vote:
        if not event.user_intent or not event.user_intent.strip():
            return Vote(self.name, VoteKind.ALLOW, "NO_INTENT_SIGNAL_CONFIGURED")

        action_text = " ".join([event.tool_name, event.operation, str(event.arguments)])
        intent_tokens = _tokens(event.user_intent)
        action_tokens = _tokens(action_text)
        if not intent_tokens:
            return Vote(self.name, VoteKind.ALLOW, "INTENT_HAS_NO_COMPARABLE_TERMS")

        overlap = len(intent_tokens & action_tokens) / len(intent_tokens)
        if overlap < 0.10 and _CONSEQUENTIAL.search(action_text):
            return Vote(self.name, VoteKind.REVIEW, f"LOW_INTENT_OVERLAP:{overlap:.2f}")
        return Vote(self.name, VoteKind.ALLOW, f"INTENT_OVERLAP:{overlap:.2f}")

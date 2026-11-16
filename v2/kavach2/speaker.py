"""Speaker: turns the reviewers' opinions into one verdict. Deterministic."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .types import Action, Opinion, Reviewer, Session, Verdict


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    opinions: tuple[Opinion, ...]


class Speaker:
    def __init__(self, reviewers: Sequence[Reviewer]):
        self.reviewers = tuple(reviewers)

    def decide(self, action: Action, session: Session) -> Decision:
        # An action its tool declares read-only is not reviewed. Known limit: a "read" that sends
        # data out (a fetch with data in the URL) is only caught if the tool declares it honestly.
        if action.changes_state is False:
            return Decision(Verdict.ALLOW, "tool declares the action read-only", ())
        opinions = []
        for reviewer in self.reviewers:
            try:
                opinions.append(reviewer.review(action, session))
            except Exception:  # a reviewer that fails must not become a silent allow
                opinions.append(Opinion(reviewer.name, Verdict.ASK, "reviewer failed"))
        if not opinions:
            return Decision(Verdict.ALLOW, "no reviewers configured", ())
        worst = max(opinions, key=lambda o: o.verdict.severity)
        return Decision(worst.verdict, f"{worst.reviewer}: {worst.reason}", tuple(opinions))

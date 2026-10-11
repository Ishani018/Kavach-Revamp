"""The Speaker is the only component that combines minister votes."""
from collections.abc import Sequence

from .models import Verdict, Vote, VoteKind


def speak(votes: Sequence[Vote]) -> Verdict:
    """Combine votes with a small, conservative priority order."""
    kinds = {vote.kind for vote in votes}

    if VoteKind.BLOCK in kinds:
        return Verdict.BLOCK
    if VoteKind.REVIEW in kinds:
        return Verdict.REVIEW
    if not votes or VoteKind.ABSTAIN in kinds:
        return Verdict.INDETERMINATE
    if kinds == {VoteKind.ALLOW}:
        return Verdict.ALLOW

    # Defensive fallback for an unexpected or incomplete vote set.
    return Verdict.INDETERMINATE

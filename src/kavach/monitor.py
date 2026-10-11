"""Thin wiring: run each minister, then ask the Speaker for one verdict."""
from collections.abc import Sequence

from .models import ActionEvent, Verdict, Vote
from .speaker import speak


class Monitor:
    def __init__(self, ministers: Sequence[object]) -> None:
        self.ministers = tuple(ministers)

    def evaluate(self, event: ActionEvent) -> tuple[Verdict, tuple[Vote, ...]]:
        votes = tuple(minister.evaluate(event) for minister in self.ministers)
        return speak(votes), votes

"""The only wiring layer: run ministers, then let the Speaker combine their votes."""
from collections.abc import Sequence

from .models import ActionEvent, Verdict, Vote
from .speaker import speak


class Monitor:
    def __init__(self, ministers: Sequence[object] | None = None) -> None:
        if ministers is None:
            from .ministers.vault import VaultMinister
            from .ministers.executor import ExecutorMinister
            from .ministers.channel import ChannelMinister
            from .ministers.compass import CompassMinister
            from .ministers.navigator import NavigatorMinister
            from .ministers.trajectory import TrajectoryMinister

            ministers = (
                VaultMinister(),
                ExecutorMinister(),
                ChannelMinister(),
                CompassMinister(),
                NavigatorMinister(),
                TrajectoryMinister(),
            )
        self.ministers = tuple(ministers)

    def evaluate(self, event: ActionEvent) -> tuple[Verdict, tuple[Vote, ...]]:
        votes = tuple(minister.evaluate(event) for minister in self.ministers)
        return speak(votes), votes

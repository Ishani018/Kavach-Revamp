import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def navigator():
    """The Invariant-backed NAVIGATOR; no embeddings, vector database, or API key."""
    from kavach.ministers.navigator import NavigatorMinister

    return NavigatorMinister()

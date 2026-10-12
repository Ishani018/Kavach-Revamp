import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def navigator(tmp_path_factory):
    """The real NAVIGATOR (loads BGE, builds a scratch ChromaDB). ~20s once per run."""
    from kavach.ministers.navigator import NavigatorMinister

    return NavigatorMinister(chroma_path=tmp_path_factory.mktemp("chroma"))

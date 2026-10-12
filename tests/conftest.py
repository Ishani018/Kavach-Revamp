import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def navigator(tmp_path_factory):
    """The real NAVIGATOR (loads BGE, builds a scratch ChromaDB). ~20s once per run."""
    from kavach.ministers.navigator import NavigatorMinister

    return NavigatorMinister(chroma_path=tmp_path_factory.mktemp("chroma"))


def pytest_configure(config):
    config.addinivalue_line("markers", "current_behaviour: records what NAVIGATOR does today (frozen baseline); passing does not mean the behaviour is desirable")
    config.addinivalue_line("markers", "desired_behaviour: specifies what NAVIGATOR should do; expected to fail (strict xfail) until the issue is fixed. Run with --runxfail to see the real failures")


@pytest.fixture(scope="session")
def nav_baseline():
    from tests import navigator_support as ns
    return ns.baseline(), ns.rows()


@pytest.fixture(scope="session")
def nav_replay(navigator, nav_baseline):
    """Replays the frozen test sample, wrapper probes and pattern canaries through the CURRENT navigator."""
    import importlib.util, sys
    from tests import navigator_support as ns
    b, rows = nav_baseline
    ok, why = ns.environment_matches(b)
    if not ok:
        pytest.skip("environment differs from the frozen baseline: " + why)
    verify = ns._load("verify_baseline_mod", ns.BASE / "verify_baseline.py")
    subset = [r for r in rows if r["test_sample"] or r["set"] in ("wrapper_probe", "canary_doc")]
    calls = verify.calls_for(subset)
    return subset, verify.replay(navigator, subset, calls), calls

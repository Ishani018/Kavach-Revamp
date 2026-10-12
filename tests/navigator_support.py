"""Helpers for the NAVIGATOR baseline and desired-behaviour tests (see review/navigator-baseline/)."""
import importlib.util
import json
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "review" / "navigator-baseline"
sys.path.insert(0, str(BASE))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


guard = _load("regression_guard_mod", BASE / "regression_guard.py")
freeze = _load("freeze_baseline_mod", BASE / "freeze_baseline.py")
diag = freeze.explainer_module()


def baseline():
    return json.loads((BASE / "navigator_baseline.json").read_text())


def rows():
    return guard.load_rows()


def environment_matches(b):
    """Exact-number tests are only meaningful where the library and model versions equal the frozen ones."""
    try:
        for p, v in b["environment"]["packages"].items():
            if metadata.version(p) != v:
                return False, f"{p} {metadata.version(p)} != frozen {v}"
    except metadata.PackageNotFoundError as e:
        return False, str(e)
    m = freeze.model_info()
    if m["weights_sha256_from_blob_name"] != b["model"]["weights_sha256_from_blob_name"]:
        return False, "embedding model weights differ from the frozen baseline"
    return True, ""


def command_of(call):
    import re
    m = re.match(r"tool:\S+\s+args:(\{.*\})\s*$", call, re.S)
    return (json.loads(m.group(1)).get("command") if m else None) or ""

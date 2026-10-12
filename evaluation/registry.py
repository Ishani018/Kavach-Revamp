"""Load the curated dataset registry and resolve examples."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .loaders import LOADERS, Example

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path(__file__).resolve().parent / "registry.json"
MANIFEST_PATH = Path(__file__).resolve().parent / "manifest.json"

ROLES = ("unit_test_fixture", "development_tuning", "historical_benchmark_result", "held_out_evaluation")
HELD_OUT_VERIFIED = "verified_held_out"   # no registered dataset has this value; see README


def load_registry() -> Dict[str, Any]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def datasets(registry: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    return (registry or load_registry())["datasets"]


def load_examples(entry: Dict[str, Any]) -> List[Example]:
    """Examples of a dataset that has a local copy and a loader."""
    loader = LOADERS[entry["format"]]
    path = ROOT / entry["path"]
    return loader(entry["id"], path, entry["label"]) if "label" in entry else loader(entry["id"], path)

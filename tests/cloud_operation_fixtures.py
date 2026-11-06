"""Frozen command inputs for native cloud regressions; no Python matchers."""

from __future__ import annotations

import json
from pathlib import Path

_FIXTURE = json.loads((Path(__file__).parent / "fixtures/cloud-operation-paths.v1.json").read_text(encoding="utf-8"))
assert _FIXTURE["schema"] == "guard.cloud-operation-test-inputs.v1"


def _paths(name: str) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(path) for path in _FIXTURE["paths"][name])


AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1 = _paths("AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1")
AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4 = _paths("AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4")
AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5 = _paths("AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5")
AWS_DESTRUCTIVE_COMMAND_PATHS = (
    AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_1
    + AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_4
    + AWS_DESTRUCTIVE_COMMAND_PATHS_BATCH_5
)
AZURE_DESTRUCTIVE_COMMAND_PATHS = _paths("AZURE_DESTRUCTIVE_COMMAND_PATHS")
GCP_DESTRUCTIVE_COMMAND_PATHS = _paths("GCP_DESTRUCTIVE_COMMAND_PATHS")

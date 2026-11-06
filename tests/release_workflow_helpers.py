"""Shared loaders for GitHub workflow contract tests."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
NATIVE_WHEEL_WORKFLOW = ROOT / ".github/workflows/release-native-wheel.yml"
NATIVE_WHEEL_LANES = ("linux-x64", "macos-x64", "macos-arm64", "windows-x64", "windows-arm64", "linux-arm64")
# The Linux ARM64 wheel compiles in its own job; it has no warm-cache preparation lane.
PREPARED_WHEEL_LANES = NATIVE_WHEEL_LANES[:5]


def load_workflow(path: Path) -> dict[object, object]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    return workflow


def native_wheel_job() -> dict:
    return load_workflow(NATIVE_WHEEL_WORKFLOW)["jobs"]["wheel"]


def native_target_matrix(job: dict) -> dict:
    expression = job["strategy"]["matrix"]["include"]
    match = re.fullmatch(
        r"\$\{\{ fromJSON\('([^']+)'\)\[inputs.target(?: \|\| '')?\] \|\| fromJSON\('\[\]'\) \}\}",
        expression,
    )
    assert match is not None, expression
    return json.loads(match.group(1))

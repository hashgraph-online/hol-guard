"""Branch contracts for release/3.2 pull-request validation."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE_BRANCH = "release/3.2"

PR_GATE_WORKFLOWS = (
    ".github/workflows/cline-contract-ci.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/native-release-contract.yml",
    ".github/workflows/native-wheel-ci.yml",
    ".github/workflows/guard-network-remediation-proof.yml",
    ".github/workflows/guard-gvisor-reference.yml",
    ".github/workflows/extension-control-center-installed-ci.yml",
)


def _triggers(relative_path: str) -> dict[str, object]:
    workflow = cast(
        dict[object, object],
        yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8")),
    )
    return cast(dict[str, object], workflow[True])


def _branches(trigger: object) -> list[str]:
    return cast(list[str], cast(dict[str, object], trigger)["branches"])


def test_release_32_pull_requests_receive_required_product_gates() -> None:
    for relative_path in PR_GATE_WORKFLOWS:
        triggers = _triggers(relative_path)

        assert RELEASE_BRANCH in _branches(triggers["pull_request"]), relative_path


def test_release_32_gate_expansion_does_not_authorize_push_publication() -> None:
    publish_triggers = _triggers(".github/workflows/publish.yml")

    assert RELEASE_BRANCH not in _branches(publish_triggers["push"])

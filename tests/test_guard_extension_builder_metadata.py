"""Inventory discovery must not claim a semantic review or active protection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest

from tests.extension_builder_support import make_kit


@pytest.mark.parametrize("kind", ["cli", "mcp"])
@pytest.mark.parametrize("reviewed", [False, True])
def test_generated_metadata_does_not_imply_review_or_activation(
    tmp_path: Path, kind: Literal["cli", "mcp"], reviewed: bool
) -> None:
    kit = make_kit(tmp_path, kind, reviewed=reviewed)
    files = dict(kit.files)
    contribution_name = next(name for name in files if name.startswith("artifacts/contributions/"))
    contribution = json.loads(files[contribution_name])
    assert contribution["description"] == "Conservative operation knowledge compiled from a contributor inventory."
    assert contribution["trustClass"] == "external"
    assert contribution["activation"] == "opt-in"
    report = json.loads(files["report.json"])
    expected_reviewed = len(kit.discovery.operations) if reviewed else 0
    assert report["reviewedOperations"] == expected_reviewed
    assert report["activeProtectionChanged"] is False

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.authority_workflow_contract import require_unfiltered_release_pull_requests
from scripts.ci.rust_authority_ownership_gate import _workflow_gate


def test_actual_release_authority_workflows_retain_complete_diff_and_installed_gates() -> None:
    _workflow_gate()


@pytest.mark.parametrize(
    "trigger",
    (
        "branches: [main]",
        "branches: [release/3.2]",
        "branches: [main, release/3.2, '!release/3.2']",
        "paths: ['rust/**']",
        "paths-ignore: ['docs/**']",
        "branches-ignore: [release/3.2]",
        "types: [opened, reopened]",
    ),
)
def test_missing_branch_or_filtered_changes_cannot_bypass_authority_gate(trigger: str) -> None:
    source = f"on:\n  pull_request:\n    {trigger}\npermissions:\n  contents: read\n"
    with pytest.raises(RuntimeError):
        require_unfiltered_release_pull_requests(source, label="test workflow")


@pytest.mark.parametrize("trigger", ("", "\n    branches: [release/3.2, main]"))
def test_unfiltered_events_and_equivalent_branch_order_are_accepted(trigger: str) -> None:
    source = f"on:\n  pull_request:{trigger}\npermissions:\n  contents: read\n"
    require_unfiltered_release_pull_requests(source, label="test workflow")


def test_current_workflow_loses_required_diff_gate_when_fetch_depth_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative = Path(".github/workflows/rust-authority-ownership.yml")
    source = relative.read_text().replace("fetch-depth: 0", "fetch-depth: 1")
    destination = tmp_path / relative
    destination.parent.mkdir(parents=True)
    destination.write_text(source)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="fetch-depth: 0"):
        _workflow_gate()

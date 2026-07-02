from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.inventory_cisco import run_cisco_inventory_scans
from codex_plugin_scanner.guard.models import HarnessDetection


def test_local_cisco_inventory_runs_mark_cloud_required_provenance(tmp_path: Path) -> None:
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / ".hol-guard")
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(),
    )

    runs = run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=detection,
        mcp_mode="auto",
        skill_mode="auto",
        timeout_seconds=1,
    )

    assert {run.source for run in runs} == {"cisco-mcp-scanner", "cisco-skill-scanner"}
    for run in runs:
        assert run.metadata.get("evidenceProvenance") == "client_unverified"
        assert run.metadata.get("scannerAuthority") == "local_reported"
        assert run.metadata.get("scannerVerificationRequired") == "guard_cloud"

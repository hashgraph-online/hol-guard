from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.inventory_cisco import run_cisco_inventory_scans
from codex_plugin_scanner.guard.models import HarnessDetection


def _ctx(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True)
    workspace_dir.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )


def test_cisco_inventory_scans_mark_local_results_as_cloud_required(
    tmp_path: Path,
) -> None:
    runs = run_cisco_inventory_scans(
        harness="hermes",
        context=_ctx(tmp_path),
        detection=HarnessDetection(
            harness="hermes",
            installed=True,
            command_available=False,
            config_paths=(),
            artifacts=(),
        ),
        mcp_mode="auto",
        skill_mode="auto",
    )

    assert {run.source for run in runs} == {
        "cisco-mcp-scanner",
        "cisco-skill-scanner",
    }
    assert all(run.metadata.get("evidenceProvenance") == "client_unverified" for run in runs)
    assert all(run.metadata.get("scannerResolutionSource") == "local_reported" for run in runs)
    assert all(run.metadata.get("scannerVerificationRequired") == "guard_cloud" for run in runs)

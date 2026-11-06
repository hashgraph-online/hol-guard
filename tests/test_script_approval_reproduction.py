"""Realistic Bash review regression with exclusively disposable effects.

The worker exercises the actual resident hook decision. It does not claim
host execution or immutable delivery: those require the managed OMP lane.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "script_approvals"


@pytest.fixture
def maintenance_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    bin_dir = home / "bin"
    bin_dir.mkdir()
    shutil.copyfile(FIXTURES / "maintenance.sh", workspace / "maintenance.sh")
    cli = bin_dir / "fixture-registry"
    shutil.copyfile(FIXTURES / "fixture-registry", cli)
    cli.chmod(0o755)
    for repository in ("alpha", "beta"):
        target = home / "fixture-registry" / repository / "obsolete"
        target.parent.mkdir(parents=True)
        target.write_text("protected deletion sentinel\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", os.pathsep.join((str(bin_dir), "/usr/bin", "/bin")))
    monkeypatch.delenv("BASH_ENV", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    return home, workspace


def test_fixture_has_distinct_report_and_deletion_effects(maintenance_lab: tuple[Path, Path]) -> None:
    home, workspace = maintenance_lab
    subprocess.run(["/bin/bash", "maintenance.sh", "dry"], cwd=workspace, check=True)
    report = home / "maintenance-report.tsv"
    assert report.read_text().splitlines() == [
        "alpha/current",
        "alpha/obsolete",
        "alpha\tlocal metadata",
        "beta/current",
        "beta/obsolete",
        "beta\tlocal metadata",
    ]
    assert all((home / "fixture-registry" / repo / "obsolete").is_file() for repo in ("alpha", "beta"))
    subprocess.run(["/bin/bash", "maintenance.sh", "delete"], cwd=workspace, check=True)
    assert all(not (home / "fixture-registry" / repo / "obsolete").exists() for repo in ("alpha", "beta"))


@pytest.mark.parametrize("mode", ["dry", "delete"])
def test_unbound_maintenance_launch_can_still_be_approved(
    maintenance_lab: tuple[Path, Path],
    native_approval_reuse_runtime: Path,
    mode: str,
) -> None:
    from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
    from codex_plugin_scanner.guard.approvals import apply_approval_resolution
    from codex_plugin_scanner.guard.config import update_guard_settings
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.store import GuardStore

    home, workspace = maintenance_lab
    store = GuardStore(home / ".hol-guard")
    update_guard_settings(store.guard_home, {"mode": "enforce", "subprocess_action": "review"})
    report = home / "maintenance-report.tsv"
    protected = home / "protected-report"
    protected.write_text("protected output sentinel\n")
    report.symlink_to(protected)
    command = f"/bin/bash {shlex.quote(str(workspace / 'maintenance.sh'))} {mode}"
    worker = HookWorker(store=store, workspace=workspace)
    try:
        result = worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": command},
                "tool_call_id": f"maintenance-{mode}",
                "session_id": "maintenance-reproduction",
                "cwd": str(workspace),
            },
            params={},
            default_harness="omp",
            home_dir=home,
            guard_home=store.guard_home,
            workspace=workspace,
        )
        assert result["policy_action"] != "allow", result
        rows = store.list_approval_requests(status="pending")
        assert len(rows) == 1, (result, rows)
        contract = request_scope_contract(rows[0])
        # Guard cannot prove what the script does, but the user can still approve
        # it; the approval binds the command (docs/guard/approval-invariant.md).
        assert "retry_cannot_reuse_approval" not in contract.restrictions
        assert contract.exact_action_persistence_eligible
        assert contract.once_only_reason is None
        assert contract.can_run_once
        apply_approval_resolution(
            store=store,
            request_id=rows[0]["request_id"],
            action="allow",
            scope="artifact",
            workspace=str(workspace),
            reason="isolated approval regression",
            scope_contract_version=contract.version,
            scope_contract_digest=contract.digest,
            return_queue_result=True,
        )
        assert store.get_approval_request(rows[0]["request_id"])["status"] != "pending"
    finally:
        worker.close()
    assert protected.read_text() == "protected output sentinel\n"
    assert all((home / "fixture-registry" / repo / "obsolete").is_file() for repo in ("alpha", "beta"))

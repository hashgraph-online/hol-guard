"""End-to-end background assessment through the compiled runtime.

The run uses the real snapshot and the real local supply-chain audit against
a cached advisory bundle. The premium Cloud audit is replaced with a failure,
so a passing run also proves the background path never reaches it.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_supply_chain_egress as egress_module
from codex_plugin_scanner.guard import supply_chain_cloud_audit as cloud_audit_module
from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_workspace import bind_workspace
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request
from tests.test_guard_phase06_workspace_audit import WORKSPACE_AUDIT_NOW, _seed_premium_entitlement
from tests.test_guard_supply_chain_evaluator import WORKSPACE_ID, _bundle_response, _force_cloud_fallback, _package

LOCKFILE = {
    "packages": {
        "": {"dependencies": {"minimist": "^1.2.0"}},
        "node_modules/minimist": {"version": "1.2.8"},
    }
}


@pytest.fixture
def native_binary() -> None:
    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")


def test_background_run_reports_a_blocked_dependency_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_binary: None
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"dependencies":{"minimist":"^1.2.0"}}', encoding="utf-8")
    (workspace / "package-lock.json").write_text(json.dumps(LOCKFILE), encoding="utf-8")
    (workspace / "notes.txt").write_text("untracked and dirty files are part of the snapshot", encoding="utf-8")
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    bind_workspace(store, WORKSPACE_ID)
    bundle = _package(
        ecosystem="npm", name="minimist", version="1.2.8", default_action="block", recommended_fix_version="1.2.9"
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(packages=[bundle]), WORKSPACE_AUDIT_NOW)
    _force_cloud_fallback(monkeypatch)

    def no_cloud_audit(*args, **kwargs):
        raise AssertionError("background assessment must not call the Cloud audit")

    monkeypatch.setattr(cloud_audit_module, "_run_cloud_workspace_audit", no_cloud_audit)

    admitted = worker.admit_workspace(store, str(workspace))
    keys = assessments.WorktreeKeys(str(admitted["codebase_key"]), str(admitted["worktree_key"]))
    # A manual request skips the debounce an automatic open run waits for.
    assert worker.queue_manual_run(store, keys) == admitted["run_id"]
    assert runner.run_next(store, load_guard_config(store.guard_home), owner="test")
    [latest] = assessments.latest_assessed_runs(store)
    assert latest["run_id"] == admitted["run_id"]
    assert latest["state"] in {"completed", "partial"}
    assert latest["coverage"]["detectors"]["secrets"] == "complete"
    assert "detector_not_run:secrets" not in latest["coverage"]["reasons"]
    [finding] = [item for item in latest["findings"] if item["package_name"] == "minimist"]
    assert (finding["decision"], finding["package_version"], finding["fix_version"]) == ("block", "1.2.8", "1.2.9")
    assert str(workspace) not in json.dumps(latest)

    (workspace / "notes.txt").write_text("edited", encoding="utf-8")
    assert worker.observe(store) == 1


def test_automatic_run_never_reaches_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_binary: None
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"dependencies":{"minimist":"^1.2.0"}}', encoding="utf-8")
    (workspace / "package-lock.json").write_text(json.dumps(LOCKFILE), encoding="utf-8")
    store = GuardStore(tmp_path / "guard-home")
    bind_workspace(store, WORKSPACE_ID)
    bundle = _package(
        ecosystem="npm", name="minimist", version="1.2.8", default_action="block", recommended_fix_version="1.2.9"
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, _bundle_response(packages=[bundle]), WORKSPACE_AUDIT_NOW)

    def no_network(*args, **kwargs):
        raise AssertionError("an automatic assessment must not open a connection")

    monkeypatch.setattr(egress_module, "_fetch_raw", no_network)
    opened = 1_000_000_000
    admitted = worker.admit_workspace(store, str(workspace), clock=lambda: opened)
    due = opened + assessments.MAX_DEBOUNCE_WAIT_MS
    assert runner.run_next(store, load_guard_config(store.guard_home), owner="test", clock=lambda: due)
    [latest] = assessments.latest_assessed_runs(store)
    assert (latest["run_id"], latest["trigger_kind"]) == (admitted["run_id"], "workspace_open")
    # Both detectors ran over the whole worktree, so nothing keeps the run partial.
    assert latest["state"] == "completed"
    assert latest["coverage"]["detectors"]["secrets"] == "complete"
    [finding] = [item for item in latest["findings"] if item["package_name"] == "minimist"]
    assert finding["decision"] == "block"


def test_daemon_routes_require_dashboard_auth_and_admit_a_worktree(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        path = "/v1/supply-chain/workspace-assessments"
        anonymous, _ = _read_json_response(_request(daemon.port, path, method="GET"))
        token = _dashboard_token_for(store)
        admitted_status, admitted = _read_json_response(
            _request(daemon.port, path, token=token, payload={"root": str(workspace)})
        )
        listed_status, listing = _read_json_response(_request(daemon.port, path, method="GET", token=token))
        findings_status, _ = _read_json_response(
            _request(daemon.port, "/v1/supply-chain/workspace-findings", method="GET", token=token)
        )
    finally:
        daemon.stop()
    assert anonymous in {401, 403}
    assert admitted_status == 202 and admitted["run_id"]
    assert listed_status == findings_status == 200
    [worktree] = listing["worktrees"]
    assert worktree["worktree_key"] == admitted["worktree_key"]


def test_findings_route_resolves_the_suggested_folder_like_a_tracked_root(tmp_path: Path, native_binary: None) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(workspace, target_is_directory=True)
    other = tmp_path / "other"
    other.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        path = "/v1/supply-chain/workspace-assessments"
        token = _dashboard_token_for(store)
        _read_json_response(_request(daemon.port, path, token=token, payload={"root": str(workspace)}))

        def tracked(root: str | None) -> object:
            suffix = "" if root is None else "?root=" + urllib.parse.quote(root, safe="")
            _, body = _read_json_response(
                _request(daemon.port, "/v1/supply-chain/workspace-findings" + suffix, method="GET", token=token)
            )
            return body.get("suggested_root_tracked", "absent")

        assert tracked(None) == "absent"
        assert tracked(str(workspace)) is True
        assert tracked(str(alias) + "/") is True
        assert tracked(f"{workspace}/../workspace") is True
        assert tracked(str(other)) is False
        assert tracked("relative/path") is False
    finally:
        daemon.stop()

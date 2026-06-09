"""Phase 04 intercept proofs for package-manager shims and daemon test action."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.shims import install_package_shims, probe_package_shim_intercepts
from codex_plugin_scanner.guard.store import GuardStore
from tests.shim_execution_helpers import write_fake_manager_script
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request


def _harness_context(tmp_path: Path, *, workspace_dir: Path | None = None) -> HarnessContext:
    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )


def test_shim_execution_helper_records_fake_manager_invocation(tmp_path: Path) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    marker_path = tmp_path / "npm-marker.json"
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=marker_path,
        exit_code=0,
    )
    result = subprocess.run(
        [str(fake_bin / "npm"), "install", "lodash"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    payload = json.loads(marker_path.read_text(encoding="utf-8"))
    assert payload["argv"][1:] == ["install", "lodash"]


def test_package_shim_intercept_probe_records_evaluator_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    context = _harness_context(tmp_path, workspace_dir=workspace_dir)
    install_package_shims(context, managers=("npm",))
    shim_dir = context.guard_home / "package-shims" / "bin"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=tmp_path / "npm-never-runs.json",
        exit_code=0,
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    result = probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=workspace_dir)

    assert result["intercept_proved"] is True
    manager_result = result["manager_results"][0]
    assert manager_result["manager"] == "npm"
    assert manager_result["evaluator_invoked"] is True
    assert manager_result["intercept_ran"] is True
    assert manager_result.get("protect_decision") in {"allow", "review", "block", "monitor"}


def test_package_shim_intercept_skips_tampered_shim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    context = _harness_context(tmp_path, workspace_dir=workspace_dir)
    install_package_shims(context, managers=("npm",))
    shim_dir = context.guard_home / "package-shims" / "bin"
    (shim_dir / "npm").write_text("#!/bin/sh\necho tampered", encoding="utf-8")
    monkeypatch.setenv("PATH", str(shim_dir))

    result = probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=workspace_dir)

    assert result["intercept_proved"] is False
    assert result["manager_results"] == [
        {
            "evaluator_invoked": False,
            "intercept_ran": False,
            "manager": "npm",
            "skipped_reason": "shim_tampered",
        },
    ]


def test_daemon_package_shim_test_reports_path_inactive_without_evaluator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        "2026-05-27T16:00:00.000Z",
        workspace_id="workspace-1",
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        install_status, _install_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
        test_status, test_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert install_status == 200
    assert test_status == 200
    assert test_payload["result"]["intercept_proved"] is False
    assert test_payload["result"]["manager_results"][0]["skipped_reason"] == "path_inactive"
    assert test_payload["result"]["manager_results"][0]["evaluator_invoked"] is False

"""Phase 04 intercept proofs for package-manager shims and daemon test action."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import shims as shims_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.shims import install_package_shims, probe_package_shim_intercepts
from codex_plugin_scanner.guard.store import GuardStore
from tests.shim_execution_helpers import (
    manager_probe_args,
    parse_protect_json_output,
    protect_evaluator_evidence,
    write_fake_manager_script,
)
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


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


def test_parse_protect_json_output_ignores_trailing_manager_stdout() -> None:
    payload = {
        "dry_run": True,
        "supply_chain_evaluation": {"evidence_ids": [42, "ev-1"]},
        "verdict": {"action": "allow"},
    }
    stdout = json.dumps(payload) + "\nnpm notice dry-run complete\n"
    parsed = parse_protect_json_output(stdout)
    evidence = protect_evaluator_evidence(parsed)
    assert evidence["evaluator_invoked"] is True
    assert evidence["protect_decision"] == "allow"
    assert evidence["evidence_ids"] == ["42", "ev-1"]


def test_manager_probe_args_include_dry_run_for_npm() -> None:
    assert manager_probe_args("npm") == ("install", "--dry-run", "lodash@4.17.21")
    assert manager_probe_args("brew") == ("install", "--dry-run", "jq")


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


def test_package_shim_intercept_probe_records_evaluator_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    assert not (tmp_path / "npm-never-runs.json").exists()


def test_package_shim_intercept_probe_marks_hung_manager_as_probe_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    context = _harness_context(tmp_path, workspace_dir=workspace_dir)
    install_package_shims(context, managers=("npm",))
    shim_dir = context.guard_home / "package-shims" / "bin"
    monkeypatch.setenv("PATH", str(shim_dir))

    def raise_timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["npm"], timeout=15)

    monkeypatch.setattr(shims_module.subprocess, "run", raise_timeout)

    result = probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=workspace_dir)

    assert result["intercept_proved"] is False
    assert result["manager_results"] == [
        {
            "evaluator_invoked": False,
            "intercept_ran": False,
            "manager": "npm",
            "skipped_reason": "probe_failed",
        },
    ]


def test_package_shim_intercept_probe_timeout_covers_store_busy_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    captured_timeout: dict[str, int] = {}

    def raise_timeout(*_args, **kwargs):
        captured_timeout["value"] = kwargs["timeout"]
        raise subprocess.TimeoutExpired(cmd=["npm"], timeout=kwargs["timeout"])

    monkeypatch.setattr(shims_module.subprocess, "run", raise_timeout)

    result = probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=workspace_dir)

    assert result["intercept_proved"] is False
    assert result["manager_results"][0]["skipped_reason"] == "probe_failed"
    assert captured_timeout["value"] == shims_module._PACKAGE_SHIM_PROBE_TIMEOUT_SECONDS
    assert captured_timeout["value"] > 15


def test_package_shim_intercept_probe_omits_manager_stdout_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
        marker_path=tmp_path / "npm-secret-marker.json",
        exit_code=0,
        stdout_text="npm token=npm_super_secret_value",
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    result = probe_package_shim_intercepts(context, managers=("npm",), workspace_dir=workspace_dir)
    manager_result = result["manager_results"][0]

    assert manager_result["evaluator_invoked"] is True
    serialized = json.dumps(manager_result)
    assert "npm_super_secret_value" not in serialized


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
    _seed_guard_cloud(store, workspace_id="workspace-1")
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

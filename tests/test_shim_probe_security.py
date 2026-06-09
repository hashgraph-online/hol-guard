"""Security tests for package-shim probe and pip3 parser coverage."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.protect import parse_protect_command
from codex_plugin_scanner.guard.runtime.package_intent import parse_package_intent
from codex_plugin_scanner.guard.shim_probe import parse_protect_json_stdout
from codex_plugin_scanner.guard.shims import install_package_shims, probe_package_shim_intercepts
from tests.shim_execution_helpers import write_fake_manager_script


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


def test_shim_probe_does_not_invoke_real_package_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    context = _harness_context(tmp_path, workspace_dir=workspace_dir)
    install_package_shims(context, managers=("npm", "bundle", "cargo"))
    shim_dir = context.guard_home / "package-shims" / "bin"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(parents=True)
    for manager in ("npm", "bundle", "cargo"):
        write_fake_manager_script(
            fake_bin=fake_bin,
            manager=manager,
            marker_path=tmp_path / f"{manager}-probe-marker.json",
            exit_code=0,
        )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    result = probe_package_shim_intercepts(
        context,
        managers=("npm", "bundle", "cargo"),
        workspace_dir=workspace_dir,
    )

    assert result["intercept_proved"] is True
    for manager in ("npm", "bundle", "cargo"):
        marker_path = tmp_path / f"{manager}-probe-marker.json"
        assert not marker_path.exists(), f"{manager} shim executed real package manager during probe"
        manager_result = next(item for item in result["manager_results"] if item["manager"] == manager)
        assert manager_result["evaluator_invoked"] is True


def test_parse_protect_command_treats_pip3_as_pip_install() -> None:
    request = parse_protect_command(["pip3", "install", "requests==2.32.3"])

    assert request.install_kind == "package_install"
    assert request.executor == "pip"
    assert request.targets[0].package_name == "requests"
    assert request.targets[0].ecosystem == "pip"


def test_parse_package_intent_treats_pip3_as_pip_install(tmp_path: Path) -> None:
    intent = parse_package_intent("pip3 install requests==2.32.3", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "pip"
    assert intent.intent_kind == "install"
    assert intent.targets[0].package_name == "requests"


def test_package_shim_test_requires_approval_gate_when_enabled(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request

    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "local-password",
            "confirm_password": "local-password",
        },
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 403
    assert payload["error"] == "approval_gate_required"


def test_installed_shim_honors_probe_env_without_real_execution(
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
    marker_path = tmp_path / "npm-direct-marker.json"
    write_fake_manager_script(
        fake_bin=fake_bin,
        manager="npm",
        marker_path=marker_path,
        exit_code=0,
    )
    monkeypatch.setenv("PATH", os.pathsep.join([str(shim_dir), str(fake_bin)]))

    result = subprocess.run(
        [str(shim_dir / "npm"), "install", "--dry-run", "lodash@4.17.21"],
        capture_output=True,
        text=True,
        check=False,
        cwd=workspace_dir,
        env={**os.environ, "HOL_GUARD_SHIM_PROBE": "1"},
    )

    assert result.returncode == 0
    assert not marker_path.exists()
    payload = parse_protect_json_stdout(result.stdout)
    assert payload.get("dry_run") is True

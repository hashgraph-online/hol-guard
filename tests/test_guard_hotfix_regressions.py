"""Regression coverage for local-protection hotfix contracts."""

from __future__ import annotations

import argparse
import json
from io import StringIO
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals as approvals_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_preflight, commands_router
from codex_plugin_scanner.guard.cli.commands_preflight import _unsafe_broad_preflight_target
from codex_plugin_scanner.guard.managed_install_proof import bind_managed_install_proof
from codex_plugin_scanner.guard.package_firewall_entitlement import package_firewall_operation_allowed
from codex_plugin_scanner.guard.package_shim_status import enrich_package_shim_status_payload
from codex_plugin_scanner.guard.store import GuardStore


def _orphaned_shim_status(shim_dir: Path) -> dict[str, object]:
    return {
        "active_managers": [],
        "detected_managers": ["npm"],
        "installed_managers": [],
        "last_test_at": {},
        "protected_managers": [],
        "path_active": False,
        "path_contains_shim_dir": True,
        "path_status": "missing_from_path",
        "bypasses": [],
        "manager_details": [],
        "missing_managers": [],
        "restart_shell_required": False,
        "process_path_status": "active",
        "process_restart_required": False,
        "shell_profile_configured": True,
        "shim_dir": str(shim_dir),
        "supported_managers": ["npm"],
        "undetected_managers": [],
    }


def _guard_generated_shim_source(manager: str) -> str:
    return "\n".join(
        (
            "#!/usr/bin/python3",
            f"command_name = {manager!r}",
            "base_command = ['guard', 'protect', '--package-shim-ui']",
            "from codex_plugin_scanner.guard.package_shim_gate import (",
            "    package_shim_command_requires_guard,",
            ")",
        )
    )


def test_orphaned_guard_package_shim_is_recovered_for_repair(tmp_path: Path) -> None:
    shim_dir = tmp_path / "package-shims" / "bin"
    shim_dir.mkdir(parents=True)
    shim = shim_dir / "npm"
    shim.write_text(_guard_generated_shim_source("npm"), encoding="utf-8")

    status = enrich_package_shim_status_payload(_orphaned_shim_status(shim_dir), {})

    assert status["installed_managers"] == ["npm"]
    assert status["active_managers"] == ["npm"]
    assert status["recovered_managers"] == ["npm"]
    assert status["path_status"] == "in_path"
    assert status["protected_managers"] == []
    details = status["manager_details"]
    assert isinstance(details, list)
    assert details[0]["integrity"] == "stale"
    assert details[0]["recovered_without_manifest"] is True


def test_orphaned_package_shim_symlink_is_not_recovered(tmp_path: Path) -> None:
    shim_dir = tmp_path / "package-shims" / "bin"
    shim_dir.mkdir(parents=True)
    outside = tmp_path / "outside-npm"
    outside.write_text(_guard_generated_shim_source("npm"), encoding="utf-8")
    (shim_dir / "npm").symlink_to(outside)

    status = enrich_package_shim_status_payload(_orphaned_shim_status(shim_dir), {})

    assert status["installed_managers"] == []
    assert status["recovered_managers"] == []


def test_expired_cloud_entitlement_does_not_block_existing_local_repair() -> None:
    entitlement = {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": "pro",
    }

    assert package_firewall_operation_allowed(entitlement, "repair", has_installed_managers=True) is True
    assert package_firewall_operation_allowed(entitlement, "remove", has_installed_managers=True) is True
    assert package_firewall_operation_allowed(entitlement, "repair", has_installed_managers=False) is False
    assert package_firewall_operation_allowed(entitlement, "install", has_installed_managers=True) is False
    assert package_firewall_operation_allowed(entitlement, "test", has_installed_managers=True) is False


def test_omp_managed_install_proof_is_recognized_as_live_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    home_dir = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    hook_path = home_dir / ".omp" / "agent" / "extensions" / "hol-guard.ts"
    hook_path.parent.mkdir(parents=True)
    hook_path.write_text("export const guard = true;\n", encoding="utf-8")
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=store.guard_home)
    manifest = bind_managed_install_proof({"config_path": str(hook_path)}, context)

    assert approvals_module._live_hook_verification(
        [{"harness": "omp", "active": True, "manifest": manifest}],
        store,
    ) == {"omp": True}


def test_preflight_rejects_home_ancestors_and_filesystem_root_but_allows_project(tmp_path: Path) -> None:
    account_root = tmp_path / "accounts"
    home = account_root / "home"
    project = home / "src" / "project"
    project.mkdir(parents=True)

    assert _unsafe_broad_preflight_target(home, home_dir=home) is True
    assert _unsafe_broad_preflight_target(account_root, home_dir=home) is True
    assert _unsafe_broad_preflight_target(Path(home.anchor), home_dir=home) is True
    assert _unsafe_broad_preflight_target(project, home_dir=home) is False


def test_preflight_resolution_failure_honors_json_output_stream(monkeypatch) -> None:
    def fail_resolve(_path: Path, *_args: object, **_kwargs: object) -> Path:
        raise OSError("unresolvable")

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    output = StringIO()
    args = argparse.Namespace(target=".", json=True, cisco_mode="off", harness=None, enforce=False)

    exit_code = commands_preflight._run_guard_safe_preflight_command(args, output_stream=output)

    assert exit_code == 2
    payload = json.loads(output.getvalue())
    assert payload["error"] == "preflight_target_unresolvable"
    assert "unresolvable" in payload["message"]


def test_preflight_success_honors_output_stream(monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(
        commands_preflight,
        "_run_consumer_scan_with_mode",
        lambda *_args, **_kwargs: {"install_verdict": {"action": "allow"}, "result": "ok"},
    )
    monkeypatch.setattr(
        commands_preflight,
        "_emit",
        lambda _name, payload, _json_output: print(json.dumps(payload, sort_keys=True)),
    )
    output = StringIO()
    args = argparse.Namespace(target=str(project), json=True, cisco_mode="off", harness=None, enforce=False)

    exit_code = commands_preflight._run_guard_safe_preflight_command(args, output_stream=output)

    assert exit_code == 0
    assert json.loads(output.getvalue())["result"] == "ok"


def test_router_converts_keyboard_interrupt_to_exit_130(capsys) -> None:
    def interrupted(_args: argparse.Namespace, **_kwargs: object) -> int:
        raise KeyboardInterrupt

    exit_code = commands_router._invoke_guard_handler(
        interrupted,
        argparse.Namespace(),
    )

    assert exit_code == 130
    assert capsys.readouterr().err == "Interrupted.\n"

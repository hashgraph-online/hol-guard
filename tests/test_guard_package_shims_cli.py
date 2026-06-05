"""Focused CLI tests for paid package-shim gating."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
from codex_plugin_scanner.guard.store import GuardStore


def _seed_paid_oauth_entitlement(home_dir: Path) -> None:
    GuardStore(home_dir).set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem="private-key",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        grant_id="grant-1",
        machine_id="machine-1",
        supply_chain_entitlement_expires_at="2026-07-05T01:39:51+00:00",
        supply_chain_firewall=True,
        supply_chain_plan_id="pro",
        workspace_id="workspace-1",
        now="2026-06-05T01:39:51+00:00",
    )


def test_package_shims_install_requires_paid_entitlement(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    guard_home = tmp_path / "guard-home"

    rc = main(["guard", "package-shims", "install", "--manager", "npm", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["error"] == "paid_guard_cloud_required"
    assert payload["entitlement"]["tier"] == "free"


def test_package_shims_status_reports_paid_oauth_entitlement(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _seed_paid_oauth_entitlement(guard_home)

    rc = main(["guard", "package-shims", "status", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"] == {
        "allowed": True,
        "reason": "paid_oauth_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert payload["actions"]["install"] == "available"


def test_package_shims_install_requires_local_approval_gate_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _seed_paid_oauth_entitlement(guard_home)
    update_approval_gate_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": "local-password",
            "confirm_password": "local-password",
        },
    )

    rc = main(
        [
            "guard",
            "package-shims",
            "install",
            "--manager",
            "npm",
            "--approval-password",
            "local-password",
            "--home",
            str(guard_home),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    shim_path = guard_home / "package-shims" / "bin" / "npm"
    assert rc == 0
    assert payload["entitlement"]["tier"] == "pro"
    assert payload["installed_managers"] == ["npm"]
    assert shim_path.exists()

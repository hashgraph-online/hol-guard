"""Focused CLI tests for paid package-shim gating."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
from codex_plugin_scanner.guard.shims import build_shim_content_hash, install_package_shims
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


def _seed_paid_bundle_entitlement(home_dir: Path) -> None:
    GuardStore(home_dir).set_sync_payload(
        "supply_chain_bundle_entitlement",
        {
            "bundle_version": "bundle-version-test",
            "key_id": "bundle-key-test",
            "policy_hash": "policy-hash-test",
            "tier": "pro",
            "workspace_id": "workspace-1",
        },
        "2026-06-05T01:39:51+00:00",
    )


def _seed_retry_required_oauth_connect(home_dir: Path) -> None:
    store = GuardStore(home_dir)
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem="private-key",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-05T01:39:51+00:00",
    )
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-06-05T01:39:51+00:00",
        request_id="connect-1",
    )
    store.record_latest_guard_connect_sync_result(
        status="retry_required",
        milestone="first_sync_failed",
        now="2026-06-05T01:40:10+00:00",
        reason="Guard authorization expired. Run `hol-guard connect` again.",
    )


def _seed_retry_required_connect_state(home_dir: Path) -> None:
    store = GuardStore(home_dir)
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-06-05T01:39:51+00:00",
        request_id="connect-1",
    )
    store.record_latest_guard_connect_sync_result(
        status="retry_required",
        milestone="first_sync_failed",
        now="2026-06-05T01:40:10+00:00",
        reason="Guard authorization expired. Run `hol-guard connect` again.",
    )


def _install_local_package_shim(guard_home: Path, home_dir: Path, manager: str) -> None:
    install_package_shims(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=None,
            guard_home=guard_home,
        ),
        managers=(manager,),
    )


def test_package_shims_install_requires_guard_cloud_connect_first(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"

    rc = main(["guard", "package-shims", "install", "--manager", "npm", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["error"] == "guard_cloud_connect_required"
    assert payload["entitlement"] == {
        "allowed": False,
        "reason": "guard_cloud_connect_required",
        "tier": "unknown",
        "upgrade_cta": "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.",
    }
    assert payload["available_actions"] == ["status", "connect", "education", "cli_fallback"]


def test_package_shims_status_reports_reconnect_required_when_cloud_auth_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _seed_retry_required_oauth_connect(guard_home)
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_local_guard_cloud_proof",
        lambda _store: (_ for _ in ()).throw(RuntimeError("cloud auth still expired")),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_supply_chain_bundle",
        lambda _store: (_ for _ in ()).throw(RuntimeError("bundle refresh blocked")),
    )

    rc = main(["guard", "package-shims", "status", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"] == {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": "unknown",
        "upgrade_cta": "Reconnect HOL Guard Cloud to refresh package firewall access.",
    }
    assert payload["actions"]["install"] == "reconnect_required"
    assert payload["actions"]["repair"] == "disabled"
    assert payload["actions"]["remove"] == "disabled"


def test_package_shims_status_self_heals_connected_cloud_auth_without_cached_entitlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    seed_connected_oauth_without_entitlement,
) -> None:
    guard_home = tmp_path / "guard-home"
    seed_connected_oauth_without_entitlement(GuardStore(guard_home))
    calls: list[str] = []

    def _fake_sync_local_guard_cloud_proof(store: GuardStore) -> dict[str, object]:
        calls.append("proof")
        store.record_latest_guard_connect_sync_success(
            sync_payload={"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1},
            now="2026-06-05T01:41:00+00:00",
        )
        return {"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1}

    def _fake_sync_supply_chain_bundle(store: GuardStore) -> dict[str, object]:
        calls.append("bundle")
        store.set_sync_payload(
            "supply_chain_bundle_entitlement",
            {
                "bundle_version": "bundle-version-test",
                "key_id": "bundle-key-test",
                "policy_hash": "policy-hash-test",
                "tier": "pro",
                "workspace_id": "workspace-1",
            },
            "2026-06-05T01:41:05+00:00",
        )
        return {"bundle_version": "bundle-version-test", "tier": "pro"}

    monkeypatch.setattr(local_supply_chain_module, "sync_local_guard_cloud_proof", _fake_sync_local_guard_cloud_proof)
    monkeypatch.setattr(local_supply_chain_module, "sync_supply_chain_bundle", _fake_sync_supply_chain_bundle)

    rc = main(["guard", "package-shims", "status", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert calls == ["proof", "bundle"]
    assert payload["entitlement"] == {
        "allowed": True,
        "reason": "paid_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert payload["actions"]["install"] == "available"


def test_package_shims_status_preserves_reconnect_gate_when_connected_auth_refresh_expires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    seed_connected_oauth_without_entitlement,
) -> None:
    guard_home = tmp_path / "guard-home"
    seed_connected_oauth_without_entitlement(GuardStore(guard_home))
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_local_guard_cloud_proof",
        lambda _store: (_ for _ in ()).throw(
            local_supply_chain_module.GuardSyncAuthorizationExpiredError(
                "Guard authorization expired. Run `hol-guard connect` again."
            )
        ),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_supply_chain_bundle",
        lambda _store: (_ for _ in ()).throw(RuntimeError("bundle refresh blocked")),
    )

    rc = main(["guard", "package-shims", "status", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"] == {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": "unknown",
        "upgrade_cta": "Reconnect HOL Guard Cloud to refresh package firewall access.",
    }
    assert payload["actions"]["install"] == "reconnect_required"


def test_package_shims_install_requires_reconnect_when_cloud_auth_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _seed_retry_required_oauth_connect(guard_home)
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_local_guard_cloud_proof",
        lambda _store: (_ for _ in ()).throw(RuntimeError("cloud auth still expired")),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_supply_chain_bundle",
        lambda _store: (_ for _ in ()).throw(RuntimeError("bundle refresh blocked")),
    )

    rc = main(["guard", "package-shims", "install", "--manager", "npm", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["error"] == "guard_cloud_reconnect_required"
    assert payload["entitlement"]["tier"] == "unknown"


def test_package_shims_status_requires_reconnect_for_retry_required_connect_state_without_oauth_storage(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _seed_retry_required_connect_state(guard_home)

    rc = main(["guard", "package-shims", "status", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"] == {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": "unknown",
        "upgrade_cta": "Reconnect HOL Guard Cloud to refresh package firewall access.",
    }
    assert payload["actions"]["install"] == "reconnect_required"


def test_package_shims_install_self_heals_retry_required_cloud_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _seed_retry_required_oauth_connect(guard_home)

    def fake_sync_local_guard_cloud_proof(store: GuardStore) -> dict[str, object]:
        store.record_latest_guard_connect_sync_success(
            sync_payload={"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1},
            now="2026-06-05T01:41:00+00:00",
        )
        return {"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1}

    def fake_sync_supply_chain_bundle(store: GuardStore) -> dict[str, object]:
        store.set_sync_payload(
            "supply_chain_bundle_entitlement",
            {
                "bundle_version": "bundle-version-test",
                "key_id": "bundle-key-test",
                "policy_hash": "policy-hash-test",
                "tier": "pro",
                "workspace_id": "workspace-1",
            },
            "2026-06-05T01:41:05+00:00",
        )
        return {"bundle_version": "bundle-version-test", "tier": "pro"}

    monkeypatch.setattr(local_supply_chain_module, "sync_local_guard_cloud_proof", fake_sync_local_guard_cloud_proof)
    monkeypatch.setattr(local_supply_chain_module, "sync_supply_chain_bundle", fake_sync_supply_chain_bundle)

    rc = main(["guard", "package-shims", "install", "--manager", "npm", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    shim_path = guard_home / "package-shims" / "bin" / "npm"
    assert rc == 0
    assert payload["entitlement"] == {
        "allowed": True,
        "reason": "paid_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert payload["activation_state"] == "restart_required"
    assert payload["installed_managers"] == ["npm"]
    assert payload["profile"]["changed"] is True
    assert shim_path.exists()
    profile_path = Path(str(payload["profile"]["profile_path"]))
    assert str(guard_home / "package-shims" / "bin") in profile_path.read_text(encoding="utf-8")


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
    assert payload["actions"]["repair"] == "disabled"
    assert payload["actions"]["remove"] == "disabled"


def test_package_shims_status_allows_local_recovery_when_cloud_is_not_connected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _install_local_package_shim(guard_home, home_dir, "npm")

    rc = main(["guard", "package-shims", "status", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"]["reason"] == "guard_cloud_connect_required"
    assert payload["actions"]["install"] == "connect_required"
    assert payload["actions"]["repair"] == "available"
    assert payload["actions"]["remove"] == "available"


def test_package_shims_repair_runs_without_guard_cloud_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _install_local_package_shim(guard_home, home_dir, "npm")

    rc = main(["guard", "package-shims", "repair", "--manager", "npm", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"]["reason"] == "guard_cloud_connect_required"
    assert payload["activation_state"] == "restart_required"
    assert payload["profile"]["changed"] is True
    profile_path = Path(str(payload["profile"]["profile_path"]))
    assert str(guard_home / "package-shims" / "bin") in profile_path.read_text(encoding="utf-8")


def test_guard_doctor_repair_regenerates_stale_package_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _install_local_package_shim(guard_home, home_dir, "npm")
    shim_path = guard_home / "package-shims" / "bin" / "npm"
    current_content = shim_path.read_text(encoding="utf-8")
    stale_content = '#!/bin/sh\nexec npm "$@"\n'
    shim_path.write_text(stale_content, encoding="utf-8")
    manifest_path = guard_home / "package-shims" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["content_hashes"]["npm"] = build_shim_content_hash(stale_content.encode("utf-8"))
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    rc = main(
        [
            "guard",
            "doctor",
            "--repair",
            "--home",
            str(home_dir),
            "--guard-home",
            str(guard_home),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["package_shims"]["issues"] == [
        {
            "kind": "package_shim_integrity",
            "manager": "npm",
            "integrity": "stale",
            "repair": "Run `hol-guard doctor --repair` to regenerate package-manager shims.",
        },
        {
            "kind": "package_shim_path",
            "repair": "Run `hol-guard doctor --repair`, then open a new shell if PATH changed.",
        },
    ]
    assert payload["package_shims"]["repair"]["repaired"] == ["npm"]
    assert payload["package_shims"]["after_repair"]["manager_details"][0]["integrity"] == "ok"
    assert shim_path.read_text(encoding="utf-8") == current_content


def test_package_shims_uninstall_runs_without_guard_cloud_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    guard_home = tmp_path / "guard-home"
    _install_local_package_shim(guard_home, home_dir, "npm")

    rc = main(["guard", "package-shims", "uninstall", "--manager", "npm", "--home", str(guard_home), "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["entitlement"]["reason"] == "guard_cloud_connect_required"
    assert payload["removed_managers"] == ["npm"]
    assert not (guard_home / "package-shims" / "bin" / "npm").exists()


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
    _seed_paid_bundle_entitlement(guard_home)
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

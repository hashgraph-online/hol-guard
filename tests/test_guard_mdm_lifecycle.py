from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.mdm import lifecycle
from codex_plugin_scanner.guard.mdm.contracts import MDM_STATUS_SCHEMA_VERSION, MachinePaths


def test_user_status_does_not_conflate_machine_installation(tmp_path: Path) -> None:
    payload = lifecycle.user_status(tmp_path)
    assert payload["schemaVersion"] == MDM_STATUS_SCHEMA_VERSION
    assert payload["scope"] == "user"
    assert payload["state"] == "absent"
    assert payload["healthy"] is False


def test_user_home_must_be_absolute_and_exist(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mdm_home_must_be_absolute"):
        lifecycle.validate_user_home("relative")
    with pytest.raises(ValueError, match="mdm_home_not_found"):
        lifecycle.validate_user_home(str(tmp_path / "missing"))


def test_activation_is_idempotent_and_writes_user_only_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append(command)
        return {"managed_installs": []}

    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    first = lifecycle.activate_user(tmp_path, "developer")
    second = lifecycle.repair_user(tmp_path, "developer")
    marker = tmp_path / ".hol-guard" / "mdm-activation.json"

    assert calls == ["install", "install"]
    assert first["operation"] == "activate"
    assert second["operation"] == "repair"
    assert json.loads(marker.read_text())["user"] == "developer"
    assert marker.stat().st_mode & 0o077 == 0


def test_partial_activation_rolls_back_new_harnesses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStore:
        active = False

        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return [{"harness": "codex", "active": True}] if self.active else []

    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        if command == "install":
            FakeStore.active = True
            raise RuntimeError("interrupted")
        FakeStore.active = False
        return {}

    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)

    with pytest.raises(RuntimeError, match="interrupted"):
        lifecycle.activate_user(tmp_path, "developer")

    assert commands == ["install", "uninstall"]
    assert FakeStore.active is False


def test_deactivation_restores_integrations_and_removes_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    (guard_home / "mdm-activation.json").write_text("{}")
    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        return {"managed_installs": []}

    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    payload = lifecycle.deactivate_user(tmp_path, authorization_fingerprint="consumed-token")

    assert commands == ["uninstall"]
    assert payload["operation"] == "deactivate"
    assert not (guard_home / "mdm-activation.json").exists()


def test_deactivation_requires_machine_authorization(tmp_path: Path) -> None:
    with pytest.raises(PermissionError, match="mdm_removal_authorization_required"):
        lifecycle.deactivate_user(tmp_path)


def test_status_schema_accepts_stable_user_contract(tmp_path: Path) -> None:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "mdm-status-v1.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator(schema).validate(lifecycle.user_status(tmp_path))


def test_removal_authorization_is_scoped_short_lived_and_single_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization_root = tmp_path / "authorizations"
    authorization_root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    now = datetime.now(timezone.utc)
    token = authorization_root / "token.json"
    token.write_text(
        json.dumps(
            {
                "operation": "deactivate",
                "user": "developer",
                "home": str(home),
                "nonce": "unique-removal-nonce",
                "issuedAt": now.isoformat(),
                "expiresAt": (now + timedelta(minutes=2)).isoformat(),
            }
        )
    )
    monkeypatch.setattr(lifecycle.platform, "system", lambda: "Windows")

    fingerprint = lifecycle.validate_removal_authorization(
        token, home=home, user="developer", authorization_root=authorization_root
    )
    assert len(fingerprint) == 64
    assert not token.exists()

    with pytest.raises(ValueError, match="mdm_removal_authorization_consumed_or_missing"):
        lifecycle.validate_removal_authorization(
            token, home=home, user="developer", authorization_root=authorization_root
        )


def test_removal_authorization_rejects_arbitrary_path(tmp_path: Path) -> None:
    token = tmp_path / "token.json"
    token.write_text("{}")
    with pytest.raises(ValueError, match="mdm_removal_authorization_wrong_scope"):
        lifecycle.validate_removal_authorization(
            token,
            home=tmp_path,
            user="developer",
            authorization_root=tmp_path / "trusted",
        )


def test_authorization_creation_requires_admin_and_safe_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = MachinePaths(tmp_path, tmp_path / "state", None, tmp_path / "logs", tmp_path / "manifest")
    monkeypatch.setattr(lifecycle, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(lifecycle, "_is_administrator", lambda: False)
    with pytest.raises(PermissionError, match="mdm_administrator_context_required"):
        lifecycle.authorize_deactivation(tmp_path, "developer")

    monkeypatch.setattr(lifecycle, "_is_administrator", lambda: True)
    monkeypatch.setattr(lifecycle.platform, "system", lambda: "Windows")
    with pytest.raises(ValueError, match="mdm_removal_authorization_name_invalid"):
        lifecycle.authorize_deactivation(tmp_path, "developer", token_name="../escape.json")
    payload = lifecycle.authorize_deactivation(tmp_path, "developer", token_name="developer.json")
    assert Path(str(payload["authorizationPath"])).is_file()


def test_trusted_key_loader_skips_only_malformed_entries(tmp_path: Path) -> None:
    path = tmp_path / "release-trusted-keys.json"
    path.write_text(json.dumps({"valid": "a2V5", "invalid": "%%%"}))

    assert lifecycle._load_trusted_keys(path) == {"valid": b"key"}

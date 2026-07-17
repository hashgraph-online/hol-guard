from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.config import load_guard_config, overlay_synced_guard_policy
from codex_plugin_scanner.guard.mdm import policy as policy_module
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, MachinePaths
from codex_plugin_scanner.guard.mdm.policy import apply_managed_policy, load_managed_policy


def _policy(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce", "actions": {"shell": "block", "read": "warn"}},
        "lockedSettings": ["mode"],
        "update": {"owner": "mdm"},
    }
    payload.update(overrides)
    return payload


def test_loads_active_policy_and_redacts_network_secrets(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy(network={"proxyMode": "explicit", "proxyUrl": "https://proxy:8443"})))

    state = load_managed_policy(policy_path=path)

    assert state.status == "active"
    assert state.policy is not None
    assert state.policy.install_owner == "mdm"
    assert state.policy.to_public_dict()["network"] == {
        "proxyMode": "explicit",
        "proxyConfigured": True,
        "caBundleConfigured": False,
        "allowPublicRegistries": True,
    }


def test_rejects_unknown_keys_and_proxy_credentials(tmp_path: Path) -> None:
    for index, payload in enumerate(
        (
            _policy(unknown=True),
            _policy(network={"proxyMode": "explicit", "proxyUrl": "https://user:secret@proxy"}),
        )
    ):
        path = tmp_path / f"policy-{index}.json"
        path.write_text(json.dumps(payload))
        state = load_managed_policy(policy_path=path)
        assert state.status == "invalid"
        assert state.reason_code == "managed_policy_invalid"


def test_policy_is_size_bounded(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(b" " * (1024 * 1024 + 1))
    assert load_managed_policy(policy_path=path).status == "invalid"


def test_locked_values_override_local_and_actions_only_strengthen(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy()))
    state = load_managed_policy(policy_path=path)
    assert state.policy is not None

    composed = apply_managed_policy(
        {"mode": "monitor", "actions": {"shell": "allow", "read": "block", "write": "review"}},
        state.policy,
    )

    assert composed == {
        "mode": "enforce",
        "actions": {"shell": "block", "read": "block", "write": "review"},
    }


def test_managed_value_replaces_invalid_local_type(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy()))
    state = load_managed_policy(policy_path=path)
    assert state.policy is not None

    assert apply_managed_policy({"mode": True}, state.policy)["mode"] == "enforce"


def test_partial_managed_nested_policy_preserves_local_strengthening(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            _policy(
                settings={"risk_actions": {"network_egress": "block"}},
                lockedSettings=["risk_actions.network_egress"],
            )
        )
    )
    state = load_managed_policy(policy_path=path)
    assert state.policy is not None

    composed = apply_managed_policy(
        {"risk_actions": {"network_egress": "review", "credential_access": "block"}},
        state.policy,
    )

    assert composed["risk_actions"] == {
        "network_egress": "block",
        "credential_access": "block",
    }


def test_nested_managed_lock_rejects_persisted_weakening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            _policy(
                settings={"risk_actions": {"network_egress": "block"}},
                lockedSettings=["risk_actions.network_egress"],
            )
        )
    )
    state = load_managed_policy(policy_path=path)
    monkeypatch.setattr(config_module, "load_managed_policy", lambda: state)

    with pytest.raises(ValueError, match=r"risk_actions\.network_egress"):
        config_module.update_guard_settings(
            tmp_path / "guard-home",
            {"risk_actions": {"network_egress": "warn"}},
        )


def test_proxy_credentials_are_rejected_when_encoded() -> None:
    payload = _policy(
        network={
            "proxyMode": "explicit",
            "proxyUrl": "https://user%40example:secret@proxy.example:8443",
        }
    )

    with pytest.raises(ValueError, match="proxy credentials"):
        policy_module.parse_managed_policy(payload)


def test_missing_policy_reports_absent(tmp_path: Path) -> None:
    state = load_managed_policy(policy_path=tmp_path / "missing.json")
    assert state.status == "absent"
    assert state.reason_code == "managed_policy_absent"


def test_managed_policy_survives_local_and_cloud_weakening(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            _policy(
                settings={
                    "mode": "enforce",
                    "security_level": "paranoid",
                    "default_action": "block",
                    "risk_actions": {"network_egress": "block"},
                    "harness_risk_actions": {"codex": {"network_egress": "block"}},
                },
                lockedSettings=["mode", "security_level", "default_action", "risk_actions.network_egress"],
            )
        )
    )
    state = load_managed_policy(policy_path=path)
    guard_home = tmp_path / "home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\ndefault_action = "allow"\n')

    config = load_guard_config(guard_home, managed_policy_state=state)
    overlaid = overlay_synced_guard_policy(config, {"mode": "prompt", "defaultAction": "warn"})

    assert overlaid.mode == "enforce"
    assert overlaid.security_level == "paranoid"
    assert overlaid.default_action == "block"
    assert overlaid.risk_actions == {"network_egress": "block"}
    assert overlaid.harness_risk_actions == {"codex": {"network_egress": "block"}}
    assert overlaid.install_owner == "mdm"


def test_local_policy_can_strengthen_locked_action(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy(settings={"default_action": "warn"}, lockedSettings=["default_action"])))
    state = load_managed_policy(policy_path=path)
    assert state.policy is not None
    assert apply_managed_policy({"default_action": "block"}, state.policy)["default_action"] == "block"


def test_invalid_machine_policy_fails_closed_in_runtime_config(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text("not-json")
    state = load_managed_policy(policy_path=path)
    guard_home = tmp_path / "home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\ndefault_action = "allow"\n')

    config = load_guard_config(guard_home, managed_policy_state=state)

    assert config.managed_policy_status == "invalid"
    assert config.mode == "enforce"
    assert config.default_action == "block"
    assert config.install_owner == "mdm"


def test_removed_profile_retains_last_valid_machine_floor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    native_path = tmp_path / "managed-policy.json"
    paths = MachinePaths(
        tmp_path / "runtime",
        tmp_path / "state",
        native_path,
        tmp_path / "logs",
        tmp_path / "manifest",
    )
    monkeypatch.setattr(policy_module, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(policy_module, "_administrator_context", lambda _system: True)
    monkeypatch.setattr(policy_module, "_cache_owner_is_trusted", lambda _path, _system: True)
    native_path.write_text(json.dumps(_policy()))

    active = load_managed_policy(system_name="Linux")
    native_path.unlink()
    cached = load_managed_policy(system_name="Linux")

    assert active.status == "active"
    assert active.policy is not None
    assert cached.status == "active"
    assert cached.reason_code == "managed_policy_profile_removed_cached"
    assert cached.policy is not None
    assert cached.policy.content_hash == active.policy.content_hash


def test_read_only_policy_load_does_not_refresh_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    native_path = tmp_path / "managed-policy.json"
    paths = MachinePaths(
        tmp_path / "runtime",
        tmp_path / "state",
        native_path,
        tmp_path / "logs",
        tmp_path / "manifest",
    )
    writes: list[tuple[dict[str, object], str]] = []
    native_path.write_text(json.dumps(_policy()))
    monkeypatch.setattr(policy_module, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(policy_module, "_write_policy_cache", lambda payload, system: writes.append((payload, system)))

    state = load_managed_policy(system_name="Linux", write_cache=False)

    assert state.status == "active"
    assert writes == []

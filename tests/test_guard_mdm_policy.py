from __future__ import annotations

import base64
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.config import load_guard_config, overlay_synced_guard_policy
from codex_plugin_scanner.guard.mdm import policy as policy_module
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, MachinePaths
from codex_plugin_scanner.guard.mdm.policy import apply_managed_policy, load_managed_policy
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_key_fingerprint
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring


def _policy(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce", "actions": {"shell": "block", "read": "warn"}},
        "lockedSettings": ["mode"],
        "update": {"owner": "mdm"},
    }
    payload.update(overrides)
    return payload


def _policy_bundle_key_payload(keyring: dict[str, object]) -> dict[str, object]:
    keys = keyring["keys"]
    assert isinstance(keys, list)
    key_payload = keys[0]
    assert isinstance(key_payload, dict)
    return key_payload


def _managed_policy_schema_validator() -> Draft202012Validator:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "mdm-policy-v1.schema.json"
    return Draft202012Validator(json.loads(schema_path.read_text()))


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


def test_integrity_trust_parses_pins_without_disclosing_key_material(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    key = base64.b64encode(b"k" * 32).decode()
    path.write_text(
        json.dumps(
            _policy(
                integrityTrust={
                    "releasePublicKeys": {"release-1": key},
                    "macosTeamId": "TEAM123",
                    "windowsSignerThumbprints": ["01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67"],
                }
            )
        )
    )

    state = load_managed_policy(policy_path=path)

    assert state.policy is not None
    assert state.policy.integrity_trust.release_public_keys == {"release-1": b"k" * 32}
    assert state.policy.to_public_dict()["integrityTrust"] == {
        "releaseKeyIds": ["release-1"],
        "macosTeamIdConfigured": True,
        "windowsSignerThumbprintsConfigured": True,
    }


@pytest.mark.parametrize("encoded", ["not-base64", base64.b64encode(b"short").decode()])
def test_integrity_trust_rejects_invalid_release_keys(encoded: str) -> None:
    with pytest.raises(ValueError, match="release public key"):
        policy_module.parse_managed_policy(_policy(integrityTrust={"releasePublicKeys": {"release-1": encoded}}))


def test_managed_policy_normalizes_policy_bundle_keyring_and_redacts_key_material(
    tmp_path: Path,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy(policyBundleKeyring=keyring)))

    state = load_managed_policy(policy_path=path)

    assert state.status == "active"
    assert state.policy is not None
    assert state.policy.policy_bundle_keyring == keyring
    public_policy = state.policy.to_public_dict()
    assert public_policy["policyBundleKeyring"] == {
        "configured": True,
        "keyCount": 1,
        "workspaceId": "workspace-managed",
    }
    assert "publicKeyPem" not in json.dumps(public_policy)
    assert "fingerprintSha256" not in json.dumps(public_policy)

    _managed_policy_schema_validator().validate(_policy(policyBundleKeyring=keyring))


def test_managed_policy_accepts_empty_policy_bundle_keyring_for_managed_disable(
    tmp_path: Path,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    keyring["keys"] = []
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy(policyBundleKeyring=keyring)))

    state = load_managed_policy(policy_path=path)

    assert state.status == "active"
    assert state.policy is not None
    assert state.policy.policy_bundle_keyring == keyring
    assert state.policy.to_public_dict()["policyBundleKeyring"] == {
        "configured": True,
        "keyCount": 0,
        "workspaceId": "workspace-managed",
    }


@pytest.mark.parametrize(
    "mutation",
    (
        "contract",
        "wrapper-purpose",
        "wrapper-workspace",
        "key-purpose",
        "key-workspace",
    ),
)
def test_managed_policy_rejects_invalid_policy_bundle_keyring_contract(
    tmp_path: Path,
    mutation: str,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    keys = keyring["keys"]
    assert isinstance(keys, list)
    key_payload = keys[0]
    assert isinstance(key_payload, dict)
    if mutation == "contract":
        keyring["contractVersion"] = "guard-policy-keyring.v0"
    elif mutation == "wrapper-purpose":
        keyring["purpose"] = "supply_chain"
    elif mutation == "wrapper-workspace":
        keyring["workspaceId"] = ""
    elif mutation == "key-purpose":
        key_payload["purpose"] = "supply_chain"
    else:
        key_payload["workspaceId"] = "workspace-other"
    path = tmp_path / f"policy-{mutation}.json"
    path.write_text(json.dumps(_policy(policyBundleKeyring=keyring)))

    state = load_managed_policy(policy_path=path)

    assert state.status == "invalid"
    assert state.reason_code == "managed_policy_invalid"


@pytest.mark.parametrize("unknown_field_location", ("wrapper", "key"))
def test_managed_policy_and_schema_reject_unknown_policy_bundle_keyring_fields(
    tmp_path: Path,
    unknown_field_location: str,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    if unknown_field_location == "wrapper":
        keyring["extension"] = "not-allowed"
    else:
        _policy_bundle_key_payload(keyring)["extension"] = "not-allowed"
    payload = _policy(policyBundleKeyring=keyring)

    with pytest.raises(ValidationError):
        _managed_policy_schema_validator().validate(payload)

    path = tmp_path / f"policy-unknown-{unknown_field_location}.json"
    path.write_text(json.dumps(payload))
    state = load_managed_policy(policy_path=path)

    assert state.status == "invalid"
    assert state.reason_code == "managed_policy_invalid"


@pytest.mark.parametrize("invalid_anchor", ("malformed-pem", "non-rsa", "undersized-rsa"))
def test_managed_policy_rejects_invalid_policy_bundle_cryptographic_anchors(
    tmp_path: Path,
    invalid_anchor: str,
) -> None:
    keyring = policy_bundle_test_keyring(workspace_id="workspace-managed")
    key_payload = _policy_bundle_key_payload(keyring)
    if invalid_anchor == "malformed-pem":
        public_key_pem = "not a PEM public key"
    else:
        private_key = (
            ec.generate_private_key(ec.SECP256R1())
            if invalid_anchor == "non-rsa"
            else rsa.generate_private_key(public_exponent=65537, key_size=1024)
        )
        public_key_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
    key_payload["publicKeyPem"] = public_key_pem
    key_payload["fingerprintSha256"] = policy_bundle_key_fingerprint(public_key_pem)
    payload = _policy(policyBundleKeyring=keyring)

    # JSON Schema validates shape; runtime validation must additionally enforce
    # PEM parsing, the RSA key type, and the minimum RSA modulus size.
    _managed_policy_schema_validator().validate(payload)

    path = tmp_path / f"policy-{invalid_anchor}.json"
    path.write_text(json.dumps(payload))
    state = load_managed_policy(policy_path=path)

    assert state.status == "invalid"
    assert state.reason_code == "managed_policy_invalid"


def test_existing_v1_managed_policy_without_policy_bundle_keyring_is_unchanged(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy()))

    state = load_managed_policy(policy_path=path)

    assert state.status == "active"
    assert state.policy is not None
    assert state.policy.policy_bundle_keyring is None
    assert "policyBundleKeyring" not in state.policy.to_public_dict()


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


@pytest.mark.parametrize(
    ("file_mode", "file_uid", "parent_mode"),
    [
        (stat.S_IFLNK | 0o777, 0, stat.S_IFDIR | 0o755),
        (stat.S_IFREG | 0o666, 0, stat.S_IFDIR | 0o755),
        (stat.S_IFREG | 0o644, 501, stat.S_IFDIR | 0o755),
        (stat.S_IFREG | 0o644, 0, stat.S_IFDIR | 0o777),
    ],
    ids=("symlink", "writable-file", "non-root-owner", "writable-parent"),
)
def test_native_machine_policy_source_rejects_insecure_provenance(
    monkeypatch: pytest.MonkeyPatch,
    file_mode: int,
    file_uid: int,
    parent_mode: int,
) -> None:
    policy_path = Path("/etc/hol-guard/managed-policy.json")

    def fake_lstat(path: Path) -> SimpleNamespace:
        if path == policy_path:
            return SimpleNamespace(st_mode=file_mode, st_uid=file_uid)
        mode = parent_mode if path == policy_path.parent else stat.S_IFDIR | 0o755
        return SimpleNamespace(st_mode=mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    assert not policy_module._machine_policy_source_is_trusted(policy_path, "Linux")


def test_native_machine_policy_source_accepts_root_owned_nonwritable_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = Path("/etc/hol-guard/managed-policy.json")

    def fake_lstat(path: Path) -> SimpleNamespace:
        mode = stat.S_IFREG | 0o644 if path == policy_path else stat.S_IFDIR | 0o755
        return SimpleNamespace(st_mode=mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    assert policy_module._machine_policy_source_is_trusted(policy_path, "Linux")


def test_native_machine_policy_source_rejects_relative_path_before_stat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_lstat(_path: Path) -> SimpleNamespace:
        raise AssertionError("relative paths must be rejected before filesystem traversal")

    monkeypatch.setattr(Path, "lstat", unexpected_lstat)

    assert not policy_module._machine_policy_source_is_trusted(
        Path("etc/hol-guard/managed-policy.json"),
        "Linux",
    )


def test_native_machine_policy_loader_reports_insecure_source_as_tampered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_path = tmp_path / "managed-policy.json"
    native_path.write_text(json.dumps(_policy()))
    paths = MachinePaths(
        tmp_path / "runtime",
        tmp_path / "state",
        native_path,
        tmp_path / "logs",
        tmp_path / "manifest",
    )
    monkeypatch.setattr(policy_module, "default_machine_paths", lambda **_kwargs: paths)

    state = load_managed_policy(system_name="Linux")

    assert state.status == "tampered"
    assert state.reason_code == "managed_policy_source_tampered"


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
    monkeypatch.setattr(policy_module, "_machine_policy_source_is_trusted", lambda _path, _system: True)
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
    monkeypatch.setattr(policy_module, "_machine_policy_source_is_trusted", lambda *_args: True)
    monkeypatch.setattr(policy_module, "_write_policy_cache", lambda payload, system: writes.append((payload, system)))

    state = load_managed_policy(system_name="Linux", write_cache=False)

    assert state.status == "active"
    assert writes == []


def test_windows_cache_is_never_promoted_to_managed_signing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "program-data" / "HOL Guard"
    state_root.mkdir(parents=True)
    cache_path = state_root / "managed-policy-cache.json"
    cache_path.write_text(
        json.dumps(
            _policy(
                policyBundleKeyring=policy_bundle_test_keyring(
                    workspace_id="workspace-managed",
                )
            )
        )
    )
    paths = MachinePaths(
        tmp_path / "runtime",
        state_root,
        None,
        tmp_path / "logs",
        tmp_path / "manifest",
    )
    monkeypatch.setattr(policy_module, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(
        policy_module,
        "_read_windows_policy",
        lambda: (None, r"HKLM\Software\Policies\HOL\Guard"),
    )

    state = load_managed_policy(system_name="Windows")

    assert state.status == "tampered"
    assert state.reason_code == "managed_policy_cache_tampered"
    assert state.policy is None
    assert not policy_module._machine_policy_source_is_trusted(cache_path, "Windows")
    assert not policy_module._cache_owner_is_trusted(cache_path, "Windows")

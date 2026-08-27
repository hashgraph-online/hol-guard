from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CUSTOM_EXTENSION_CONTINUITY_FIELD,
    apply_verified_custom_extension_continuity,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-08-27T12:00:00Z"
_FUTURE = "2026-08-28T12:00:00Z"
_WORKSPACE_ID = "workspace-custom-continuity"
_DEVICE_ID = "device-custom-continuity"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _workspace_identity(identity_hash: str) -> str:
    return _digest(f"guard.custom-extension-continuity.v1:{_WORKSPACE_ID}:{identity_hash}")


def _device_identity() -> str:
    return _digest(f"guard.custom-extension-continuity.v1:device:{_WORKSPACE_ID}:{_DEVICE_ID}")


def _bundle(identity_hash: str, *, state: str = "blocked", revision: int = 1) -> dict[str, object]:
    return {
        "workspaceId": _WORKSPACE_ID,
        "payload": {
            CUSTOM_EXTENSION_CONTINUITY_FIELD: {
                "schemaVersion": "guard.custom-extension-continuity.v2",
                "revision": revision,
                "observedAt": _NOW,
                "expiresAt": _FUTURE,
                "items": [
                    {
                        "identityHash": _workspace_identity(identity_hash),
                        "deviceIdentityHashes": [_device_identity()],
                        "state": state,
                    }
                ],
            }
        },
    }


def _observed_store(tmp_path: Path) -> tuple[GuardStore, UnlistedCliIdentity]:
    store = GuardStore(tmp_path / "guard-home")
    identity = UnlistedCliIdentity(
        cli_id="local-cli.release-tool-12345678",
        name="release-tool",
        kind="executable",
        identity_hash="a" * 64,
        example_label="release-tool",
    )
    store.record_local_cli_observation(identity, seen_at=_NOW, help_status="ok")
    return store, identity


def test_v2_projection_applies_only_to_matching_workspace_identity_and_device(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    state = apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "blocked"
    assert state["items"][identity.cli_id]["status"] == "applied"
    assert "source_path" not in str(state)

    other_store, other_identity = _observed_store(tmp_path / "other")
    state = apply_verified_custom_extension_continuity(
        other_store,
        _bundle(other_identity.identity_hash),
        device_id="different-device",
        now=_NOW,
    )
    assert other_store.read_local_cli_grant(other_identity.cli_id) is None
    assert state["items"] == {}


def test_v2_explicit_signed_removal_clears_cloud_authority_but_not_local_file(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    source = tmp_path / "release-tool"
    source.write_text("still local", encoding="utf-8")
    apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    removed = apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash, state="removed", revision=2),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    assert store.read_local_cli_grant(identity.cli_id) is None
    assert removed["items"][identity.cli_id]["status"] == "removed"
    assert source.read_text(encoding="utf-8") == "still local"


def test_omitted_projection_retains_last_known_good_until_explicit_tombstone(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    retained = apply_verified_custom_extension_continuity(
        store,
        {"workspaceId": _WORKSPACE_ID, "payload": {}},
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    assert store.read_local_cli_grant(identity.cli_id)["state"] == "blocked"
    assert retained["items"][identity.cli_id]["status"] == "applied"


def test_shared_signed_projection_contract_is_privacy_safe_and_bounded() -> None:
    contract = json.loads(
        (Path(__file__).parents[1] / "contracts/managed-controls/v1/signed-custom-extension-continuity.schema.json")
        .read_text(encoding="utf-8")
    )
    assert contract["properties"]["schemaVersion"]["const"] == (
        "guard.custom-extension-continuity.v2"
    )
    assert contract["properties"]["items"]["maxItems"] == 100
    item = contract["properties"]["items"]["items"]
    assert item["additionalProperties"] is False
    assert item["properties"]["deviceIdentityHashes"]["maxItems"] == 1
    assert set(item["properties"]) == {
        "deviceIdentityHashes",
        "identityHash",
        "state",
    }


def test_v2_projection_refuses_cross_device_binding_disclosure(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    bundle = _bundle(identity.identity_hash)
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    continuity = payload[CUSTOM_EXTENSION_CONTINUITY_FIELD]
    assert isinstance(continuity, dict)
    items = continuity["items"]
    assert isinstance(items, list) and isinstance(items[0], dict)
    items[0]["deviceIdentityHashes"] = [_device_identity(), "f" * 64]
    with pytest.raises(ValueError, match="invalid continuity device binding"):
        apply_verified_custom_extension_continuity(
            store,
            bundle,
            device_id=_DEVICE_ID,
            now=_NOW,
        )

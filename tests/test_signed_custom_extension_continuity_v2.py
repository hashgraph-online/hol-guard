from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

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


def _workspace_identity(identity_hash: str, *, workspace_id: str = _WORKSPACE_ID) -> str:
    return _digest(f"guard.custom-extension-continuity.v1:{workspace_id}:{identity_hash}")


def _device_identity(*, workspace_id: str = _WORKSPACE_ID, device_id: str = _DEVICE_ID) -> str:
    return _digest(f"guard.custom-extension-continuity.v1:device:{workspace_id}:{device_id}")


def _bundle(
    identity_hash: str,
    *,
    state: str = "blocked",
    revision: int = 1,
    workspace_id: str = _WORKSPACE_ID,
    device_id: str = _DEVICE_ID,
) -> dict[str, object]:
    return {
        "workspaceId": workspace_id,
        "payload": {
            CUSTOM_EXTENSION_CONTINUITY_FIELD: {
                "schemaVersion": "guard.custom-extension-continuity.v2",
                "revision": revision,
                "observedAt": _NOW,
                "expiresAt": _FUTURE,
                "items": [
                    {
                        "identityHash": _workspace_identity(identity_hash, workspace_id=workspace_id),
                        "deviceIdentityHashes": [_device_identity(workspace_id=workspace_id, device_id=device_id)],
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


def _state_items(state: dict[str, object]) -> dict[str, dict[str, object]]:
    items = state.get("items")
    assert isinstance(items, dict)
    return cast(dict[str, dict[str, object]], items)


def test_v2_projection_applies_only_to_matching_workspace_identity_and_device(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    state = apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    grant = store.read_local_cli_grant(identity.cli_id)
    assert grant is not None and grant["state"] == "blocked"
    assert _state_items(state)[identity.cli_id]["status"] == "applied"
    assert "source_path" not in str(state)

    other_store, other_identity = _observed_store(tmp_path / "other")
    state = apply_verified_custom_extension_continuity(
        other_store,
        _bundle(other_identity.identity_hash),
        device_id="different-device",
        now=_NOW,
    )
    assert other_store.read_local_cli_grant(other_identity.cli_id) is None
    assert _state_items(state) == {}


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
    assert _state_items(removed)[identity.cli_id]["status"] == "removed"
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
    grant = store.read_local_cli_grant(identity.cli_id)
    assert grant is not None and grant["state"] == "blocked"
    assert _state_items(retained)[identity.cli_id]["status"] == "applied"


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


def test_v2_tombstone_for_prior_identity_cannot_clear_replacement_grant(tmp_path: Path) -> None:
    store, original = _observed_store(tmp_path)
    apply_verified_custom_extension_continuity(
        store,
        _bundle(original.identity_hash, state="allowed"),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    replacement = UnlistedCliIdentity(
        cli_id=original.cli_id,
        name=original.name,
        kind=original.kind,
        identity_hash="b" * 64,
        example_label=original.example_label,
    )
    store.record_local_cli_observation(replacement, seen_at=_NOW, help_status="ok")
    store.upsert_local_cli_grant(
        identity=replacement,
        state="blocked",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_NOW,
        command_states={},
    )

    state = apply_verified_custom_extension_continuity(
        store,
        _bundle(original.identity_hash, state="removed", revision=2),
        device_id=_DEVICE_ID,
        now=_NOW,
    )

    assert _state_items(state)[original.cli_id]["status"] == "changed_identity"
    assert store.read_local_cli_grant(original.cli_id) == {
        "cli_id": original.cli_id,
        "identity_hash": replacement.identity_hash,
        "state": "blocked",
        "revision": 2,
        "updated_at": _NOW,
    }


def test_v2_projection_updates_every_cli_alias_with_the_same_identity(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    alias = UnlistedCliIdentity(
        cli_id="local-cli.release-tool-alias-12345678",
        name="release-tool-alias",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="release-tool-alias",
    )
    store.record_local_cli_observation(alias, seen_at=_NOW, help_status="ok")

    state = apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash),
        device_id=_DEVICE_ID,
        now=_NOW,
    )

    assert set(_state_items(state)) == {identity.cli_id, alias.cli_id}
    identity_grant = store.read_local_cli_grant(identity.cli_id)
    alias_grant = store.read_local_cli_grant(alias.cli_id)
    assert identity_grant is not None and identity_grant["state"] == "blocked"
    assert alias_grant is not None and alias_grant["state"] == "blocked"


def test_v2_context_change_removes_prior_cloud_authority_atomically(tmp_path: Path) -> None:
    store, identity = _observed_store(tmp_path)
    apply_verified_custom_extension_continuity(
        store,
        _bundle(identity.identity_hash),
        device_id=_DEVICE_ID,
        now=_NOW,
    )
    other_workspace = "workspace-other"
    other_device = "device-other"
    next_bundle = _bundle(
        identity.identity_hash,
        workspace_id=other_workspace,
        device_id=other_device,
    )
    payload = next_bundle["payload"]
    assert isinstance(payload, dict)
    continuity = payload[CUSTOM_EXTENSION_CONTINUITY_FIELD]
    assert isinstance(continuity, dict)
    continuity["items"] = []

    state = apply_verified_custom_extension_continuity(
        store,
        next_bundle,
        device_id=other_device,
        now=_NOW,
    )

    assert store.read_local_cli_grant(identity.cli_id) is None
    assert _state_items(state) == {}
    assert state["binding"] == {
        "workspaceHash": _digest(f"guard.custom-extension-continuity.v1:workspace:{other_workspace}"),
        "deviceHash": _device_identity(workspace_id=other_workspace, device_id=other_device),
    }


def test_v2_concurrent_local_tightening_after_preflight_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store, identity = _observed_store(tmp_path)
    original_read = store.read_local_cli_grant
    injected = False

    def _tighten(cli_id: str):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            concurrent.upsert_local_cli_grant(
                identity=identity,
                state="blocked",
                expected_revision=0,
                updated_at=_NOW,
                command_states={},
            )
        return original_read(cli_id)

    monkeypatch.setattr(store, "read_local_cli_grant", _tighten)
    with pytest.raises(ValueError, match="authority changed"):
        apply_verified_custom_extension_continuity(
            store,
            _bundle(identity.identity_hash, state="allowed"),
            device_id=_DEVICE_ID,
            now=_NOW,
        )

    grant = GuardStore(guard_home).read_local_cli_grant(identity.cli_id)
    assert grant is not None and grant["state"] == "blocked"
    assert GuardStore(guard_home).get_sync_payload("custom_extension_continuity") is None

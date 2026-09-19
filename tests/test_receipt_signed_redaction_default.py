"""Signed receipt settings distinguish defaults from explicit privacy floors."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicy, ManagedPolicyState
from codex_plugin_scanner.guard.runtime.receipt_upload import optional_upload_settings
from codex_plugin_scanner.guard.runtime.workspace_preferences import (
    effective_receipt_redaction_level,
    optional_upload_allowed,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import validated_synced_policy_bundle
from codex_plugin_scanner.guard.workspace_preference_authority import capture_workspace_preference_state
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_guard_receipt_redaction_cursor import _signed_redaction_policy_bundle
from tests.test_workspace_preference_authority import NOW, OTHER, WORKSPACE, _accept, _store, _wire


def _ready_store(tmp_path: Path, *, local: str | None = None, remote: str = "none") -> GuardStore:
    store, _ = _store(tmp_path)
    settings = "sync = true\ntelemetry = true\n"
    if local is not None:
        settings += f'receipt_redaction_level = "{local}"\n'
    (store.guard_home / "config.toml").write_text(settings, encoding="utf-8")
    _accept(store, _wire(redaction=remote))
    state = capture_workspace_preference_state(store)
    assert state.confirmed and state.workspace_id == WORKSPACE
    assert optional_upload_allowed(store)
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=WORKSPACE), NOW)
    return store


def _signed_level(store: GuardStore, level: str | None, *, revision: int = 1) -> dict[str, object]:
    timestamp = f"2026-07-01T00:00:{revision:02d}Z"
    bundle = sign_policy_bundle(
        _signed_redaction_policy_bundle(
            level=level,
            bundle_version=f"policy-2026-07-01.{revision}",
            issued_at=timestamp,
        ),
        workspace_id=WORKSPACE,
    )
    store.set_sync_payload("policy_bundle", bundle, timestamp)
    validated = validated_synced_policy_bundle(store)
    assert validated is not None
    assert validated["bundleHash"] == bundle["bundleHash"]
    assert validated.get("receiptRedactionLevel") == level
    return bundle


def _upload_level(store: GuardStore) -> str:
    state = capture_workspace_preference_state(store)
    allowed, level = optional_upload_settings(store, state)
    assert allowed
    assert effective_receipt_redaction_level(store) == level
    return level


@pytest.mark.parametrize("signed_level", ["none", "partial"])
def test_verified_signed_level_can_replace_absent_local_default(tmp_path: Path, signed_level: str) -> None:
    store = _ready_store(tmp_path)
    assert "receipt_redaction_level" not in (store.guard_home / "config.toml").read_text(encoding="utf-8")
    assert config_module.load_guard_config(store.guard_home).receipt_redaction_level == "full"
    _signed_level(store, signed_level)

    assert _upload_level(store) == signed_level


@pytest.mark.parametrize(
    "local,signed_level,expected",
    [("full", "none", "full"), ("partial", "none", "partial"), ("none", "partial", "partial")],
)
def test_explicit_local_privacy_floor_survives_signed_relaxation(
    tmp_path: Path, local: str, signed_level: str, expected: str
) -> None:
    store = _ready_store(tmp_path, local=local)
    assert config_module.load_guard_config(store.guard_home).receipt_redaction_level == local
    _signed_level(store, signed_level)

    assert _upload_level(store) == expected


@pytest.mark.parametrize("remote", ["full", "partial"])
def test_confirmed_workspace_privacy_floor_survives_signed_relaxation(tmp_path: Path, remote: str) -> None:
    store = _ready_store(tmp_path, local="none", remote=remote)
    _signed_level(store, "none")

    assert _upload_level(store) == remote


def test_signed_clear_restores_default_and_later_revision_can_relax(tmp_path: Path) -> None:
    store = _ready_store(tmp_path)
    hashes: list[str] = []
    for revision, level, expected in [(1, "none", "none"), (2, None, "full"), (3, "none", "none")]:
        bundle = _signed_level(store, level, revision=revision)
        hashes.append(str(bundle["bundleHash"]))
        assert len(set(hashes)) == revision
        assert optional_upload_allowed(store)
        assert _upload_level(store) == expected


@pytest.mark.parametrize("invalid", ["tampered", "expired", "foreign"])
def test_unaccepted_signed_level_cannot_replace_default(tmp_path: Path, invalid: str) -> None:
    store = _ready_store(tmp_path)
    bundle = _signed_level(store, "none")
    if invalid == "tampered":
        bundle["receiptRedactionLevel"] = "partial"
    elif invalid == "expired":
        bundle["expiresAt"] = "2026-07-02T00:00:00Z"
        bundle = sign_policy_bundle(bundle, workspace_id=WORKSPACE)
    else:
        bundle = sign_policy_bundle(bundle, workspace_id=OTHER)
    store.set_sync_payload("policy_bundle", bundle, NOW)
    assert validated_synced_policy_bundle(store) is None

    assert _upload_level(store) == "full"


@pytest.mark.parametrize("managed_level", ["full", "partial"])
def test_managed_privacy_floor_survives_signed_relaxation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, managed_level: str
) -> None:
    store = _ready_store(tmp_path)
    policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={"receipt_redaction_level": managed_level},
        locked_settings=frozenset({"receipt_redaction_level"}),
    )
    managed = ManagedPolicyState("active", "synthetic-component-fixture", policy)
    monkeypatch.setattr(config_module, "load_managed_policy", lambda: managed)
    configured = config_module.load_guard_config(store.guard_home)
    assert configured.receipt_redaction_level == managed_level
    assert "receipt_redaction_level" in configured.managed_locked_settings
    _signed_level(store, "none")

    assert _upload_level(store) == managed_level

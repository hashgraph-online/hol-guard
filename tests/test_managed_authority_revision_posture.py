from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.runtime.extension_catalog_handshake import runtime_session_success_summary
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import build_managed_controls_runtime_posture
from codex_plugin_scanner.guard.runtime.managed_controls_sync import managed_controls_runtime_sync_posture
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import activate_managed_bundle, managed_bundle
from tests.test_guard_extension_control_authority import _PASSWORD, _commit

_TIMESTAMP = "2026-09-17T12:00:00Z"


@pytest.fixture(autouse=True)
def enable_managed_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")


def posture(store: GuardStore) -> dict[str, object]:
    return managed_controls_runtime_sync_posture(store, generated_at=_TIMESTAMP)


def test_real_protected_activation_keeps_managed_revision_independent_of_local_edits(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    update_settings(
        home, {"enabled": True, "new_password": _PASSWORD, "confirm_password": _PASSWORD, "cooldown_seconds": 0}
    )
    store = GuardStore(home)
    assert activate_managed_bundle(store, managed_bundle()) is True
    observed = posture(store)
    assert observed["extensionAuthorityRevision"] == 0
    assert observed["managedExtensionAuthorityRevision"] == 1
    for revision in range(2):
        _commit(store, revision=revision, key=f"local-edit-{revision}")
        observed = posture(store)
        assert observed["extensionAuthorityRevision"] == revision + 1
        assert observed["managedExtensionAuthorityRevision"] == 1
    reopened = GuardStore(home)
    assert posture(reopened) == observed
    reopened.clear_policy_bundle_authority(_TIMESTAMP, policy_bundle_last_error={"reason": "cleared"})
    cleared = posture(reopened)
    assert cleared["extensionAuthorityRevision"] == 2
    assert cleared["managedExtensionAuthorityRevision"] == 2
    assert cleared["effectiveProjectionDigest"] != observed["effectiveProjectionDigest"]


def test_unavailable_or_disabled_authority_never_borrows_a_managed_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert posture(store)["managedExtensionAuthorityRevision"] is None
    assert activate_managed_bundle(store, managed_bundle()) is True
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "false")
    assert posture(store)["managedExtensionAuthorityRevision"] is None
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")
    with store._connect() as connection:
        connection.execute(
            "update extension_control_authority_snapshot set snapshot_digest = ? where singleton = 1", ("f" * 64,)
        )
    unavailable = posture(store)
    assert unavailable["managedExtensionAuthorityRevision"] is None
    assert unavailable["extensionAuthorityRevision"] is None
    assert unavailable["effectiveProjectionDigest"] is None


@pytest.mark.parametrize("value", [-1, 1.5, True, False, 2**53, "1", float("inf")])
def test_managed_observation_rejects_non_wire_integers(value: object) -> None:
    with pytest.raises(ValueError):
        build_managed_controls_runtime_posture(
            catalog_digest="a" * 64, managed_extension_authority_revision=cast(int, value)
        )


@pytest.mark.parametrize("revision", [None, 0, 1, 2**53 - 1])
def test_runtime_summary_retains_the_independent_optional_counter(revision: int | None) -> None:
    observed = build_managed_controls_runtime_posture(
        catalog_digest="a" * 64, extension_authority_revision=5, managed_extension_authority_revision=revision
    )
    summary = runtime_session_success_summary(
        session_payload={
            **observed,
            "sessionId": "synthetic-runtime",
            "deviceId": "synthetic-device",
            "harness": "hol-guard",
            "surface": "cli",
            "workspace": "synthetic-workspace",
        },
        response_payload={},
        synced_at=_TIMESTAMP,
        catalog_sync={},
    )
    assert summary["extensionAuthorityRevision"] == 5
    assert summary["managedExtensionAuthorityRevision"] == revision

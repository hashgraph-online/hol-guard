from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.extension_catalog_handshake import runtime_session_success_summary
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import build_managed_controls_runtime_posture
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(("local_revision", "managed_revision"), [(0, 0), (0, 1), (7, 1), (7, 2)])
def test_cloud_sync_preserves_independent_protected_revisions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, local_revision: int, managed_revision: int
) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")
    authority = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED, local_revision, "a" * 64, (), managed_revision=managed_revision
    )
    monkeypatch.setattr(GuardStore, "read_extension_control_authority_for_registry", lambda *_args: authority)
    payload = runner._cloud_runtime_session_payload(
        GuardStore(tmp_path / "guard-home"),
        {"session_id": "runtime-session-1", "updated_at": "2026-08-25T00:00:00Z"},
    )
    assert payload["extensionAuthorityRevision"] == local_revision
    assert payload["managedExtensionAuthorityRevision"] == managed_revision
    summary = runtime_session_success_summary(
        session_payload=payload, response_payload={}, synced_at="2026-08-25T00:00:00Z", catalog_sync={}
    )
    assert summary["extensionAuthorityRevision"] == local_revision
    assert summary["managedExtensionAuthorityRevision"] == managed_revision


def test_unavailable_authority_does_not_fabricate_managed_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    monkeypatch.setenv("GUARD_MANAGED_EXTENSION_CONTROLS_V1", "true")
    authority = ExtensionControlAuthorityView(AuthorityHealth.TAMPERED, 7, "a" * 64, (), managed_revision=2)
    monkeypatch.setattr(GuardStore, "read_extension_control_authority_for_registry", lambda *_args: authority)
    posture = runner._managed_controls_runtime_sync_posture(
        GuardStore(tmp_path / "guard-home"), generated_at="2026-08-25T00:00:00Z"
    )
    assert "managedExtensionAuthorityRevision" not in posture
    assert posture["extensionAuthorityRevision"] is None
    summary = runtime_session_success_summary(
        session_payload={
            **posture,
            "sessionId": "runtime-session-1",
            "deviceId": "device-1",
            "harness": "codex",
            "surface": "cli",
            "workspace": "local-machine",
        },
        response_payload={},
        synced_at="2026-08-25T00:00:00Z",
        catalog_sync={},
    )
    assert "managedExtensionAuthorityRevision" not in summary


@pytest.mark.parametrize("revision", [True, -1, 1.5, "1", 2**53])
def test_wire_rejects_non_integer_or_unrepresentable_managed_revision(revision: object) -> None:
    with pytest.raises(ValueError, match="nonnegative safe integer"):
        build_managed_controls_runtime_posture(
            catalog_digest="a" * 64,
            managed_extension_authority_revision=revision,  # type: ignore[arg-type]
        )


def test_unknown_managed_revision_is_distinct_from_initial_zero() -> None:
    assert "managedExtensionAuthorityRevision" not in build_managed_controls_runtime_posture(catalog_digest="a" * 64)
    assert (
        build_managed_controls_runtime_posture(catalog_digest="a" * 64, managed_extension_authority_revision=0)[
            "managedExtensionAuthorityRevision"
        ]
        == 0
    )

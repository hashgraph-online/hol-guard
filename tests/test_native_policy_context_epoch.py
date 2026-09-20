"""A superseded context cannot replace newer scoped authority selection."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher_context as publisher_context
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_cloud_policy_inputs import NativeCloudPolicyInputs
from codex_plugin_scanner.guard.native_policy_authority_read import NativeVerifiedPolicyInputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import CapturedV3PublicationInputs
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _status


@pytest.mark.parametrize("handoff", ["current", "new-scoped", "closed"])
def test_context_selection_belongs_to_its_captured_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, handoff: str
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert store._policy_integrity_secret_material(create=True)[0] is not None
    status = _status()
    status.capabilities.features += tuple(SCOPED_PUBLISH_FEATURES)
    original = publisher_context._v3_inputs_from_capture
    captures: list[NativeVerifiedPolicyInputs] = []
    newer: NativeVerifiedPolicyInputs | None = None

    def capture_then_handoff(
        capture_publisher: NativePolicySnapshotPublisher,
        inputs: NativeVerifiedPolicyInputs,
        *,
        allow_signed_defaults: bool,
        command_extensions: Mapping[str, object],
    ) -> CapturedV3PublicationInputs:
        nonlocal newer
        result = original(
            capture_publisher,
            inputs,
            allow_signed_defaults=allow_signed_defaults,
            command_extensions=command_extensions,
        )
        captures.append(inputs)
        assert inputs.authority.rows == ()
        assert inputs.sources == []
        if handoff == "new-scoped":
            store.upsert_policy(
                PolicyDecision(harness="codex", scope="global", action="block", source="local"),
                "2026-09-19T00:00:00Z",
            )
            publisher.request_publish()
            current = publisher._publication_context()
            current_is_scoped = current is not None and isinstance(current[-2], NativeVerifiedPolicyInputs)
            assert current_is_scoped
            assert current is not None
            assert isinstance(current[-2], NativeVerifiedPolicyInputs)
            newer = current[-2]
            assert len(newer.authority.rows) == 1
            assert newer.authority.rows[0].action.value == "block"
            assert publisher.requires_scoped_authority
        elif handoff == "closed":
            publisher.close()
            assert publisher.closed
        return result

    monkeypatch.setattr(publisher_context, "_v3_inputs_from_capture", capture_then_handoff)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    try:
        publisher.request_publish()
        attempt_epoch = publisher._epoch
        context = publisher._publication_context()
        has_context = context is not None
        assert len(captures) == 1
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        if handoff == "current":
            assert context is not None and isinstance(context[-2], NativeCloudPolicyInputs)
            assert publisher._epoch == attempt_epoch
            assert not publisher.requires_scoped_authority
        elif handoff == "new-scoped":
            assert newer is not None
            assert publisher._epoch > attempt_epoch
            assert publisher.requires_scoped_authority
            assert not has_context
        else:
            assert publisher.closed
            assert not has_context
        assert publisher.last_error is None
        assert publisher._failure_count == 0
        assert publisher._retry_not_before_monotonic is None
    finally:
        publisher.close()

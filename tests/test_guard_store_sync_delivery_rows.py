"""The receipts sync rows kept by the native store."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import policy_bundle_failure_ack, workspace_assessment_sync
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-28T00:10:00+00:00"


def test_an_empty_store_has_no_rows(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.workspace_assessment_delivery() is None
    assert store.cached_policy_bundle() is None


def test_a_committed_delivery_is_read_back(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    built = workspace_assessment_sync.WorkspaceAssessmentSyncBuild(payload={"generatedAt": _NOW}, digest="sha256:a")
    workspace_assessment_sync.commit_workspace_assessment_sent(store, built, now=_NOW)
    expected = {"digest": "sha256:a", "sent_at": _NOW}
    assert store.workspace_assessment_delivery() == expected
    assert store.get_sync_payload(workspace_assessment_sync.DELIVERY_STATE_KEY) == expected


def test_a_malformed_delivery_is_refused_without_a_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match="invalid_digest"):
        store.commit_workspace_assessment_sent(digest="", sent_at=_NOW)
    with pytest.raises(ValueError, match="invalid_sent_at"):
        store.commit_workspace_assessment_sent(digest="sha256:a", sent_at="")
    assert store.workspace_assessment_delivery() is None


def test_the_cached_bundle_is_read_as_stored(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("policy_bundle", {}, _NOW)
    assert store.cached_policy_bundle() == {}
    bundle = {"bundleHash": "sha256:abc", "bundleVersion": "7"}
    store.set_sync_payload("policy_bundle", bundle, _NOW)
    assert store.cached_policy_bundle() == bundle


def test_only_a_failed_acknowledgement_is_recorded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match="invalid_acknowledgement"):
        store.record_policy_bundle_failure_ack(acknowledgement={"status": "applied"}, now=_NOW)
    assert store.get_sync_payload("policy_bundle_ack") is None
    failed = {"status": "failed", "deviceId": "device-1", "bundleHash": "sha256:abc"}
    store.record_policy_bundle_failure_ack(acknowledgement=failed, now=_NOW)
    assert store.get_sync_payload("policy_bundle_ack") == failed


def test_a_rejected_cached_bundle_records_its_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    bundle = {"bundleHash": "sha256:abc", "bundleVersion": "7"}
    store.set_sync_payload("policy_bundle", bundle, _NOW)
    failed = {"status": "failed", "deviceId": "device-1", "bundleHash": "sha256:abc"}
    seen: list[object] = []

    def validate(_store: GuardStore, payload: object) -> tuple[dict[str, object] | None, str | None]:
        seen.append(payload)
        return None, "bundle_signature_invalid"

    def build(previous: object, **_kwargs: object) -> dict[str, object]:
        return dict(failed)

    monkeypatch.setattr(policy_bundle_failure_ack, "failed_acknowledgement", build)
    result = policy_bundle_failure_ack.cached_bundle_failure_acknowledgement(
        store, acknowledgement={}, device_id="device-1", device_name="Device", validate=validate
    )
    assert seen == [bundle]
    assert result == failed
    assert store.get_sync_payload("policy_bundle_ack") == failed

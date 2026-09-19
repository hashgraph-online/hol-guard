"""Exact source identity and resident publication visibility regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_activation_visibility import policy_activation_visibility
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle

_BUNDLE_HASH = "sha256:" + "a" * 64
_RESIDENT = {"policy_digest": "b" * 64, "generation": 3, "runtime_identity": "c" * 64, "mode": "enforce"}


class _ReadyPublisher:
    def __init__(self, binding: dict[str, object] | None = None) -> None:
        self.binding = dict(_RESIDENT if binding is None else binding)

    def is_ready(self) -> bool:
        return True

    def current_snapshot_binding(self) -> dict[str, object] | None:
        return self.binding

    @property
    def last_error(self) -> str | None:
        return None


def _visibility(**changes: object) -> dict[str, object]:
    arguments = {
        "desired_revision": 7,
        "desired_digest": _BUNDLE_HASH,
        "durable_bundle": {"bundleVersion": 7, "bundleHash": _BUNDLE_HASH},
        "acknowledgement": {"status": "synced", "bundleVersion": 7, "bundleHash": _BUNDLE_HASH},
        "publisher": _ReadyPublisher(),
        "expected_resident_binding": {**_RESIDENT, "bundleVersion": 7, "bundleHash": _BUNDLE_HASH},
        **changes,
    }
    return policy_activation_visibility(**arguments)


def test_integer_revisions_require_separate_source_and_resident_digests() -> None:
    status = _visibility()
    assert status["desired_revision"] == 7
    assert status["durable_revision"] == 7
    assert status["durable_digest"] == _BUNDLE_HASH
    assert status["resident_digest"] == _RESIDENT["policy_digest"]
    assert status["applied"] is True
    assert status["deployment_complete"] is True


@pytest.mark.parametrize(
    "changes",
    [
        {"desired_digest": None},
        {"desired_digest": "sha256:" + "d" * 64},
        {"desired_revision": "7"},
        {"durable_bundle": {"bundleVersion": 7, "payloadHash": _BUNDLE_HASH}},
        {"acknowledgement": {"status": "synced", "bundleHash": _BUNDLE_HASH}},
        {"acknowledgement": {"status": "synced", "bundleVersion": 7}},
        {"acknowledgement": {"status": "synced", "bundleVersion": 7, "bundleHash": "sha256:" + "d" * 64}},
        {"acknowledgement": {"status": "synced", "bundleVersion": 6, "bundleHash": _BUNDLE_HASH}},
        {"acknowledgement": {"status": [], "bundleVersion": 7, "bundleHash": _BUNDLE_HASH}},
        {"expected_resident_binding": None},
        {"expected_resident_binding": {**_RESIDENT, "bundleVersion": 8, "bundleHash": _BUNDLE_HASH}},
        {"expected_resident_binding": {**_RESIDENT, "bundleVersion": 7, "bundleHash": "sha256:" + "d" * 64}},
        {"publisher": _ReadyPublisher({**_RESIDENT, "generation": 2})},
        {"publisher": _ReadyPublisher({**_RESIDENT, "generation": True})},
        {"publisher": _ReadyPublisher({**_RESIDENT, "policy_digest": "d" * 64})},
        {"publisher": _ReadyPublisher({**_RESIDENT, "runtime_identity": "d" * 64})},
        {"publisher": _ReadyPublisher({**_RESIDENT, "mode": "observe"})},
    ],
)
def test_missing_or_mismatched_evidence_cannot_claim_application(changes: dict[str, object]) -> None:
    assert _visibility(**changes)["deployment_complete"] is False


@pytest.mark.parametrize("revision", [None, True, False, 0, -1, "", "   "])
def test_invalid_revisions_cannot_bind_by_accident(revision: object) -> None:
    assert (
        _visibility(
            desired_revision=revision,
            durable_bundle={"bundleVersion": revision, "bundleHash": _BUNDLE_HASH},
            acknowledgement={"status": "applied", "bundleVersion": revision, "bundleHash": _BUNDLE_HASH},
        )["applied"]
        is False
    )


def test_ready_production_publisher_does_not_prove_cloud_bundle_application(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _signed_bundle(rollout_state="enforcing")
    assert _activate_bundle(store, bundle, "2026-07-18T00:00:00Z") is not None

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client_request)
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        status = policy_activation_visibility(
            desired_revision=str(bundle["bundleVersion"]),
            desired_digest=str(bundle["bundleHash"]),
            durable_bundle=store.get_sync_payload("policy_bundle_last_good"),
            acknowledgement=store.get_sync_payload("policy_bundle_ack"),
            publisher=publisher,
        )
        assert status["acknowledged"] is True
        assert status["resident_ready"] is True
        assert status["publication_pending"] is True
        assert status["publication_error"] == "policy_activation_resident_binding_unavailable"
        assert status["deployment_complete"] is False
    finally:
        publisher.close()


def test_unready_publisher_and_private_error_never_claim_application() -> None:
    class PendingPublisher(_ReadyPublisher):
        def is_ready(self) -> bool:
            return False

        def current_snapshot_binding(self) -> dict[str, object] | None:
            return None

        @property
        def last_error(self) -> str:
            return "private-canary transport output"

    status = _visibility(publisher=PendingPublisher())
    assert status["publication_pending"] is True
    assert status["deployment_complete"] is False
    assert status["publication_error"] == "native_policy_snapshot_publish_failed"

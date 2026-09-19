"""Source changes and authority lifetime fence native default publication."""

from __future__ import annotations

import copy
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.synced_policy import synced_policy_payload
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.policy_bundle_signing_helpers import sign_policy_bundle
from tests.test_native_cloud_policy_activation import _activate_defaults, _signed_defaults_bundle


def _publisher(store: object, **kwargs: object) -> NativePolicySnapshotPublisher:
    def client_request(**request: object) -> bytes:
        payload = request["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload)

    return NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client_request, **kwargs)


def test_canonical_defaults_preserve_integer_revision(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    bundle, keyring = _signed_defaults_bundle(2, "block")
    _activate_defaults(store, bundle, keyring)
    defaults = synced_policy_payload(store)
    assert defaults is not None
    assert defaults["bundleVersion"] == 8
    assert type(defaults["bundleVersion"]) is int
    assert defaults["defaultAction"] == "block"


@pytest.mark.parametrize("mutation", ["signature", "workspace", "revoked_key"])
def test_untrusted_current_source_cannot_keep_a_ready_snapshot(tmp_path: Path, mutation: str) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    bundle, keyring = _signed_defaults_bundle(1, "block")
    _activate_defaults(store, bundle, keyring)
    publisher = _publisher(store)
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        if mutation == "signature":
            tampered = copy.deepcopy(bundle)
            tampered["verifier"]["signature"] = "AA=="
            store.set_sync_payload("policy_bundle", tampered, "2026-09-17T00:00:01Z")
        elif mutation == "workspace":
            store.set_sync_payload(
                "oauth_local_credentials", {"workspace_id": "other-workspace"}, "2026-09-17T00:00:01Z"
            )
        else:
            revoked = copy.deepcopy(keyring)
            revoked["keys"][0]["state"] = "revoked"
            store.set_sync_payload("policy_bundle_keyring", revoked, "2026-09-17T00:00:01Z")
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_cloud_policy_authority_unavailable"
    finally:
        publisher.close()


def test_replacement_during_publication_does_not_accept_the_previous_source(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    bundle, keyring = _signed_defaults_bundle(1, "block")
    _activate_defaults(store, bundle, keyring)
    replacement = copy.deepcopy(bundle)
    replacement["bundleVersion"] = "policy-next"
    replacement["issuedAt"] = "2026-07-02T00:00:00Z"
    replacement = sign_policy_bundle(replacement)

    def replace_during_publish(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        _activate_defaults(store, replacement, keyring)
        return _ack(payload)

    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=replace_during_publish
    )
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_cloud_policy_changed_during_publish"
        assert store.get_sync_payload("policy_bundle")["bundleHash"] == replacement["bundleHash"]
    finally:
        publisher.close()


def test_cloud_expiry_shortens_an_identical_cached_policy_and_closes_readiness(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    clock = [time.time()]
    publisher = _publisher(store, wall_clock=lambda: clock[0])
    try:
        publisher._publish_once()
        before = publisher.current_snapshot()
        assert before is not None
        bundle, keyring = _signed_defaults_bundle(1, "warn")
        defaults = bundle["policyDefaults"]
        assert isinstance(defaults, dict)
        config = load_guard_config(store.guard_home)
        for wire, field in (
            ("defaultAction", "default_action"),
            ("unknownPublisherAction", "unknown_publisher_action"),
            ("changedHashAction", "changed_hash_action"),
            ("newNetworkDomainAction", "new_network_domain_action"),
            ("subprocessAction", "subprocess_action"),
        ):
            defaults[wire] = getattr(config, field)
        expires_at = int(clock[0]) + 30
        bundle["expiresAt"] = datetime.fromtimestamp(expires_at, timezone.utc).isoformat().replace("+00:00", "Z")
        bundle = sign_policy_bundle(bundle)
        _activate_defaults(store, bundle, keyring)
        assert not publisher.is_ready()
        publisher._publish_once()
        after = publisher.current_snapshot()
        assert after is not None, publisher.last_error
        assert after["policy_digest"] == before["policy_digest"]
        assert after["generation"] > before["generation"]
        assert after["expires_at_ms"] == expires_at * 1_000
        clock[0] = expires_at + 1
        assert not publisher.is_ready()
        publisher._publish_once()
        assert publisher.last_error == "native_cloud_policy_authority_unavailable"
        assert publisher.current_snapshot_binding() is None
    finally:
        publisher.close()


def test_clear_withdraws_readiness_before_returning(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    bundle, keyring = _signed_defaults_bundle(1, "block")
    _activate_defaults(store, bundle, keyring)
    publisher = _publisher(store)
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        store.clear_policy_bundle_authority("2026-09-17T00:00:02Z", policy_bundle_last_error={})
        assert not publisher.is_ready()
        publisher._publish_once()
        snapshot = publisher.current_snapshot()
        assert snapshot is not None
        assert snapshot["effective_policy"]["default_action"] != "block"
    finally:
        publisher.close()

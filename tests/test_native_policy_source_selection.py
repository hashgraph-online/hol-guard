"""Publication contracts follow complete authority, not available feature names."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_module
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_cloud_policy_inputs import NativeCloudPolicyInputs
from codex_plugin_scanner.guard.native_policy_authority_read import NativeVerifiedPolicyInputs
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.test_native_cloud_policy_activation import _activate_defaults, _signed_defaults_bundle


def _publisher(tmp_path: Path, *, features: tuple[str, ...] = (), client=None):
    store = GuardStore(tmp_path / "guard")
    status = _status()
    status.capabilities.features += features
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)
    return store, publisher, status


def _insert_untrusted_row(store: GuardStore) -> None:
    # A separate writer supplies no in-process notification or local row MAC.
    with store._connect() as connection:
        connection.execute(
            "insert into policy_decisions(harness, scope, action, source, updated_at) values(?,?,?,?,?)",
            ("codex", "global", "block", "local", "2026-09-18T00:00:00Z"),
        )


@pytest.mark.parametrize("features", [(), tuple(SCOPED_PUBLISH_FEATURES), ("policy-snapshot-v4",)])
def test_empty_authenticated_authority_preserves_v3_regardless_of_available_v4_features(tmp_path, features):
    _, publisher, _ = _publisher(tmp_path, features=features)
    try:
        context = publisher._publication_context()
        assert context is not None
        assert isinstance(context[5], NativeCloudPolicyInputs)
        assert context[5].defaults is None and context[5].source_identity is None
        assert publisher._scoped_publication_enabled is False
    finally:
        publisher.close()


@pytest.mark.parametrize("features", [(), ("policy-snapshot-v4",)])
def test_real_local_authority_never_disappears_when_scoped_support_is_missing(tmp_path, features):
    store, publisher, _ = _publisher(tmp_path, features=features)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="global", action="block", source="local"),
        "2026-09-18T00:00:00Z",
    )
    try:
        with pytest.raises(NativePolicySnapshotError, match="protocol_unsupported"):
            publisher._publication_context()
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_complete_local_authority_selects_supported_v4(tmp_path):
    store, publisher, _ = _publisher(tmp_path, features=tuple(SCOPED_PUBLISH_FEATURES))
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="global", action="block", source="local"),
        "2026-09-18T00:00:00Z",
    )
    try:
        context = publisher._publication_context()
        assert context is not None and isinstance(context[5], NativeVerifiedPolicyInputs)
        assert len(context[5].authority.rows) == 1
        assert context[5].authority.rows[0].action.value == "block"
    finally:
        publisher.close()


def test_untrusted_cross_process_row_revokes_source_free_observation(tmp_path):
    store, publisher, _ = _publisher(tmp_path, client=lambda **kwargs: _ack(kwargs["payload"]))
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        _insert_untrusted_row(store)
        assert publisher._policy_input_changed({str(store.guard_home / "guard.db")})
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_untrusted_row_created_during_v3_push_cannot_open_ready_barrier(tmp_path):
    def client(**kwargs):
        _insert_untrusted_row(store)
        return _ack(kwargs["payload"])

    store, publisher, _ = _publisher(tmp_path, client=client)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("key", ["policy_bundle", "policy_bundle_materialization", "guard_review_memory_registry"])
def test_malformed_mandatory_source_never_becomes_source_free(tmp_path, key):
    store, publisher, _ = _publisher(tmp_path, features=tuple(SCOPED_PUBLISH_FEATURES))
    store.set_sync_payload(key, {"malformed": True}, "2026-09-18T00:00:00Z")
    try:
        with pytest.raises(NativePolicySnapshotError):
            publisher._publication_context()
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_previously_scoped_selection_refuses_feature_withdrawal_even_after_empty_capture(tmp_path):
    _, publisher, _ = _publisher(tmp_path)
    publisher._scoped_publication_enabled = True
    try:
        with pytest.raises(NativePolicySnapshotError, match="protocol_unsupported"):
            publisher._publication_context()
        assert publisher._scoped_publication_enabled
        assert not publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("rollout", [None, "0", "1"])
def test_existing_authenticated_defaults_v3_support_does_not_promote_canonical_rollout(
    tmp_path, monkeypatch, version, rollout
):
    if rollout is None:
        monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
    else:
        monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", rollout)
    store, publisher, _ = _publisher(tmp_path, client=lambda **kwargs: _ack(kwargs["payload"]))
    bundle, keys = _signed_defaults_bundle(version, "block")
    _activate_defaults(store, bundle, keys)
    prior_ack = store.get_sync_payload("policy_bundle_ack")
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        context = publisher._publication_context()
        assert context is not None and isinstance(context[5], NativeCloudPolicyInputs)
        assert context[5].defaults is not None and context[5].source_identity is not None
        assert context[5].defaults["defaultAction"] == "block"
        assert context[5].source_identity[1] == bundle["bundleHash"]
        assert publisher._v4_publication is None
        assert store.get_sync_payload("policy_bundle_ack") == prior_ack
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    finally:
        publisher.close()


def test_authenticated_defaults_with_partial_v4_support_cannot_take_compatibility_lane(tmp_path):
    store, publisher, _ = _publisher(tmp_path, features=("policy-snapshot-v4",))
    bundle, keys = _signed_defaults_bundle(2, "block")
    _activate_defaults(store, bundle, keys)
    try:
        with pytest.raises(NativePolicySnapshotError, match="protocol_unsupported"):
            publisher._publication_context()
        assert publisher._scoped_publication_enabled
    finally:
        publisher.close()


def test_authenticated_defaults_with_complete_v4_support_keeps_full_source_commitment(tmp_path):
    store, publisher, _ = _publisher(tmp_path, features=tuple(SCOPED_PUBLISH_FEATURES))
    bundle, keys = _signed_defaults_bundle(2, "block")
    _activate_defaults(store, bundle, keys)
    try:
        context = publisher._publication_context()
        assert context is not None and isinstance(context[5], NativeVerifiedPolicyInputs)
        assert context[5].defaults is not None
        assert context[5].defaults["defaultAction"] == "block"
        assert context[5].sources[0]["digest"] == bundle["bundleHash"]
        assert context[5].authority.rows == ()
    finally:
        publisher.close()


def test_unchanged_invalid_source_observation_keeps_retry_backoff(tmp_path):
    store, publisher, _ = _publisher(tmp_path, client=lambda **kwargs: _ack(kwargs["payload"]))
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        _insert_untrusted_row(store)
        changed = {str(store.guard_home / "guard.db")}
        assert publisher._policy_input_changed(changed)
        publisher._record_error("native_policy_authority_local_unavailable")
        retry = publisher._retry_not_before_monotonic
        assert not publisher._policy_input_changed(changed)
        assert publisher._retry_not_before_monotonic == retry
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_configuration_change_during_v3_push_cannot_accept_previous_policy(tmp_path):
    def client(**kwargs):
        (store.guard_home / "config.toml").write_text('mode="enforce"\ndefault_action="block"\n')
        return _ack(kwargs["payload"])

    store, publisher, _ = _publisher(tmp_path, client=client)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
    finally:
        publisher.close()


def test_source_change_after_complete_recapture_cannot_commit_v3_ack(tmp_path, monkeypatch):
    store, publisher, _ = _publisher(tmp_path, client=lambda **kwargs: _ack(kwargs["payload"]))
    capture = publisher_module.compiled_v3_compatible_policy

    def changed_after_capture(*args, **kwargs):
        result = capture(*args, **kwargs)
        _insert_untrusted_row(store)
        return result

    monkeypatch.setattr(publisher_module, "compiled_v3_compatible_policy", changed_after_capture)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
    finally:
        publisher.close()


@pytest.mark.parametrize("features", [(), tuple(SCOPED_PUBLISH_FEATURES)])
def test_actual_loaded_managed_configuration_never_flattens_to_v3(tmp_path, monkeypatch, features):
    from tests.test_native_generic_policy_resident import _source

    source = _source(tmp_path, monkeypatch)
    source.profile.write_text(
        json.dumps(
            {
                "schemaVersion": "hol-guard-mdm-policy.v1",
                "settings": {"default_action": "block"},
                "lockedSettings": ["default_action"],
            }
        )
    )
    status = _status()
    status.capabilities.features += features
    calls = []
    publisher = NativePolicySnapshotPublisher(
        store=source.store,
        status_provider=lambda: status,
        client_request=lambda **kwargs: calls.append(kwargs) or b"unused",
    )
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert calls == []
        assert publisher._scoped_publication_enabled
        assert publisher.last_error in {
            "native_policy_snapshot_protocol_unsupported",
            "native_policy_authority_capability_unsupported",
        }
    finally:
        publisher.close()


def test_authenticated_off_target_rule_cannot_enter_defaults_only_v3_lane(tmp_path, monkeypatch):
    from tests.test_generic_policy_native_application import _source

    store, bundle = _source(tmp_path, monkeypatch, shape="off-target")
    keys = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(keys, dict)
    _activate_defaults(store, bundle, keys)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status)
    try:
        with pytest.raises(NativePolicySnapshotError, match="native_cloud_policy_semantics_unsupported"):
            publisher._publication_context()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("phase", ["before-publication", "after-push"])
def test_protected_key_withdrawal_cannot_keep_previous_v3_acceptance(tmp_path, monkeypatch, phase):
    withdraw = False

    def client(**kwargs):
        if withdraw:
            monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_kwargs: (None, None))
        return _ack(kwargs["payload"])

    store, publisher, _ = _publisher(tmp_path, client=client)
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        if phase == "before-publication":
            monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_kwargs: (None, None))
        else:
            withdraw = True
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("rollout", [None, "0", "1"])
def test_ordinary_defaults_sync_never_promotes_v3_invalidation_to_applied(tmp_path, monkeypatch, rollout):
    from codex_plugin_scanner.guard import native_policy_bundle_sync
    from tests.test_generic_policy_native_application import _source
    from tests.test_policy_bundle_v2_runtime_admission import _sync_receipts

    store, bundle = _source(tmp_path, monkeypatch, shape="defaults")
    if rollout is not None:
        monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", rollout)
    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=_status, client_request=lambda **kwargs: _ack(kwargs["payload"])
    )
    monkeypatch.setattr(native_policy_bundle_sync, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    try:
        summary = _sync_receipts(store, monkeypatch, synced_at="2026-09-18T16:00:00Z", policy_bundle=bundle)
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "received"
        assert ack["bundleHash"] == bundle["bundleHash"]
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
        assert publisher._v4_publication is None
        if rollout == "1":
            assert publisher.wait_until_ready(), publisher.last_error
            assert publisher.is_ready(), publisher.last_error
            assert summary["policy_application_status"] == "unverified"
            assert summary["policy_rejection_reason"] == "native_policy_publication_pending"
        else:
            assert not publisher.is_ready()
            assert summary["policy_application_status"] == "fallback"
            assert summary["policy_rejection_reason"] == "canonical_enforcement_disabled"
    finally:
        publisher.close()


@pytest.mark.parametrize("mutation", ["row", "configuration"])
def test_source_change_during_resident_confirmation_cannot_commit_v3_ack(tmp_path, monkeypatch, mutation):
    store, publisher, _ = _publisher(tmp_path, client=lambda **kwargs: _ack(kwargs["payload"]))
    confirm = publisher._confirm_resident_fingerprint

    def changed_during_confirmation(*args, **kwargs):
        if mutation == "row":
            _insert_untrusted_row(store)
        else:
            (store.guard_home / "config.toml").write_text('mode="enforce"\ndefault_action="block"\n')
        return confirm(*args, **kwargs)

    monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", changed_during_confirmation)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
    finally:
        publisher.close()


@pytest.mark.parametrize("failure", [OSError, NativePolicySnapshotError])
def test_source_change_with_failed_v3_transport_revokes_previous_ack(tmp_path, failure):
    fail_transport = False

    def client(**kwargs):
        if fail_transport:
            _insert_untrusted_row(store)
            raise failure("synthetic transport failure")
        return _ack(kwargs["payload"])

    _, publisher, _ = _publisher(tmp_path, client=client)
    store = publisher.store
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        fail_transport = True
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("mutation", ["row", "configuration"])
def test_signed_v4_source_change_during_resident_confirmation_cannot_commit_ack(tmp_path, monkeypatch, mutation):
    from tests.test_generic_policy_native_application import _publisher as signed_publisher
    from tests.test_generic_policy_native_application import _source

    store, bundle = _source(tmp_path, monkeypatch, shape="defaults")
    keys = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(keys, dict)
    _activate_defaults(store, bundle, keys)
    publisher = signed_publisher(store, monkeypatch)
    confirm = publisher._confirm_resident_fingerprint

    def changed_during_confirmation(*args, **kwargs):
        if mutation == "row":
            _insert_untrusted_row(store)
        else:
            (store.guard_home / "config.toml").write_text('mode="enforce"\ndefault_action="block"\n')
        return confirm(*args, **kwargs)

    monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", changed_during_confirmation)
    try:
        publisher._publish_once()
        assert not publisher.is_ready()
        assert publisher.current_snapshot() is None
        assert publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_policy_authority_changed_during_publish"
    finally:
        publisher.close()

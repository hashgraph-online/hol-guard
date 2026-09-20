"""Readiness races around real V4 reservation with a synthetic resident transport."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshot_registry
from codex_plugin_scanner.guard import native_policy_snapshot_publisher_scoped as scoped
from codex_plugin_scanner.guard.native_command_control_binding import build_native_command_control_binding
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.policy_rule_identity import PolicyRuleIdentity
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _config, _status
from tests.test_native_command_control_binding import _binding, _metadata
from tests.test_native_policy_snapshot_v4_publication import _ack, _inputs

_IDENTITY = PolicyRuleIdentity("synthetic-policy", "synthetic-rule", "7")


def _resident(home, generation=3):
    (home / "native-runtime").mkdir(mode=0o700, exist_ok=True)
    directory = home / "native-runtime" / "resident-v3-synthetic"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"generation-{generation:020d}.json"
    if not path.exists():
        path.write_text("{}")
    return path


@pytest.fixture
def barrier(tmp_path, monkeypatch):
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    status = _status()
    status.capabilities.features += tuple(scoped.SCOPED_PUBLISH_FEATURES)
    state = SimpleNamespace(
        inputs=replace(_inputs(expiry=10000), rule_identities=((7, _IDENTITY),)),
        config=_config(),
        now=1.0,
        status=status,
        calls=[],
        during_ack=None,
        materialize=True,
        command_extensions=build_native_command_control_binding(
            ExtensionControlRuntimeSnapshot.from_authority_view(
                ExtensionControlAuthorityView(AuthorityHealth.UNENROLLED, 0, _metadata().catalog_digest, (), 0)
            ),
            _metadata(),
        ),
    )
    store = SimpleNamespace(
        guard_home=home,
        path=home / "guard.db",
        _policy_integrity_secret_material=lambda **kwargs: (b"s" * 32, "synthetic"),
        _connect=lambda: sqlite3.connect(home / "guard.db"),
    )
    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", lambda *args, **kwargs: state.inputs)

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        state.calls.append(snapshot)
        assert not publisher.is_ready() or len(state.calls) > 1
        if state.materialize:
            _resident(home)
        if state.during_ack:
            state.during_ack()
        return json.dumps(_ack(snapshot)).encode()

    publisher = NativePolicySnapshotPublisher(
        store=cast(GuardStore, cast(object, store)),
        status_provider=lambda: state.status,
        client_request=client,
        wall_clock=lambda: state.now,
    )
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda **kwargs: dict(state.config))
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: copy.deepcopy(state.command_extensions))
    yield publisher, state
    publisher.close()


def _result_binding(publisher, selected: int | None = 7):
    binding = publisher.current_snapshot_binding()
    assert binding is not None
    binding.pop("mode")
    binding.pop("command_extensions_bound", None)
    binding["policy_generation"] = binding.pop("generation")
    binding["selected_decision_id"] = selected
    return binding


def _assert_closed(publisher):
    assert not publisher.is_ready()
    assert publisher.current_snapshot() is None
    assert publisher.current_snapshot_binding() is None


def test_exact_publication_opens_barrier_and_only_frozen_provenance_is_used(barrier, monkeypatch):
    publisher, state = barrier
    publisher._publish_once()
    assert publisher.is_ready()
    publication = publisher._v4_publication
    assert publication.candidate.inputs is state.inputs
    binding = _result_binding(publisher)
    assert publisher.result_binding_is_current(binding)
    assert publisher.policy_rule_identity_for_result(binding) == _IDENTITY
    assert publisher.result_binding_is_current(_result_binding(publisher, None))
    assert publisher.policy_rule_identity_for_result(_result_binding(publisher, None)) is None

    def forbidden(*args, **kwargs):
        pytest.fail("hot binding and provenance may not re-read source, config, or filesystem")

    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", forbidden)
    monkeypatch.setattr(publisher, "_current_input_fingerprint", forbidden)
    monkeypatch.setattr(publisher, "_compiled_effective_policy", forbidden)
    assert publisher.current_snapshot_binding()["source_input_digest"] == state.inputs.input_digest
    assert publisher.policy_rule_identity_for_result(binding) == _IDENTITY
    exposed = publisher.current_snapshot()
    exposed["source_input_digest"] = "f" * 64
    assert publisher.result_binding_is_current(binding)


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_generation", True),
        ("policy_generation", 999),
        ("policy_digest", "0" * 64),
        ("source_input_digest", "0" * 64),
        ("runtime_identity", "0" * 64),
        ("resident_generation", True),
        ("resident_generation", 999),
        ("selected_decision_id", True),
        ("selected_decision_id", 0),
        ("selected_decision_id", 999),
    ],
)
def test_substituted_result_cannot_expose_a_decision_or_provenance(barrier, field, value):
    publisher, _ = barrier
    publisher._publish_once()
    binding = _result_binding(publisher)
    binding[field] = value
    assert not publisher.result_binding_is_current(binding)
    assert publisher.policy_rule_identity_for_result(binding) is None


@pytest.mark.parametrize("alter", ["missing", "extra"])
def test_result_binding_is_exact_not_a_partial_comparison(barrier, alter):
    publisher, _ = barrier
    publisher._publish_once()
    binding = _result_binding(publisher)
    if alter == "missing":
        del binding["source_input_digest"]
    else:
        binding["unrecognized"] = True
    assert not publisher.result_binding_is_current(binding)


@pytest.mark.parametrize("mutation", ["epoch", "close", "expiry"])
def test_results_are_fenced_after_evaluation_even_without_selected_row(barrier, mutation):
    publisher, state = barrier
    publisher._publish_once()
    bindings = [_result_binding(publisher), _result_binding(publisher, None)]
    if mutation == "epoch":
        publisher.request_publish()
    elif mutation == "close":
        publisher.close()
    else:
        state.now = 10.0
    for binding in bindings:
        assert not publisher.result_binding_is_current(binding)
        assert publisher.policy_rule_identity_for_result(binding) is None
    _assert_closed(publisher)


@pytest.mark.parametrize("mutation", ["epoch", "close", "source", "config", "expiry", "resident"])
def test_inflight_publication_cannot_overwrite_newer_authority(barrier, mutation):
    publisher, state = barrier
    if mutation == "resident":
        _resident(publisher.guard_home)

    def mutate():
        if mutation == "epoch":
            publisher.request_publish()
        elif mutation == "close":
            publisher.close()
        elif mutation == "source":
            state.inputs = replace(state.inputs, input_digest="e" * 64)
        elif mutation == "config":
            state.config["default_action"] = "block"
        elif mutation == "expiry":
            state.now = 10.0
        else:
            _resident(publisher.guard_home, generation=4)

    state.during_ack = mutate
    publisher._publish_once()
    assert len(state.calls) == 1
    _assert_closed(publisher)


def test_no_resident_metadata_is_not_positive_ready_evidence(barrier):
    publisher, state = barrier
    state.materialize = False
    publisher._publish_once()
    _assert_closed(publisher)
    assert publisher.last_error == "native_policy_snapshot_resident_changed"


def test_noncanonical_resident_generation_name_cannot_open_readiness(barrier):
    publisher, state = barrier

    def rename_metadata():
        canonical = _resident(publisher.guard_home)
        canonical.rename(canonical.with_name("generation-3.json"))

    state.during_ack = rename_metadata
    publisher._publish_once()
    _assert_closed(publisher)
    assert publisher.last_error == "native_policy_snapshot_resident_changed"


def test_source_mutation_during_fresh_capture_is_rejected(barrier, monkeypatch):
    publisher, state = barrier
    calls = 0

    def capture(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            (publisher.guard_home / "config.toml").write_text('mode = "observe"\n')
        return state.inputs

    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", capture)
    publisher._publish_once()
    assert calls == 2
    _assert_closed(publisher)


def test_resident_restart_after_fresh_capture_is_rejected(barrier, monkeypatch):
    publisher, state = barrier
    calls = 0

    def capture(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            _resident(publisher.guard_home, generation=4)
        return state.inputs

    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", capture)
    publisher._publish_once()
    _assert_closed(publisher)
    assert publisher.last_error == "native_policy_snapshot_resident_changed"


def test_capture_unavailable_during_renewal_revokes_previous_ready_publication(barrier, monkeypatch):
    publisher, _ = barrier
    publisher._publish_once()
    binding = _result_binding(publisher)

    def unavailable(*args, **kwargs):
        raise NativePolicySnapshotError("native_policy_authority_local_unavailable")

    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", unavailable)
    publisher._publish_once(renew_after_generation=1)
    _assert_closed(publisher)
    assert not publisher.result_binding_is_current(binding)


@pytest.mark.parametrize("missing", sorted(scoped.SCOPED_PUBLISH_FEATURES))
def test_partial_v4_features_never_downgrade_or_publish(barrier, missing):
    publisher, state = barrier
    state.status.capabilities.features = tuple(f for f in state.status.capabilities.features if f != missing)
    publisher._publish_once()
    _assert_closed(publisher)
    assert state.calls == []
    assert publisher.requires_scoped_authority
    assert publisher.last_error == "native_policy_snapshot_protocol_unsupported"


@pytest.mark.parametrize("loss", ["v4", "disabled", "unavailable", "incompatible"])
def test_losing_runtime_support_revokes_an_accepted_scoped_publication(barrier, loss):
    publisher, state = barrier
    publisher._publish_once()
    binding = _result_binding(publisher)
    if loss == "v4":
        state.status = _status()
    elif loss == "disabled":
        state.status.mode = "off"
    elif loss == "unavailable":
        state.status.available = False
    else:
        state.status.compatible = False
    publisher._publish_once(renew_after_generation=1)
    assert len(state.calls) == 1
    _assert_closed(publisher)
    assert not publisher.result_binding_is_current(binding)


def test_observer_ignores_unchanged_source_but_invalidates_changed_source(barrier):
    publisher, state = barrier
    publisher._publish_once()
    database = str(publisher.guard_home / "guard.db")
    assert not publisher._policy_input_changed({database})
    state.inputs = replace(state.inputs, input_digest="e" * 64)
    assert publisher._policy_input_changed({database})
    assert not publisher._policy_input_changed({database})
    assert publisher._policy_input_changed({str(publisher.guard_home / "config.toml")})
    _assert_closed(publisher)


def test_real_concurrent_epoch_mutation_fences_blocked_ack(barrier):
    publisher, state = barrier
    entered, release = threading.Event(), threading.Event()

    def wait_for_mutation():
        entered.set()
        assert release.wait(5)

    state.during_ack = wait_for_mutation
    worker = threading.Thread(target=publisher._publish_once)
    worker.start()
    try:
        assert entered.wait(5)
        publisher.request_publish()
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    _assert_closed(publisher)


@pytest.mark.parametrize("revoke", [False, True])
def test_actual_signed_source_and_post_ack_revocation_use_real_authority(tmp_path, monkeypatch, revoke):
    from tests.test_canonical_policy_row_authority import _NOW, _activated_store
    from tests.test_native_policy_authority_read import _TIME

    store = _activated_store(tmp_path, action="block")
    status = _status()
    status.capabilities.features += tuple(scoped.SCOPED_PUBLISH_FEATURES)
    calls = []

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        calls.append(snapshot)
        _resident(store.guard_home)
        if revoke:
            keyring = store.get_sync_payload("policy_bundle_keyring")
            assert isinstance(keyring, dict)
            keys = keyring["keys"]
            assert isinstance(keys, list) and isinstance(keys[0], dict)
            keys[0]["state"] = "revoked"
            # Exercise the independent post-ACK source read even without the
            # in-process notification; the actual keyring write is unchanged.
            with monkeypatch.context() as isolated:
                isolated.setattr(snapshot_registry, "notify_native_policy_mutation", lambda *args, **kwargs: None)
                store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
        return json.dumps(_ack(snapshot)).encode()

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=lambda: status,
        client_request=client,
        wall_clock=lambda: _TIME,
    )
    try:
        epoch = publisher._epoch
        publisher._publish_once()
        assert publisher._epoch == epoch
        assert len(calls) == 1
        assert calls[0]["scoped_authority"]["rows"][0]["action"] == "block"
        if revoke:
            _assert_closed(publisher)
            assert publisher.last_error == "native_policy_authority_bundle_unavailable"
        else:
            assert publisher.is_ready(), publisher.last_error
            selected = calls[0]["scoped_authority"]["rows"][0]["decision_id"]
            binding = _result_binding(publisher, selected)
            assert publisher.result_binding_is_current(binding)
            identity = publisher.policy_rule_identity_for_result(binding)
            assert identity is not None
            assert identity.to_dict() == {
                "policyId": "synthetic.policy",
                "ruleId": "synthetic.rule",
                "policyVersion": "8",
            }
    finally:
        publisher.close()


def test_refused_scoped_negotiation_is_sticky_before_first_accepted_snapshot(barrier):
    publisher, state = barrier
    state.status.capabilities.features = tuple(
        feature for feature in state.status.capabilities.features if feature != "hook-envelope-v3"
    )
    publisher._publish_once()
    assert publisher.requires_scoped_authority
    state.status = _status()
    publisher._publish_once()
    assert publisher.requires_scoped_authority
    assert not state.calls
    _assert_closed(publisher)


def test_post_ack_same_digest_with_elapsed_source_lease_is_rejected(barrier, monkeypatch):
    publisher, state = barrier
    calls = 0

    def capture(*args, **kwargs):
        nonlocal calls
        calls += 1
        return replace(state.inputs, expires_at_ms=1000) if calls == 2 else state.inputs

    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", capture)
    publisher._publish_once()
    _assert_closed(publisher)
    assert publisher.last_error == "native_policy_snapshot_expired"


def test_database_change_and_revert_during_capture_is_fenced_even_with_restored_mtime(barrier, monkeypatch):
    import os

    publisher, state = barrier
    database = publisher.guard_home / "guard.db"
    with sqlite3.connect(database) as connection:
        connection.execute("create table synthetic_authority (value text)")
        connection.execute("insert into synthetic_authority values ('original')")
    reads = 0

    def capture(*args, **kwargs):
        nonlocal reads
        reads += 1
        if reads == 2:
            before = database.stat()
            for value in ("modified", "original"):
                with sqlite3.connect(database) as connection:
                    connection.execute("update synthetic_authority set value = ?", (value,))
            os.utime(database, ns=(before.st_atime_ns, before.st_mtime_ns))
        return state.inputs

    monkeypatch.setattr(scoped, "read_native_policy_authority_inputs", capture)
    publisher._publish_once()
    assert reads == 2
    _assert_closed(publisher)
    assert publisher.last_error == "native_policy_authority_capture_changed"
    with sqlite3.connect(database) as connection:
        assert connection.execute("select value from synthetic_authority").fetchone()[0] == "original"


def test_missing_legacy_required_feature_cannot_be_hidden_by_an_unrelated_feature(barrier):
    publisher, state = barrier
    state.status = _status()
    state.status.capabilities.features = (
        *(feature for feature in state.status.capabilities.features if feature != "policy-snapshot-v3"),
        "synthetic-unrelated-feature",
    )
    publisher._publish_once()
    _assert_closed(publisher)
    assert not state.calls
    assert publisher.last_error == "native_policy_snapshot_protocol_unsupported"


def test_changed_command_controls_reject_scoped_ack_with_unchanged_source(barrier):
    publisher, state = barrier
    original_source = state.inputs.input_digest
    state.during_ack = lambda: setattr(state, "command_extensions", _binding(revision=4))
    publisher._publish_once()
    assert len(state.calls) == 1
    assert state.inputs.input_digest == original_source
    _assert_closed(publisher)
    assert publisher.last_error == "native_command_control_binding_changed"


def test_scoped_request_binding_retains_command_mutation_fence(barrier):
    publisher, _ = barrier
    publisher._publish_once()
    assert publisher.is_ready()
    binding = publisher.current_snapshot_binding()
    assert binding is not None and binding["command_extensions_bound"] is True
    assert publisher.result_binding_is_current(_result_binding(publisher))

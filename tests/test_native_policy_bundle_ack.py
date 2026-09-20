"""Real signed store and publication fences; resident ACK transport is synthetic."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_bundle_acceptance import capture_accepted_policy_bundle
from codex_plugin_scanner.guard.native_policy_bundle_ack import commit_native_policy_bundle_acknowledgement
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.policy_bundle_generic_ack import generic_policy_bundle_acknowledgement
from tests.native_expression_resident_fixtures import WORKSPACE_ID, prepare_expression_store, publish_expression_source
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_native_policy_snapshot_v4_publication import _ack


@pytest.fixture
def accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    store, workspace = prepare_expression_store(tmp_path)
    publish_expression_source(store, workspace, block_lifetime_seconds=300)
    bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(bundle, dict)
    installation = store.get_or_create_installation_id()
    previous = generic_policy_bundle_acknowledgement(
        device_id=installation, policy_bundle=bundle, synced_at="2026-09-18T00:00:00Z", applied=False
    )
    store.set_sync_payload("policy_bundle_ack", previous, "2026-09-18T00:00:00Z")
    status = _status()
    assert status.capabilities is not None
    status.capabilities.features += (*SCOPED_PUBLISH_FEATURES, "policy-command-expressions-v1")

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        directory.mkdir(parents=True, exist_ok=True)
        generation = directory / "generation-00000000000000000003.json"
        if not generation.exists():
            generation.write_text("{}")
        return json.dumps(_ack(snapshot)).encode()

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=client)
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    token = capture_accepted_policy_bundle(publisher, bundle=bundle, installation_id=installation)
    assert token is not None
    yield store, publisher, token, bundle, previous
    publisher.close()


def test_applied_transition_is_bound_and_idempotent_without_republish(accepted):
    store, publisher, token, _, previous = accepted
    old_binding = publisher.current_snapshot_binding()
    materialization = store.get_sync_payload("policy_bundle_materialization")
    result = commit_native_policy_bundle_acknowledgement(publisher, token)
    assert result is not None
    assert result["status"] == "applied"
    assert result["sequence"] == previous["sequence"] + 1
    assert result["workspaceId"] == WORKSPACE_ID
    assert commit_native_policy_bundle_acknowledgement(publisher, token) == result
    assert store.get_sync_payload("policy_bundle_materialization") == materialization
    assert publisher.current_snapshot_binding() == old_binding
    assert publisher.is_ready()


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", 999),
        ("policy_digest", "0" * 64),
        ("source_input_digest", "0" * 64),
        ("runtime_identity", "0" * 64),
        ("resident_generation", 999),
        ("mode", "observe"),
    ],
)
def test_each_changed_binding_field_refuses_without_ack_write(accepted, field, value):
    store, publisher, token, _, previous = accepted
    substituted = replace(token, binding=replace(token.binding, **{field: value}))
    assert commit_native_policy_bundle_acknowledgement(publisher, substituted) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous


def test_epoch_change_refuses_even_if_snapshot_fields_are_retained(accepted):
    store, publisher, token, _, previous = accepted
    publisher.request_publish()
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous


@pytest.mark.parametrize(
    "mutation", ["source", "source_revert", "signer", "installation", "workspace", "config", "resident"]
)
def test_change_during_authenticated_capture_refuses(accepted, monkeypatch, mutation):
    from codex_plugin_scanner.guard import native_policy_bundle_ack as ack

    store, publisher, token, _, previous = accepted
    original = ack.compiled_scoped_policy

    def interpose(value):
        captured = original(value)
        if mutation in {"source", "source_revert"}:
            prior = store.get_sync_payload("policy_bundle")
            store.set_sync_payload("policy_bundle", {}, "2026-09-18T00:00:00Z")
            if mutation == "source_revert":
                store.set_sync_payload("policy_bundle", prior, "2026-09-18T00:00:00Z")
        elif mutation == "signer":
            store.set_sync_payload("policy_bundle_keyring", {}, "2026-09-18T00:00:00Z")
        elif mutation == "installation":
            with store._connect() as connection:
                connection.execute(
                    "update guard_devices set installation_id = 'different' where device_key = 'local-device'"
                )
        elif mutation == "workspace":
            store.set_sync_payload("oauth_local_credentials", {"workspace_id": "different"}, "2026-09-18T00:00:00Z")
        elif mutation == "config":
            path = store.guard_home / "config.toml"
            path.write_text(path.read_text().replace('mode = "enforce"', 'mode = "observe"'))
        else:
            directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
            (directory / "generation-00000000000000000004.json").write_text("{}")
        return captured

    monkeypatch.setattr(ack, "compiled_scoped_policy", interpose)
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous


def test_expiry_after_ack_sql_rolls_back_before_commit(accepted, monkeypatch):
    from codex_plugin_scanner.guard import native_policy_bundle_ack as ack

    store, publisher, token, _, previous = accepted
    write = ack._write_payload

    def expire_after_write(*args):
        write(*args)
        monkeypatch.setattr(publisher, "_wall_clock", lambda: token.expires_at_ms / 1000 + 1)

    monkeypatch.setattr(ack, "_write_payload", expire_after_write)
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous
    assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None


def test_ack_commit_failure_rolls_back_and_preserves_ready_source(accepted, monkeypatch):
    import sqlite3
    from contextlib import contextmanager

    store, publisher, token, _, previous = accepted
    connect = store._connect
    before = publisher.current_snapshot_binding()
    attempted_commits = 0

    class FailingCommit:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def commit(self):
            nonlocal attempted_commits
            attempted_commits += 1
            raise sqlite3.OperationalError("synthetic commit failure")

    @contextmanager
    def failing():
        with connect() as connection:
            yield FailingCommit(connection)

    monkeypatch.setattr(store, "_connect", failing)
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous
    assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    assert publisher.current_snapshot_binding() == before
    assert attempted_commits == 1


def test_condition_contention_never_waits_while_holding_sql_write_lock(accepted, monkeypatch):
    import threading
    from contextlib import contextmanager

    store, publisher, token, _, previous = accepted
    connect = store._connect
    reserved, held, completed = threading.Event(), threading.Event(), threading.Event()
    main_thread = threading.current_thread()
    intercepted = False

    def holder():
        assert reserved.wait(2)
        with publisher._condition:
            held.set()
            with connect() as connection:
                connection.execute("begin immediate")
                connection.execute("select 1")
        completed.set()

    class Interposed:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, sql, *args):
            nonlocal intercepted
            cursor = self.connection.execute(sql, *args)
            if sql == "begin immediate" and threading.current_thread() is main_thread and not intercepted:
                intercepted = True
                reserved.set()
                assert held.wait(2)
            return cursor

    @contextmanager
    def interposed():
        with connect() as connection:
            yield Interposed(connection)

    monkeypatch.setattr(store, "_connect", interposed)
    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
        assert completed.wait(2)
    finally:
        reserved.set()
        thread.join(3)
    assert not thread.is_alive()
    assert store.get_sync_payload("policy_bundle_ack") == previous


def test_old_unbound_applied_ack_does_not_supply_native_acceptance(accepted):
    store, publisher, token, bundle, previous = accepted
    old = generic_policy_bundle_acknowledgement(
        device_id=str(previous["deviceId"]),
        policy_bundle=bundle,
        synced_at="2026-09-18T00:00:01Z",
        applied=True,
        previous=previous,
    )
    store.set_sync_payload("policy_bundle_ack", old, "2026-09-18T00:00:01Z")
    publisher.request_publish()
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
    assert store.get_sync_payload("policy_bundle_ack") == old


@pytest.mark.parametrize("mode", ["off", "shadow"])
@pytest.mark.parametrize("at_commit", [False, True])
def test_non_native_mode_cannot_be_promoted(accepted, monkeypatch, mode, at_commit):
    from codex_plugin_scanner.guard import native_policy_bundle_ack as module

    store, publisher, token, _, previous = accepted
    if at_commit:
        original = module._write_payload

        def write_then_change_mode(*args, **kwargs):
            original(*args, **kwargs)
            monkeypatch.setenv("HOL_GUARD_NATIVE", mode)

        monkeypatch.setattr(module, "_write_payload", write_then_change_mode)
    else:
        monkeypatch.setenv("HOL_GUARD_NATIVE", mode)
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous


@pytest.mark.parametrize("canonical", [None, "0", "false"])
@pytest.mark.parametrize("at_commit", [False, True])
def test_withdrawn_canonical_lane_cannot_be_promoted(accepted, monkeypatch, canonical, at_commit):
    from codex_plugin_scanner.guard import native_policy_bundle_ack as module

    store, publisher, token, _, previous = accepted

    def withdraw():
        if canonical is None:
            monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
        else:
            monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", canonical)

    if at_commit:
        original = module._write_payload

        def write_then_withdraw(*args, **kwargs):
            original(*args, **kwargs)
            withdraw()

        monkeypatch.setattr(module, "_write_payload", write_then_withdraw)
    else:
        withdraw()
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert store.get_sync_payload("policy_bundle_ack") == previous
    assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None


@pytest.mark.parametrize("legacy_historical_binding", [False, True])
def test_same_source_republication_retains_wire_ack_but_requires_fresh_native_token(
    accepted, legacy_historical_binding
):
    store, publisher, token, bundle, _ = accepted
    first = commit_native_policy_bundle_acknowledgement(publisher, token)
    assert first is not None
    if legacy_historical_binding:
        retained = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(retained, dict) and isinstance(retained["binding"], dict)
        retained["binding"].pop("command_extensions_bound")
        store.set_sync_payload("native_policy_bundle_ack_acceptance", retained, "2026-09-18T00:00:00Z")
    materialization = store.get_sync_payload("policy_bundle_materialization")
    publisher.request_publish()
    publisher._publish_once()
    renewed = capture_accepted_policy_bundle(
        publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
    )
    assert renewed is not None and renewed.binding.generation != token.binding.generation
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    assert commit_native_policy_bundle_acknowledgement(publisher, renewed) == first
    assert store.get_sync_payload("policy_bundle_ack") == first
    assert store.get_sync_payload("policy_bundle_materialization") == materialization
    record = store.get_sync_payload("native_policy_bundle_ack_acceptance")
    assert isinstance(record, dict) and record["binding"] == renewed.binding.to_request_binding()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "source",
        "ack",
        "binding",
        "epoch",
        "generation_bool",
        "digest_null",
        "mode_invalid",
        "command_binding_false",
        "command_binding_number",
        "binding_unknown_field",
    ],
)
def test_fresh_publication_does_not_reuse_unbound_or_mismatched_historical_ack(accepted, mutation):
    store, publisher, token, bundle, _ = accepted
    first = commit_native_policy_bundle_acknowledgement(publisher, token)
    assert first is not None
    sequence = first["sequence"]
    assert type(sequence) is int
    record = store.get_sync_payload("native_policy_bundle_ack_acceptance")
    assert isinstance(record, dict)
    if mutation == "missing":
        with store._connect() as connection:
            connection.execute("delete from sync_state where state_key='native_policy_bundle_ack_acceptance'")
    else:
        if mutation == "source":
            record["source"] = {**token.source, "device_id": "other-installation"}
        elif mutation == "ack":
            record["ack"] = {**first, "sequence": sequence + 1}
        elif mutation == "binding":
            record["binding"] = {}
        elif mutation == "epoch":
            record["epoch"] = True
        else:
            field, value = {
                "generation_bool": ("generation", True),
                "digest_null": ("policy_digest", None),
                "mode_invalid": ("mode", "unknown"),
                "command_binding_false": ("command_extensions_bound", False),
                "command_binding_number": ("command_extensions_bound", 1),
                "binding_unknown_field": ("unknown", True),
            }[mutation]
            retained_binding = record["binding"]
            assert isinstance(retained_binding, dict)
            retained_binding[field] = value
        store.set_sync_payload("native_policy_bundle_ack_acceptance", record, "2026-09-18T00:00:00Z")
    publisher.request_publish()
    publisher._publish_once()
    fresh = capture_accepted_policy_bundle(
        publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
    )
    assert fresh is not None and fresh != token
    assert commit_native_policy_bundle_acknowledgement(publisher, token) is None
    updated = commit_native_policy_bundle_acknowledgement(publisher, fresh)
    assert updated is not None and updated["sequence"] == sequence + 1
    assert updated != first

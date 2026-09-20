"""Actual publisher/authority controls with a modeled native transport only."""

from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_command_fixture import prepare_empty_command_authority
from scripts.native_slo_workspace_lifecycle_faults import (
    FirstAdmissionReplyFault,
    LostMetadataHints,
    key_recovery_matches,
    recover_command_key,
    require_withdrawn,
)
from tests.native_policy_snapshot_test_fixtures import _ack, _status
from tests.test_native_command_control_authority_publisher import _persist_native_floor


def _publisher(tmp_path, monkeypatch):
    home = tmp_path / "guard-home"
    store = GuardStore(home)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    prepare_empty_command_authority(store)
    calls = []

    def client(**kwargs):
        calls.append(kwargs)
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client)
    return store, publisher, calls


def test_first_real_reply_is_discarded_and_only_subsequent_validated_ack_opens_barrier(tmp_path, monkeypatch):
    _, publisher, calls = _publisher(tmp_path, monkeypatch)
    original = publisher._client_request
    try:
        with FirstAdmissionReplyFault(publisher) as fault:
            publisher._publish_once()
            require_withdrawn(publisher)
            assert publisher.last_error == "native_policy_snapshot_ack_invalid"
            assert fault.report()["real_accepted_reply_discarded"]
            assert fault.report()["production_ack_error_observed"]
            assert fault.report()["first_error_withheld_ack"]
            assert len(calls) == 1
            publisher._publish_once()
            assert publisher.is_ready()
            assert publisher.current_snapshot_binding() is not None
            assert len(calls) == 2
            assert fault.report()["subsequent_transport_forwarded"]
        assert publisher._client_request is original
        assert calls[0]["executable"] == calls[1]["executable"]
        assert calls[0]["guard_home"] == calls[1]["guard_home"]
    finally:
        publisher.close()


@pytest.mark.parametrize("output", [None, b"{}", b"invalid"])
def test_original_transport_failure_does_not_count_as_injected_accepted_reply(tmp_path, monkeypatch, output):
    _, publisher, _ = _publisher(tmp_path, monkeypatch)

    def original(**kwargs):
        return output

    publisher._client_request = original
    try:
        with FirstAdmissionReplyFault(publisher) as fault:
            publisher._publish_once()
            require_withdrawn(publisher)
            assert fault.report()["real_accepted_reply_discarded"] is False
            assert fault.report()["production_ack_error_observed"] is False
        assert publisher._client_request is original
    finally:
        publisher.close()


def test_first_admission_fault_refuses_an_already_acknowledged_publisher(tmp_path, monkeypatch):
    _, publisher, _ = _publisher(tmp_path, monkeypatch)
    try:
        publisher._publish_once()
        assert publisher.is_ready()
        original = publisher._client_request
        with pytest.raises(RuntimeError, match="cold publisher"), FirstAdmissionReplyFault(publisher):
            pytest.fail("must reject before replacing live transport")
        assert publisher._client_request is original
        assert publisher.is_ready()
    finally:
        publisher.close()


@pytest.mark.parametrize("field,value", [("generation", 999), ("policy_digest", "f" * 64)])
def test_first_admission_fault_never_counts_a_well_formed_mismatched_ack(tmp_path, monkeypatch, field, value):
    _, publisher, _ = _publisher(tmp_path, monkeypatch)

    def client(**kwargs):
        result = json.loads(_ack(kwargs["payload"]))
        result[field] = value
        return json.dumps(result).encode()

    publisher._client_request = client
    try:
        with FirstAdmissionReplyFault(publisher) as fault:
            publisher._publish_once()
            require_withdrawn(publisher)
            assert publisher.last_error == "native_policy_snapshot_ack_mismatch"
            assert fault.report()["real_accepted_reply_discarded"] is False
            assert fault.report()["production_ack_error_observed"] is False
    finally:
        publisher.close()


def test_metadata_loss_reads_real_changed_input_and_forwards_every_resident_identity(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("before")
    resident = [(("resident", 1, 1),)]
    calls = []

    def original():
        value = (((str(path), path.stat().st_size),), resident[0])
        calls.append(value)
        return value

    publisher = SimpleNamespace(_current_input_fingerprint=original)
    with LostMetadataHints(publisher) as fault:
        assert publisher._current_input_fingerprint() == calls[0]
        assert not fault.report()["actual_changed_hint_observed"]
        path.write_text("actual changed bytes")
        resident[0] = (("resident", 2, 2),)
        policy, actual_resident = publisher._current_input_fingerprint()
        assert policy == calls[0][0] and policy != calls[-1][0]
        assert actual_resident is resident[0]
        assert fault.report()["changed_metadata_hints_dropped"] == 1
        assert path.read_text() == "actual changed bytes"
    assert publisher._current_input_fingerprint is original
    assert publisher._current_input_fingerprint()[0] != policy


def test_metadata_fault_preserves_original_exception_and_restores_on_failure():
    failure = OSError("capture failure")
    calls = 0

    def original():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise failure
        return (), ()

    publisher = SimpleNamespace(_current_input_fingerprint=original)
    with pytest.raises(OSError) as captured, LostMetadataHints(publisher):
        publisher._current_input_fingerprint()
    assert captured.value is failure
    assert publisher._current_input_fingerprint is original


def test_missing_real_command_key_recovers_new_authenticated_epoch_without_discarding_binding(tmp_path, monkeypatch):
    store, publisher, _ = _publisher(tmp_path, monkeypatch)
    session = SimpleNamespace(store=store, guard_home=store.guard_home)
    probes = []
    try:
        publisher._publish_once()
        before = publisher.current_snapshot()
        assert before is not None
        _persist_native_floor(store.guard_home, before)

        def probe():
            require_withdrawn(publisher)
            assert store._authority_key(required=False) is None
            probes.append(True)
            return {"passed": True}

        accepted, evidence = recover_command_key(session, publisher, before, probe)
        require_withdrawn(publisher)
        assert accepted > 0 and probes == [True]
        assert evidence["supported_recovery_returned"]
        publisher._publish_once()
        after = publisher.current_snapshot()
        assert after is not None, publisher.last_error
        assert key_recovery_matches(before, after)
        assert "command_extensions" in after
        assert after["command_extensions"]["layers"] == before["command_extensions"]["layers"] == []
        assert after["generation"] > before["generation"]
    finally:
        publisher.close()


def _keys():
    before = {"command_extensions": {"catalog_digest": "a" * 64, "authority": {"authority_key_id": "old", "epoch": 2}}}
    after = {
        "command_extensions": {
            "health": "protected",
            "catalog_digest": "a" * 64,
            "authority": {
                "authority_key_id": "new",
                "epoch": 3,
                "recovery": {"previous_authority_key_id": "old", "previous_epoch": 2},
            },
        }
    }
    return before, after


@pytest.mark.parametrize(
    "field,value", [("authority_key_id", "old"), ("epoch", 2), ("epoch", True), ("recovery", None)]
)
def test_key_change_requires_new_key_epoch_and_exact_recovery_link(field, value):
    before, after = _keys()
    assert key_recovery_matches(before, after)
    altered = copy.deepcopy(after)
    altered["command_extensions"]["authority"][field] = value
    assert not key_recovery_matches(before, altered)


def test_require_withdrawn_rejects_stale_snapshot_even_when_ready_flag_is_false():
    publisher = SimpleNamespace(current_snapshot_binding=lambda: {"generation": 1}, is_ready=lambda: False)
    with pytest.raises(RuntimeError, match="retained acknowledgment"):
        require_withdrawn(publisher)


def test_first_admission_error_is_forwarded_without_replacing_exception():
    failure = OSError("original error recorder failure")

    def record(_):
        raise failure

    publisher = SimpleNamespace(
        _thread=None,
        _snapshot=None,
        _acked=False,
        _condition=threading.Condition(),
        _client_request=lambda **kwargs: None,
        _record_error=record,
    )
    with FirstAdmissionReplyFault(publisher):
        with pytest.raises(OSError) as captured:
            publisher._record_error("native_policy_snapshot_ack_invalid")
        assert captured.value is failure
    assert publisher._record_error is record

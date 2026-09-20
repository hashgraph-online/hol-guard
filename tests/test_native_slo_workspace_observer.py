"""Finite forwarding controls; these doubles are never installed qualification."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import config
from codex_plugin_scanner.guard import native_policy_snapshot_publisher as publisher_module
from codex_plugin_scanner.guard import native_policy_snapshot_publisher_transport as transport_module
from scripts.native_slo_workspace_observer import MAX_EVENTS, PublicationObserver, public_binding
from scripts.native_slo_workspace_trace import phase_chain

BINDING = {"generation": 17, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}


def _fixture(tmp_path, monkeypatch, fail=None):
    calls = []
    failure = RuntimeError("private payload /home/person must never be recorded")
    settings = object()
    response = object()
    snapshot = {**BINDING, "master_key": "private signing bytes", "raw_command": "private command"}
    publisher = SimpleNamespace(
        _condition=threading.Condition(),
        _snapshot=None,
        _acked=False,
        _closed=False,
        _workspace_paths={tmp_path},
        _compiled_workspace_policies={},
    )

    def stage(name):
        calls.append(name)
        if name == fail:
            raise failure

    def load(home, *, workspace, **kwargs):
        stage("load")
        assert home is tmp_path and workspace is tmp_path and kwargs == {"private_value": "private config"}
        return settings

    def compile_policy():
        stage("compile")
        return config.load_guard_config(tmp_path, workspace=tmp_path, private_value="private config")

    def encode(value):
        stage("encode")
        assert value is snapshot
        return b"private IPC bytes"

    def client(value, *, native_deadline):
        stage("client")
        assert value == b"private IPC bytes" and native_deadline == 10.25
        return response

    def transport(*, publisher: object, client: object, config: object):
        assert publisher is owner and config is settings
        wire = transport_module._policy_snapshot_push_bytes_v3(snapshot)
        assert client(wire, native_deadline=10.25) is response
        stage("validate")
        return snapshot, 3

    def publish_once():
        effective = publisher._compiled_effective_policy()
        result = publisher_module._publish_snapshot_v3(publisher=publisher, client=client, config=effective)
        publisher._snapshot, publisher._acked = result[0], True
        return result

    def forbidden():
        raise AssertionError("observer must not call authority-mutating readiness getters")

    owner = publisher
    publisher._compiled_effective_policy = compile_policy
    publisher._publish_once = publish_once
    publisher.current_snapshot_binding = publisher.current_snapshot = publisher.is_ready = forbidden
    monkeypatch.setattr(config, "load_guard_config", load)
    monkeypatch.setattr(transport_module, "_policy_snapshot_push_bytes_v3", encode)
    monkeypatch.setattr(publisher_module, "_publish_snapshot_v3", transport)
    return publisher, PublicationObserver(publisher, (tmp_path,)), calls, failure, snapshot


def test_forwarding_preserves_arguments_results_deadlines_and_restores_all_bindings(tmp_path, monkeypatch):
    publisher, observer, calls, _, snapshot = _fixture(tmp_path, monkeypatch)
    originals = (
        publisher._compiled_effective_policy,
        publisher._publish_once,
        config.load_guard_config,
        publisher_module._publish_snapshot_v3,
        transport_module._policy_snapshot_push_bytes_v3,
    )
    with observer:
        result = publisher._publish_once()
        assert result[0] is snapshot
        assert calls == ["compile", "load", "encode", "client", "validate"]
        rows = observer.rows()
        assert [row["kind"] for row in rows] == ["compile", "push", "transport_ack", "barrier"]
        assert {row["publication"] for row in rows} == {1}
        assert rows[0]["config_loads"] == 1
        assert rows[0]["scope_loads"] == [0, 1]
        chain = phase_chain(rows, BINDING, accepted_ms=rows[-1]["finished_ms"] + 1)
        assert chain["matched"] and chain["accepted_to_compile_started_ms"] < 0
        rows[-1]["binding"]["generation"] = 999
        assert observer.rows()[-1]["binding"] == BINDING
    assert originals == (
        publisher._compiled_effective_policy,
        publisher._publish_once,
        config.load_guard_config,
        publisher_module._publish_snapshot_v3,
        transport_module._policy_snapshot_push_bytes_v3,
    )
    encoded = json.dumps(observer.rows())
    assert all(value not in encoded for value in (str(tmp_path), "private", "master_key", "raw_command", "IPC"))
    assert observer.report()["headline_timing_eligible"] is False


@pytest.mark.parametrize("stage", ["compile", "load", "encode", "client", "validate"])
def test_exceptions_are_same_objects_and_cleanup_restores_forwarders(tmp_path, monkeypatch, stage):
    publisher, observer, _, failure, _ = _fixture(tmp_path, monkeypatch, fail=stage)
    original = publisher._publish_once
    with pytest.raises(RuntimeError) as error, observer:
        publisher._publish_once()
    assert error.value is failure and publisher._publish_once is original
    observer.freeze()
    assert observer.report()["complete"] and observer.report()["calls_in_flight_at_freeze"] == 0
    assert observer.rows()[-1]["ready"] is False
    assert "private" not in json.dumps(observer.rows())


def test_setup_failure_restores_partially_installed_wrappers(tmp_path, monkeypatch):
    _publisher, observer, _, _, _ = _fixture(tmp_path, monkeypatch)
    original = config.load_guard_config
    monkeypatch.delattr(transport_module, "_policy_snapshot_push_bytes_v3")
    with pytest.raises(AttributeError):
        observer.__enter__()
    assert config.load_guard_config is original
    with pytest.raises(RuntimeError):
        observer.__enter__()


def test_phase_is_bound_to_publish_call_even_when_current_phase_changes(tmp_path, monkeypatch):
    publisher, observer, _, _, _ = _fixture(tmp_path, monkeypatch)
    original = publisher._compiled_effective_policy

    def change_phase():
        observer.phase(2)
        return original()

    publisher._compiled_effective_policy = change_phase
    with observer:
        observer.phase(1)
        publisher._publish_once()
    assert {row["phase"] for row in observer.rows()} == {1}


def test_foreign_calls_and_other_threads_do_not_become_owned_config_loads(tmp_path, monkeypatch):
    _publisher, observer, calls, _, _ = _fixture(tmp_path, monkeypatch)
    with observer:
        config.load_guard_config(tmp_path, workspace=tmp_path, private_value="private config")
        thread = threading.Thread(
            target=config.load_guard_config,
            args=(tmp_path,),
            kwargs={"workspace": tmp_path, "private_value": "private config"},
        )
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert observer.rows() == [] and calls == ["load", "load"]
        marker = object()
        assert observer._transport(lambda **_kwargs: marker)(publisher=object()) is marker


def test_overflow_keeps_forwarding_and_freeze_retains_immutable_bounded_rows(tmp_path):
    observer = PublicationObserver(SimpleNamespace(_workspace_paths={tmp_path}), (tmp_path,))
    calls = []
    wrapped = observer._compilation(lambda: calls.append(1))
    for _ in range(MAX_EVENTS + 3):
        wrapped()
    observer.freeze()
    before = observer.report()
    wrapped()
    assert len(calls) == MAX_EVENTS + 4
    assert observer.report() == before
    assert before["events"] == MAX_EVENTS and before["counts"]["overflow"] == 3 and not before["complete"]
    assert len(observer.page(0)["rows"]) == 32
    with pytest.raises(ValueError):
        observer.page(True)


def test_freeze_during_a_call_explicitly_marks_trace_incomplete(tmp_path):
    observer = PublicationObserver(SimpleNamespace(_workspace_paths={tmp_path}), (tmp_path,))
    entered, release = threading.Event(), threading.Event()

    def original():
        entered.set()
        assert release.wait(timeout=2)

    thread = threading.Thread(target=observer._compilation(original))
    thread.start()
    assert entered.wait(timeout=2)
    observer.freeze()
    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert observer.report()["calls_in_flight_at_freeze"] == 1
    assert not observer.report()["complete"] and observer.rows() == []


@pytest.mark.parametrize("value", [True, 0, -1, 2**64, "1", None])
def test_binding_rejects_non_u64_generation(value):
    assert public_binding({**BINDING, "generation": value}) is None


@pytest.mark.parametrize(
    "key,value",
    [
        ("policy_digest", "A" * 64),
        ("runtime_identity", "b" * 63),
        ("policy_digest", "../private"),
        ("runtime_identity", None),
    ],
)
def test_binding_rejects_non_digest_identity(key, value):
    assert public_binding({**BINDING, key: value}) is None


def test_unexpected_transport_return_is_forwarded_without_inventing_valid_ack(tmp_path):
    publisher = object()
    observer = PublicationObserver(publisher, (Path(tmp_path),))
    marker = object()
    assert observer._transport(lambda **_kwargs: marker)(publisher=publisher, client=lambda: None) is marker
    assert observer.rows()[0]["validated"] is False


def test_scope_count_overflow_keeps_calls_and_marks_trace_incomplete(tmp_path, monkeypatch):
    publisher, observer, calls, _, _ = _fixture(tmp_path, monkeypatch)
    publisher._compiled_effective_policy = lambda: [
        config.load_guard_config(tmp_path, workspace=tmp_path, private_value="private config") for _ in range(256)
    ]
    with observer:
        result = publisher._compiled_effective_policy()
    assert len(result) == len(calls) == 256
    assert observer.rows()[0]["scope_loads"] == [0, 255]
    assert observer.rows()[0]["config_loads"] == 256 and not observer.report()["complete"]

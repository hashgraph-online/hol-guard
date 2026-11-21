"""The publisher's active-security reads go to the resident, not a one-shot."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_execution, native_resident_client
from codex_plugin_scanner.guard.catalog_delivery import active_security, lifecycle

_KEY = b"k" * 32


@pytest.fixture
def store(tmp_path: Path, monkeypatch) -> SimpleNamespace:
    monkeypatch.setattr(active_security, "_key", lambda _store: _KEY)
    return SimpleNamespace(guard_home=tmp_path / "home", path=tmp_path / "home" / "guard.db")


def _resident(monkeypatch, answer, *, ready=True):
    calls = []
    status = SimpleNamespace(identity=SimpleNamespace(path=Path("runtime")))
    monkeypatch.setattr(native_execution, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_resident_client, "native_resident_client_ready", lambda _path, _home: ready)

    def request(*, operation, request, guard_home, **_kwargs):
        calls.append((operation, request, guard_home))
        return answer(request)

    monkeypatch.setattr(native_execution, "_resident_request", request)
    return calls


def _one_shot(monkeypatch):
    calls = []

    def invoke(kind, **fields):
        calls.append((kind, fields))
        return {"from": "one-shot"}

    monkeypatch.setattr(lifecycle, "invoke", invoke)
    return calls


def _ok(request):
    return {
        "schema": "guard-command-pack-record-result.v1",
        "request_id": request["request_id"],
        "status": "ok",
        "payload": {"from": "resident"},
    }


@pytest.mark.parametrize("operation", ["scope", "check", "read", "change", "marker", "binding", "resume"])
def test_reads_that_answer_from_the_request_alone_go_to_the_resident(store, monkeypatch, operation):
    resident = _resident(monkeypatch, _ok)
    spawned = _one_shot(monkeypatch)

    assert active_security.invoke(operation, store, record="r") == {"from": "resident"}

    assert spawned == []
    ((name, request, guard_home),) = resident
    assert name == "command_pack_record"
    assert guard_home == store.guard_home
    assert request["guard_home"] == str(store.guard_home)
    assert request["store_path"] == str(store.path)
    assert request["record"] == {"kind": "active-security", "operation": operation, "key": _KEY.hex(), "record": "r"}


@pytest.mark.parametrize("operation", ["begin", "complete"])
def test_preparing_a_record_stays_on_the_one_shot(store, monkeypatch, operation):
    resident = _resident(monkeypatch, _ok)
    spawned = _one_shot(monkeypatch)

    assert active_security.invoke(operation, store, record="r") == {"from": "one-shot"}

    assert resident == []
    assert spawned == [("active-security", {"operation": operation, "key": _KEY.hex(), "record": "r"})]


@pytest.mark.parametrize(
    "answer",
    [
        lambda _request: None,
        lambda request: {**_ok(request), "request_id": "another"},
        lambda request: {**_ok(request), "payload": None},
    ],
    ids=["refused", "another-request", "no-payload"],
)
def test_an_unanswered_read_spawns_the_one_shot(store, monkeypatch, answer):
    _resident(monkeypatch, answer)
    spawned = _one_shot(monkeypatch)

    assert active_security.invoke("scope", store, record="r") == {"from": "one-shot"}
    assert [kind for kind, _ in spawned] == ["active-security"]


def test_an_unreachable_resident_spawns_the_one_shot(store, monkeypatch):
    def unreachable(_request):
        raise OSError("socket closed")

    _resident(monkeypatch, unreachable)
    spawned = _one_shot(monkeypatch)

    assert active_security.invoke("read", store, record="r") == {"from": "one-shot"}
    assert len(spawned) == 1


def test_a_read_never_starts_a_resident(store, monkeypatch):
    resident = _resident(monkeypatch, _ok, ready=False)
    spawned = _one_shot(monkeypatch)

    assert active_security.invoke("marker", store, record="r", marker={}) == {"from": "one-shot"}
    assert resident == []
    assert len(spawned) == 1


def test_identical_reads_are_not_answered_from_memory(store, monkeypatch):
    resident = _resident(monkeypatch, _ok)
    _one_shot(monkeypatch)

    for _ in range(3):
        active_security.invoke("scope", store, record="r")

    assert len(resident) == 3

"""Short evidence polls must not turn a readiness race into a client spawn."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as clients
from codex_plugin_scanner.guard import native_resident_revival as revival
from codex_plugin_scanner.guard import native_resident_stream as streams
from tests.test_native_policy_snapshot_direct_lane import _publisher


def _unexpected(*_args: object, **_kwargs: object) -> None:
    pytest.fail("idle-only dispatch must not create, track, wait, or spawn")


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    executable = tmp_path / "runtime"
    pool = clients._PersistentNativeClientPool(
        executable=executable, state_dir=tmp_path / "native-runtime", environment={}
    )
    monkeypatch.setattr(clients, "_CLIENT_POOLS", {pool._hold_key: pool})
    monkeypatch.setattr(clients, "_PersistentNativeClient", _unexpected)
    monkeypatch.setattr(clients, "_track_resident", _unexpected)
    monkeypatch.setattr(pool._condition, "wait", _unexpected)
    monkeypatch.setattr(streams.subprocess, "Popen", _unexpected)
    kwargs = dict(executable=executable, guard_home=tmp_path, environment={}, payload=b"{}", timeout_seconds=1)
    return pool, kwargs


class _WarmClient:
    def __init__(self):
        self._process = SimpleNamespace(poll=lambda: None)
        self.calls = 0

    def request(self, payload, *, deadline_monotonic, allow_start):
        assert allow_start is False
        self.calls += 1
        return b"ok"


def test_transport_rechecks_idle_lease_after_readiness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pool, kwargs = _setup(tmp_path, monkeypatch)
    # On the pre-fix implementation, reach the actual cold-client construction
    # after readiness rather than failing on its incidental tracking call.
    monkeypatch.setattr(clients, "_track_resident", lambda *_args: None)
    client = _WarmClient()
    pool._clients.add(client)
    pool._idle.append(client)
    publisher = _publisher(tmp_path)
    publisher._last_runtime_status = SimpleNamespace(identity=SimpleNamespace(path=str(kwargs["executable"])))
    transport = publisher.direct_evidence_transport()
    assert transport is not None
    borrowed = pool._lease(deadline_monotonic=time.monotonic() + 1)
    assert borrowed is client
    assert transport[1](**kwargs) is None
    assert client.calls == 0
    assert pool._clients == {client}
    pool._idle.append(borrowed)
    assert transport[1](**kwargs) == b"ok"
    assert client.calls == 1
    assert pool._idle == [client]


@pytest.mark.parametrize("state", ["missing", "busy", "closed", "dead"])
def test_idle_misses_do_not_change_registry_or_restart_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state):
    pool, kwargs = _setup(tmp_path, monkeypatch)
    client = _WarmClient()
    pool._clients.add(client)
    if state == "missing":
        clients._CLIENT_POOLS.clear()
    elif state == "closed":
        pool._closed = True
        pool._idle.append(client)
    elif state == "dead":
        client._process = SimpleNamespace(poll=lambda: 1)
        pool._idle.append(client)
    registry = dict(clients._CLIENT_POOLS)
    monkeypatch.setattr(clients, "arm_restart_hold", _unexpected)
    monkeypatch.setattr(clients, "clear_restart_hold", _unexpected)
    revival.arm_restart_hold(pool._hold_key)
    try:
        assert clients.native_resident_client_request_if_idle(**kwargs) is None
        assert revival.restart_hold_active(pool._hold_key)
        assert registry == clients._CLIENT_POOLS
        assert pool._clients == {client}
        assert client.calls == 0
    finally:
        revival.clear_restart_hold(pool._hold_key)


@pytest.mark.parametrize("contained", [True, False])
def test_client_dying_after_lease_is_retired_without_respawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contained: bool
):
    pool, kwargs = _setup(tmp_path, monkeypatch)
    client = streams._PersistentNativeClient(
        executable=kwargs["executable"], state_dir=tmp_path / "native-runtime", environment={}
    )
    polls = iter([None, 1])
    client._process = SimpleNamespace(poll=lambda: next(polls))
    closes = []
    failures = []
    monkeypatch.setattr(client, "_record_phase_failure", lambda code, phase: failures.append((code, phase)))
    monkeypatch.setattr(client, "close", lambda **kw: closes.append(kw) or contained)
    monkeypatch.setattr(client, "_write_frame", _unexpected)
    pool._clients.add(client)
    pool._idle.append(client)
    assert clients.native_resident_client_request_if_idle(**kwargs) is None
    assert failures == [("native_client_stream_failed", "idle_stream_exited")]
    assert len(closes) == 1
    assert pool._idle == []
    assert (client in pool._clients) is not contained
    assert (client in pool._retiring) is not contained


def test_absent_process_cannot_start_through_idle_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _pool, kwargs = _setup(tmp_path, monkeypatch)
    client = streams._PersistentNativeClient(
        executable=kwargs["executable"], state_dir=tmp_path / "native-runtime", environment={}
    )
    assert client.request(b"{}", deadline_monotonic=time.monotonic() + 1, allow_start=False) is None

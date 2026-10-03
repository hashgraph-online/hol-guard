from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard.native_resident_client import _PersistentNativeClientPool


def test_resident_shutdown_consumes_one_original_deadline_and_retains_unstopped_owners(tmp_path, monkeypatch):
    home = tmp_path / "home"
    keys = [(tmp_path / name, home / "native-runtime") for name in ("first", "second")]
    monkeypatch.setattr(client_module, "_RESIDENTS", {key: {} for key in keys})
    monkeypatch.setattr(client_module, "close_native_resident_clients", lambda _home, **_kwargs: None)
    monkeypatch.setattr(client_module, "_state_files", lambda _path: (tmp_path / "state",))
    clock = [100.0]
    monkeypatch.setattr(client_module.time, "monotonic", lambda: clock[0])
    budgets = []

    def stop(**kwargs):
        assert kwargs["deadline_monotonic"] == 101.0
        budgets.append(kwargs["timeout_seconds"])
        clock[0] = 102.0
        return True

    monkeypatch.setattr(client_module, "stop_native_resident", stop)
    assert client_module.close_native_residents(home, deadline_monotonic=101.0) is False
    assert budgets == [1.0]
    assert keys[0] not in client_module._RESIDENTS
    assert keys[1] in client_module._RESIDENTS


def test_expired_resident_shutdown_does_not_launch_stop_child(tmp_path, monkeypatch):
    home = tmp_path / "home"
    key = (tmp_path / "runtime", home / "native-runtime")
    monkeypatch.setattr(client_module, "_RESIDENTS", {key: {}})
    monkeypatch.setattr(client_module, "close_native_resident_clients", lambda _home, **_kwargs: None)
    monkeypatch.setattr(client_module, "_state_files", lambda _path: (tmp_path / "state",))

    def forbidden_stop(**kwargs):
        raise AssertionError("expired shutdown launched a child")

    monkeypatch.setattr(client_module, "stop_native_resident", forbidden_stop)
    assert client_module.close_native_residents(home, deadline_monotonic=time.monotonic() - 1) is False
    assert key in client_module._RESIDENTS


def test_close_native_resident_clients_attempts_all_selected_pools_before_raising(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    guard_home = tmp_path / "guard-home"
    state_dir = guard_home / "native-runtime"
    first_pool = client_module._client_pool_for(tmp_path / "runtime-a", state_dir, {})
    second_pool = client_module._client_pool_for(tmp_path / "runtime-b", state_dir, {})
    closed: list[_PersistentNativeClientPool] = []

    def close_pool(pool: _PersistentNativeClientPool) -> None:
        closed.append(pool)
        if pool is first_pool:
            raise RuntimeError("first close failed")

    monkeypatch.setattr(_PersistentNativeClientPool, "close", close_pool)

    with pytest.raises(RuntimeError, match="first close failed"):
        client_module.close_native_resident_clients(guard_home)

    assert closed == [first_pool, second_pool]
    assert first_pool in client_module._CLIENT_POOLS.values()
    assert second_pool not in client_module._CLIENT_POOLS.values()


def test_stream_close_does_not_stop_shared_resident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped: list[Path] = []
    monkeypatch.setattr(
        client_module,
        "stop_native_resident",
        lambda *, state_dir, **_kwargs: stopped.append(state_dir) or True,
    )
    monkeypatch.setattr(
        client_module,
        "_state_files",
        lambda _state_dir: (tmp_path / "native-runtime" / "generation.json",),
    )
    pool = _PersistentNativeClientPool(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )
    client = client_module._PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )
    pool._clients.add(client)  # pyright: ignore[reportPrivateUsage]
    pool.close()
    assert stopped == []


def test_close_native_residents_stops_tracked_production_pool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    guard_home = tmp_path / "guard-home"
    state_dir = guard_home / "native-runtime"
    state_dir.mkdir(parents=True)
    executable = tmp_path / "runtime"
    executable.write_text("binary", encoding="utf-8")
    with client_module._RESIDENTS_LOCK:
        original = dict(client_module._RESIDENTS)
        client_module._RESIDENTS.clear()
    stopped: list[Path] = []
    monkeypatch.setattr(client_module, "_state_files", lambda _state_dir: (state_dir / "generation.json",))
    monkeypatch.setattr(
        client_module,
        "stop_native_resident",
        lambda *, state_dir, **_kwargs: stopped.append(state_dir) or True,
    )
    try:
        _ = client_module._client_pool_for(executable, state_dir, {})
        assert client_module.close_native_residents(guard_home)
        assert stopped == [state_dir]
        with client_module._RESIDENTS_LOCK:
            assert (executable, state_dir) not in client_module._RESIDENTS
    finally:
        client_module.close_native_resident_clients()
        with client_module._RESIDENTS_LOCK:
            client_module._RESIDENTS.clear()
            client_module._RESIDENTS.update(original)


def test_close_native_residents_preserves_another_guard_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_a = tmp_path / "guard-a"
    home_b = tmp_path / "guard-b"
    state_a = home_a / "native-runtime"
    state_b = home_b / "native-runtime"
    key_a = (tmp_path / "runtime-a", state_a)
    key_b = (tmp_path / "runtime-b", state_b)
    with client_module._RESIDENTS_LOCK:
        original = dict(client_module._RESIDENTS)
        client_module._RESIDENTS.clear()
        client_module._RESIDENTS.update({key_a: {}, key_b: {}})
    stopped: list[Path] = []
    monkeypatch.setattr(client_module, "_state_files", lambda _state_dir: (tmp_path / "generation.json",))
    monkeypatch.setattr(
        client_module,
        "stop_native_resident",
        lambda *, state_dir, **_kwargs: stopped.append(state_dir) or True,
    )
    try:
        assert client_module.close_native_residents(home_a)
        assert stopped == [state_a]
        with client_module._RESIDENTS_LOCK:
            assert key_a not in client_module._RESIDENTS
            assert key_b in client_module._RESIDENTS
    finally:
        with client_module._RESIDENTS_LOCK:
            client_module._RESIDENTS.clear()
            client_module._RESIDENTS.update(original)

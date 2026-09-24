from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from native_hook_client_support import _push_snapshot, _request, _state_files
from native_managed_test_support import managed_runtime as _managed_runtime_fixture  # noqa: F401
from native_managed_test_support import request

from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients, close_native_residents


def test_production_client_reuses_authenticated_native_generation(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    payload = _request(runtime, guard_home)
    _push_snapshot(runtime, state_dir, payload)
    first = request(runtime, guard_home, payload)
    states = _state_files(state_dir)
    assert len(states) == 1
    original = json.loads(states[0].read_text(encoding="utf-8"))
    assert request(runtime, guard_home, payload) == first
    assert _state_files(state_dir) == states
    current = json.loads(states[0].read_text(encoding="utf-8"))
    assert current["generation"] == original["generation"]
    assert current["process_id"] == original["process_id"]
    if os.name != "nt":
        assert stat.S_IMODE(states[0].stat().st_mode) == 0o600
        assert stat.S_IMODE(states[0].parent.stat().st_mode) == 0o700


def test_production_stream_close_does_not_stop_shared_native_resident(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    payload = _request(runtime, guard_home)
    _push_snapshot(runtime, state_dir, payload)
    request(runtime, guard_home, payload)
    states = _state_files(state_dir)
    assert len(states) == 1
    close_native_resident_clients(guard_home)
    request(runtime, guard_home, payload)
    assert _state_files(state_dir) == states


def test_production_explicit_shutdown_retires_native_generation(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    payload = _request(runtime, guard_home)
    _push_snapshot(runtime, state_dir, payload)
    request(runtime, guard_home, payload)
    assert len(_state_files(state_dir)) == 1
    assert close_native_residents(guard_home)
    assert not _state_files(state_dir)


def test_new_native_generation_rotates_its_authentication_secret(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    state_dir = guard_home / "native-runtime"
    payload = _request(runtime, guard_home)
    _push_snapshot(runtime, state_dir, payload)
    request(runtime, guard_home, payload)
    first = json.loads(_state_files(state_dir)[0].read_text(encoding="utf-8"))
    assert close_native_residents(guard_home)
    assert not _state_files(state_dir)
    _push_snapshot(runtime, state_dir, payload)
    request(runtime, guard_home, payload)
    second = json.loads(_state_files(state_dir)[0].read_text(encoding="utf-8"))
    assert second["token_hex"] != first["token_hex"]
    assert second["generation"] > first["generation"]


def test_native_endpoint_supports_long_guard_home_paths(managed_runtime: tuple[Path, Path]) -> None:
    runtime, guard_home = managed_runtime
    nested_home = guard_home / ("long-private-home-" * 7)
    state_dir = nested_home / "native-runtime"
    state_dir.mkdir(parents=True, mode=0o700)
    try:
        payload = _request(runtime, nested_home)
        _push_snapshot(runtime, state_dir, payload)
        request(runtime, nested_home, payload)
        states = _state_files(state_dir)
        assert len(states) == 1
        state = json.loads(states[0].read_text(encoding="utf-8"))
        if os.name != "nt":
            assert state["transport"] == "unix"
            assert len(os.fsencode(state["endpoint"])) <= 100
    finally:
        assert close_native_residents(nested_home)

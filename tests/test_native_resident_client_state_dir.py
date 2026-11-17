"""Resident client state directories are pinned to one existing spelling."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module


def test_missing_runtime_directory_is_not_pinned_by_resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    state = tmp_path / "home" / "native-runtime"
    resolved: list[Path] = []
    real_resolve = Path.resolve

    def tracking_resolve(self: Path, strict: bool = False) -> Path:
        resolved.append(self)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", tracking_resolve)
    try:
        pool = client_module._client_pool_for(tmp_path / "runtime", state, {})
        assert pool._state_dir == Path(os.path.abspath(state))  # pyright: ignore[reportPrivateUsage]
        assert all(path != state for path in resolved)
    finally:
        client_module.close_native_resident_clients()


def test_existing_runtime_directory_is_pinned_by_resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    state = tmp_path / "home" / "native-runtime"
    state.mkdir(parents=True)
    resolved: list[Path] = []
    real_resolve = Path.resolve

    def tracking_resolve(self: Path, strict: bool = False) -> Path:
        resolved.append(self)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", tracking_resolve)
    try:
        pool = client_module._client_pool_for(tmp_path / "runtime", state, {})
        assert pool._state_dir == real_resolve(state)  # pyright: ignore[reportPrivateUsage]
        assert any(path == state for path in resolved)
    finally:
        client_module.close_native_resident_clients()


def test_stream_launch_uses_existing_absolute_spelling_when_pin_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_resident_stream as stream

    pinned = tmp_path / "pinned" / "native-runtime"
    created = tmp_path / "created" / "native-runtime"
    created.mkdir(parents=True)
    monkeypatch.setattr(stream.os.path, "abspath", lambda _path: str(created))
    assert stream._existing_state_dir(pinned) == created.resolve()


def test_stream_launch_keeps_an_existing_state_dir(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_resident_stream import _existing_state_dir

    state = tmp_path / "native-runtime"
    state.mkdir()
    assert _existing_state_dir(state) == state


def test_directory_probe_fails_closed_when_stat_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.native_resident_stream import _is_directory as stream_is_directory

    def fail_is_dir(self: Path) -> bool:
        raise OSError("stat failed")

    monkeypatch.setattr(Path, "is_dir", fail_is_dir)
    assert client_module._is_directory(tmp_path) is False
    assert stream_is_directory(tmp_path) is False


def test_pinned_state_dir_resolves_an_existing_absolute_spelling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "missing" / "native-runtime"
    created = tmp_path / "created"
    created.mkdir()
    monkeypatch.setattr(client_module.os.path, "abspath", lambda _path: str(created))
    monkeypatch.setattr(
        client_module,
        "_is_directory",
        lambda path: path == created or path == created.resolve(),
    )
    assert client_module._pinned_state_dir(state) == created.resolve()


def test_pinned_state_dir_keeps_absolute_when_resolve_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "missing" / "native-runtime"
    created = tmp_path / "created"
    created.mkdir()
    monkeypatch.setattr(client_module.os.path, "abspath", lambda _path: str(created))
    monkeypatch.setattr(client_module, "_is_directory", lambda path: path == created)

    def fail_resolve(self: Path, strict: bool = False) -> Path:
        raise OSError("resolve failed")

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    assert client_module._pinned_state_dir(state) == created


def test_pinned_state_dir_keeps_absolute_when_resolved_spelling_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "missing" / "native-runtime"
    created = tmp_path / "created"
    created.mkdir()
    missing = tmp_path / "gone"
    monkeypatch.setattr(client_module.os.path, "abspath", lambda _path: str(created))
    monkeypatch.setattr(client_module, "_is_directory", lambda path: path == created)
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: missing)
    assert client_module._pinned_state_dir(state) == created


def test_stream_keeps_absolute_when_resolve_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_resident_stream as stream

    pinned = tmp_path / "pinned" / "native-runtime"
    created = tmp_path / "created"
    created.mkdir()
    monkeypatch.setattr(stream.os.path, "abspath", lambda _path: str(created))

    def fail_resolve(self: Path, strict: bool = False) -> Path:
        raise OSError("resolve failed")

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    assert stream._existing_state_dir(pinned) == created


def test_overlapping_runtime_spelling_replaces_the_stale_pool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    runtime = tmp_path / "runtime"
    first = tmp_path / "first" / "native-runtime"
    second = tmp_path / "second" / "native-runtime"
    monkeypatch.setattr(client_module, "_directory_forms", lambda _path: {"same-runtime"})
    try:
        first_pool = client_module._client_pool_for(runtime, first, {})
        second_pool = client_module._client_pool_for(runtime, second, {})
        assert second_pool is not first_pool
        assert first_pool._closed is True  # pyright: ignore[reportPrivateUsage]
        assert (str(runtime), str(client_module._pinned_state_dir(first))) not in client_module._CLIENT_POOLS
        assert (str(runtime), str(client_module._pinned_state_dir(second))) in client_module._CLIENT_POOLS
    finally:
        client_module.close_native_resident_clients()

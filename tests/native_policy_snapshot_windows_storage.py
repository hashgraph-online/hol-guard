"""Windows native snapshot storage-binding tests."""

from __future__ import annotations

import ctypes
import json
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot as snapshot_module
import codex_plugin_scanner.guard.native_policy_snapshot_storage as storage_module
import codex_plugin_scanner.guard.native_policy_snapshot_windows_key as windows_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME

__test__ = False


def test_windows_snapshot_write_holds_parent_binding_across_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(storage_module.os, "name", "nt")
    monkeypatch.setattr(storage_module, "snapshot_bytes_v3", lambda _snapshot: b"payload")
    binding = types.SimpleNamespace(path=tmp_path, handle=object())
    events: list[tuple[str, object]] = []
    active = False

    @contextmanager
    def private_state_binding(_guard_home: Path):
        nonlocal active
        active = True
        events.append(("bind", binding.handle))
        try:
            yield binding
        finally:
            active = False
            events.append(("unbind", binding.handle))

    def atomic_writer(**kwargs: object) -> None:
        assert active
        events.append(("commit", kwargs["parent_handle"]))
        assert kwargs["parent_path"] == tmp_path
        assert kwargs["destination_name"] == "target-state"
        assert isinstance(kwargs["temporary_name"], str)
        assert kwargs["temporary_name"].startswith(".policy-snapshot-publisher-v3.json.")

    monkeypatch.setattr(snapshot_module, "_windows_private_state_binding", private_state_binding)
    monkeypatch.setattr(snapshot_module, "_windows_write_private_file_atomic", atomic_writer)
    monkeypatch.setattr(
        storage_module,
        "_runtime_state_directory",
        lambda _home: (_ for _ in ()).throw(AssertionError()),
    )
    monkeypatch.setattr(storage_module.os, "replace", lambda *_args: (_ for _ in ()).throw(AssertionError()))

    assert storage_module._write_v3_snapshot_file(tmp_path / "guard", "target-state", {}) == b"payload"
    assert events == [("bind", binding.handle), ("commit", binding.handle), ("unbind", binding.handle)]


def test_windows_snapshot_cache_read_holds_state_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(storage_module.os, "name", "nt")
    binding = types.SimpleNamespace(path=tmp_path / "guard" / "native-runtime", handle=object())
    active = False
    observed: list[tuple[Path, bool]] = []

    @contextmanager
    def private_state_binding(_guard_home: Path):
        nonlocal active
        active = True
        try:
            yield binding
        finally:
            active = False

    def read_file(path: Path, *, verifier_key: bytes | None = None):
        assert verifier_key == b"key"
        observed.append((path, active))
        return ({"generation": 1}, b"payload")

    monkeypatch.setattr(snapshot_module, "_windows_private_state_binding", private_state_binding)
    monkeypatch.setattr(storage_module, "_read_v3_snapshot_file", read_file)
    monkeypatch.setattr(
        storage_module,
        "_snapshot_cache_path_v3",
        lambda _home: (_ for _ in ()).throw(AssertionError("path lookup must stay inside binding")),
    )

    result = storage_module._read_v3_snapshot_cache(tmp_path / "guard", verifier_key=b"key")

    assert result == ({"generation": 1}, b"payload")
    assert observed == [(binding.path / snapshot_module.NATIVE_POLICY_SNAPSHOT_CACHE_NAME, True)]
    assert not active


def test_windows_generation_read_holds_state_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(storage_module.os, "name", "nt")
    binding = types.SimpleNamespace(path=tmp_path / "guard" / "native-runtime", handle=object())
    active = False
    observed: list[tuple[Path, bool]] = []
    value = {
        "generation": 1,
        "policy_digest": "a" * 64,
        "schema": storage_module._V3_GENERATION_SCHEMA,
    }
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    @contextmanager
    def private_state_binding(_guard_home: Path):
        nonlocal active
        active = True
        try:
            yield binding
        finally:
            active = False

    def read_file(path: Path) -> bytes:
        observed.append((path, active))
        return payload

    monkeypatch.setattr(snapshot_module, "_windows_private_state_binding", private_state_binding)
    monkeypatch.setattr(storage_module, "_windows_read_generation_state_bytes", read_file)

    result = storage_module._read_v3_generation_state(tmp_path / "guard")

    assert result == (1, "a" * 64)
    assert observed == [(binding.path.parent / storage_module._V3_GENERATION_STATE_NAME, True)]
    assert not active


def test_windows_pending_cleanup_uses_bound_file_handle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(storage_module.os, "name", "nt")
    binding = types.SimpleNamespace(path=tmp_path / "guard" / "native-runtime", handle=ctypes.c_void_p(79))
    active = False
    observed: list[tuple[object, object, bool]] = []

    @contextmanager
    def private_state_binding(_guard_home: Path):
        nonlocal active
        active = True
        try:
            yield binding
        finally:
            active = False

    def delete_child(**kwargs: object) -> None:
        assert active
        observed.append((kwargs["parent_path"], kwargs["parent_handle"], active))

    monkeypatch.setattr(snapshot_module, "_windows_private_state_binding", private_state_binding)
    monkeypatch.setattr(snapshot_module, "_windows_delete_private_child", delete_child)
    monkeypatch.setattr(
        storage_module,
        "_snapshot_pending_path_v3",
        lambda _home: (_ for _ in ()).throw(AssertionError("pending path must not be unlinked")),
    )

    storage_module._clear_v3_snapshot_pending(tmp_path / "guard")

    assert observed == [(binding.path, binding.handle, True)]
    assert not active


def test_windows_verifier_key_provisioning_holds_state_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    active = False
    calls: list[tuple[Path, bytes]] = []
    binding = types.SimpleNamespace(path=tmp_path / "native-runtime", handle=object())

    @contextmanager
    def private_state_binding(guard_home: Path):
        nonlocal active
        assert guard_home == tmp_path / "guard-home"
        active = True
        try:
            yield binding
        finally:
            active = False

    def provision(path: Path, derived: bytes, **_kwargs: object) -> Path:
        assert active
        calls.append((path, derived))
        return path

    monkeypatch.setattr(windows_key.os, "name", "nt")
    monkeypatch.setattr(windows_key, "_windows_private_state_binding", private_state_binding)
    monkeypatch.setattr(windows_key, "_windows_provision_verifier_key", provision)

    result = windows_key.provision_native_policy_verifier_key(
        tmp_path / "guard-home",
        b"m" * 32,
    )

    assert result == binding.path / NATIVE_POLICY_VERIFIER_KEY_NAME
    assert calls == [(result, snapshot_module.derive_native_policy_verifier_key(b"m" * 32))]
    assert not active

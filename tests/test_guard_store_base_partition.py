"""Public identity and live dependency seams of partitioned Guard stores."""

from __future__ import annotations

import json
import pickle
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import get_args, get_type_hints

import pytest

from codex_plugin_scanner.guard import store_base as base
from codex_plugin_scanner.guard import (
    store_base_chunks,
    store_base_keyring,
    store_base_secret_backends,
    store_base_secret_files,
)

_FACADE = "codex_plugin_scanner.guard.store_base"


def test_secret_store_exports_keep_single_class_and_pickle_identity() -> None:
    owners = {
        "SystemKeyringSecretStore": store_base_keyring,
        "EncryptedFileSecretStore": store_base_secret_files,
        "UnavailableSecretStore": store_base_secret_files,
        "FallbackSecretStore": store_base_secret_backends,
        "MigratingFallbackSecretStore": store_base_secret_backends,
    }
    for name, owner in owners.items():
        definition = getattr(base, name)
        assert definition is getattr(owner, name)
        assert definition.__module__ == _FACADE
        assert definition.__name__ == definition.__qualname__ == name
        assert pickle.loads(pickle.dumps(definition)) is definition
    assert base.MigratingFallbackSecretStore.__bases__ == (base.FallbackSecretStore,)
    assert isinstance(vars(base.SystemKeyringSecretStore)["_load_keyring_module"], staticmethod)
    assert isinstance(vars(base.SystemKeyringSecretStore)["_supports_native_macos_security_reads"], classmethod)
    assert "_base" not in base.__all__
    assert "_preserve_module" not in base.__all__


def test_chunks_keep_the_late_type_variable_and_annotation_spelling() -> None:
    assert base._chunks is store_base_chunks._chunks
    assert base._chunks.__module__ == _FACADE
    assert base._chunks.__name__ == base._chunks.__qualname__ == "_chunks"
    assert pickle.loads(pickle.dumps(base._chunks)) is base._chunks
    assert base._chunks.__annotations__ == {
        "values": "Sequence[_ChunkT]",
        "size": "int",
        "return": "Iterator[list[_ChunkT]]",
    }
    hints = get_type_hints(base._chunks)
    assert get_args(hints["values"])[0] is base._ChunkT
    assert get_args(get_args(hints["return"])[0])[0] is base._ChunkT
    assert list(base._chunks([1, 2, 3], 2)) == [[1, 2], [3]]


def test_nested_keyring_classes_keep_path_closures_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "store-base-partition-fixture")
    first_path, second_path = tmp_path / "first.json", tmp_path / "second.json"
    monkeypatch.setenv("HOL_GUARD_TEST_KEYRING_FILE", str(first_path))
    first = base.SystemKeyringSecretStore._test_keyring_module()
    monkeypatch.setenv("HOL_GUARD_TEST_KEYRING_FILE", str(second_path))
    second = base.SystemKeyringSecretStore._test_keyring_module()
    assert first is not None and second is not None and first is not second
    first.set_password("fixture-service", "fixture-id", "fixture-first")
    second.set_password("fixture-service", "fixture-id", "fixture-second")
    assert first._store_path() == first_path
    assert second._store_path() == second_path
    assert first.get_password("fixture-service", "fixture-id") == "fixture-first"
    assert second.get_password("fixture-service", "fixture-id") == "fixture-second"
    prefix = "SystemKeyringSecretStore._test_keyring_module.<locals>._TestKeyringModule"
    for owner in (first, second):
        assert owner.__module__ == _FACADE
        assert owner.__qualname__ == prefix
        assert vars(owner)["_store_path"].__func__.__module__ == _FACADE
        assert vars(owner)["_store_path"].__func__.__qualname__ == prefix + "._store_path"
        assert get_type_hints(owner._store_path) == {"return": Path}
        backend = type(owner.get_keyring())
        assert backend.__module__ == _FACADE
        assert backend.__qualname__ == prefix + ".get_keyring.<locals>._Backend"
        with pytest.raises((AttributeError, pickle.PicklingError)):
            pickle.dumps(owner)
    first.delete_password("fixture-service", "fixture-id")
    assert first.get_password("fixture-service", "fixture-id") is None
    assert second.get_password("fixture-service", "fixture-id") == "fixture-second"


def test_native_reader_cache_tracks_both_original_loader_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    owner = base.SystemKeyringSecretStore
    calls = []

    def keyring_a():
        calls.append("keyring-a")
        return object()

    def keyring_b():
        calls.append("keyring-b")
        return object()

    def api_a():
        calls.append("api-a")
        return object()

    def api_b():
        calls.append("api-b")
        raise ImportError("fixture unavailable API")

    monkeypatch.setattr(base, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(owner, "_native_macos_security_reads_cache", None)
    monkeypatch.setattr(owner, "_load_keyring_module", staticmethod(keyring_a))
    monkeypatch.setattr(owner, "_load_macos_keyring_api_module", staticmethod(api_a))
    assert owner._supports_native_macos_security_reads() is True
    assert owner._native_macos_security_reads_cache == ((id(keyring_a), id(api_a)), True)
    assert owner._supports_native_macos_security_reads() is True
    assert calls == ["keyring-a", "api-a"]
    monkeypatch.setattr(owner, "_load_keyring_module", staticmethod(keyring_b))
    assert owner._supports_native_macos_security_reads() is True
    assert owner._native_macos_security_reads_cache == ((id(keyring_b), id(api_a)), True)
    monkeypatch.setattr(owner, "_load_macos_keyring_api_module", staticmethod(api_b))
    assert owner._supports_native_macos_security_reads() is False
    assert owner._native_macos_security_reads_cache == ((id(keyring_b), id(api_b)), False)
    assert owner._supports_native_macos_security_reads() is False
    assert calls == ["keyring-a", "api-a", "keyring-b", "api-a", "keyring-b", "api-b"]

    class ChildStore(owner):
        _native_macos_security_reads_cache = None

    original_cache = owner._native_macos_security_reads_cache
    assert ChildStore._supports_native_macos_security_reads() is False
    assert "_native_macos_security_reads_cache" in vars(ChildStore)
    assert owner._native_macos_security_reads_cache is original_cache


def test_no_ui_migration_observes_current_facade_primary_class(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    class TimedPrimary:
        def get_secret_with_timeout(self, secret_id, *, timeout_seconds):
            calls.append((secret_id, timeout_seconds))
            return "fixture-migrated"

        def get_secret(self, secret_id):
            raise AssertionError("Interactive lookup must not run")

    writes = []
    fallback = SimpleNamespace(get_secret=lambda _secret_id: None, set_secret=lambda *args: writes.append(args))
    monkeypatch.setattr(base, "SystemKeyringSecretStore", TimedPrimary)
    store = base.MigratingFallbackSecretStore(primary=TimedPrimary(), fallback=fallback)
    assert store.get_secret_no_ui("fixture-id") == "fixture-migrated"
    assert calls == [("fixture-id", 0.5)]
    assert writes == [("fixture-id", "fixture-migrated")]


def test_isolated_worker_keeps_facade_import_and_live_process_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'{"value":"fixture-value"}')

    original_devnull = base.subprocess.DEVNULL
    monkeypatch.setattr(base, "subprocess", SimpleNamespace(run=run, DEVNULL=original_devnull))
    store = base.SystemKeyringSecretStore("fixture-service")
    assert store._get_macos_secret_in_isolated_process("fixture-id", timeout_seconds=0.25) == "fixture-value"
    arguments, kwargs = calls[0]
    assert arguments[1:3] == ["-I", "-c"]
    assert "from codex_plugin_scanner.guard.store_base import SystemKeyringSecretStore;" in arguments[3]
    assert "_get_secret_without_macos_ui" in arguments[3]
    assert arguments[-2:] == ["fixture-service", "fixture-id"]
    assert kwargs["timeout"] == 0.25
    assert kwargs["stdin"] == original_devnull


def test_encrypted_initialization_keeps_shared_lock_owner_and_finally_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    locks = {}
    events = []
    failure = RuntimeError("fixture key-load failure")

    def acquire(handle):
        events.append(("acquire", handle))
        assert not handle.closed

    def release(handle):
        events.append(("release", handle))
        assert not handle.closed

    def fail():
        raise failure

    monkeypatch.setattr(base, "_ENCRYPTED_SECRET_INIT_LOCKS", locks)
    monkeypatch.setattr(base, "_ENCRYPTED_SECRET_INIT_LOCKS_GUARD", threading.Lock())
    monkeypatch.setattr(base, "_acquire_advisory_file_lock", acquire)
    monkeypatch.setattr(base, "_release_advisory_file_lock", release)
    first = base.EncryptedFileSecretStore(tmp_path / "shared")
    second = base.EncryptedFileSecretStore(tmp_path / "shared")
    other = base.EncryptedFileSecretStore(tmp_path / "other")
    shared_lock = None
    for store in (first, second, other):
        store.base_dir.mkdir(parents=True, exist_ok=True)
        store.key_path.write_bytes(b"fixture-key")
        monkeypatch.setattr(store, "_load_fernet_key", fail)
        with pytest.raises(RuntimeError) as raised:
            store._ensure_ready()
        assert raised.value is failure
        key = base.os.path.realpath(base.os.fspath(store.key_path))
        assert not locks[key].locked()
        if store is first:
            shared_lock = locks[key]
        elif store is second:
            assert locks[key] is shared_lock
        else:
            assert locks[key] is not shared_lock
    assert len(locks) == 2
    assert [kind for kind, _handle in events] == ["acquire", "release"] * 3
    for index in range(0, len(events), 2):
        assert events[index][1] is events[index + 1][1]
        assert events[index][1].closed


_OWNER_EXPORTS = {
    "store_base_chunks": ("_chunks",),
    "store_base_keyring": ("SystemKeyringSecretStore",),
    "store_base_policy_matching": (
        "_path_within_workspace",
        "_normalized_workspace_path",
        "_workspace_policy_key",
        "_stored_workspace_policy_key",
        "_validate_scoped_policy_artifact_target",
        "_runtime_scoped_exact_match_key",
        "_global_runtime_scoped_exact_match_key",
        "runtime_tool_action_policy_artifact_id",
        "runtime_tool_action_exact_match_context",
        "runtime_tool_action_portable_match_context",
        "browser_mcp_exact_match_context",
        "_is_runtime_scoped_exact_match_key",
        "_is_approval_context_token",
        "_scoped_runtime_row_requires_exact_match",
        "_warn_only_policy_integrity_status",
        "_policy_integrity_ready_for_local_write",
        "_policy_integrity_setup_safe_for_local_write",
        "_family_key_value",
    ),
    "store_base_secret_backends": (
        "FallbackSecretStore",
        "MigratingFallbackSecretStore",
        "_system_keyring_availability_cache_path",
        "_read_system_keyring_availability_cache",
        "_write_system_keyring_availability_cache",
        "_system_keyring_is_available",
        "_build_oauth_secret_store",
        "_build_policy_integrity_secret_store",
        "_secret_store_backend_name",
        "_secret_store_fallback_backend_name",
    ),
    "store_base_secret_files": (
        "_acquire_advisory_file_lock",
        "_release_advisory_file_lock",
        "EncryptedFileSecretStore",
        "UnavailableSecretStore",
        "_expand_keystream",
        "_set_private_mode",
    ),
    "store_base_values": (
        "_is_approval_gate_one_shot_policy",
        "_normalize_source_name",
        "_oauth_sync_url_from_issuer",
        "_allowed_origin_from_sync_url",
        "_secret_fingerprint",
        "_legacy_secret_fingerprint",
        "_legacy_secret_sha256",
        "_secret_matches_hash",
        "_should_warn_on_slow_store_transactions",
        "receipt_index_statements",
        "_row_mapping",
        "_string_value",
        "_int_value",
        "_mapping_int",
        "_parse_utc_timestamp",
        "_canonical_utc_timestamp",
        "_timestamp_has_expired",
        "_now",
        "_lease_expiry",
        "_string_list",
        "_transport_value",
    ),
}


@pytest.mark.parametrize("owner", tuple(_OWNER_EXPORTS))
def test_each_store_owner_can_be_imported_before_the_facade(owner: str) -> None:
    source_root = Path(base.__file__).resolve().parents[2]
    script = """
import importlib
import json
import sys
import typing
from pathlib import Path

source_root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source_root))
facade_name = "codex_plugin_scanner.guard.store_base"
owner_name = "codex_plugin_scanner.guard." + sys.argv[2]
importlib.import_module("codex_plugin_scanner.guard")
assert facade_name not in sys.modules
assert owner_name not in sys.modules
owner = importlib.import_module(owner_name)
facade = importlib.import_module(facade_name)
assert Path(owner.__file__).resolve().is_relative_to(source_root)
assert Path(facade.__file__).resolve().is_relative_to(source_root)
for name in json.loads(sys.argv[3]):
    value = getattr(owner, name)
    assert getattr(facade, name) is value
    assert value.__module__ == facade_name
    typing.get_type_hints(value)
assert facade.MigratingFallbackSecretStore.__bases__ == (facade.FallbackSecretStore,)
assert facade._chunks.__globals__["_ChunkT"] is facade._ChunkT
assert typing.get_args(typing.get_type_hints(facade._chunks)["values"]) == (facade._ChunkT,)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(source_root), owner, json.dumps(_OWNER_EXPORTS[owner])],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr

"""Exact failure-time phase identities without observing private frame values."""

from __future__ import annotations

import sys
from collections.abc import Callable
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import FunctionType
from typing import NoReturn

import pytest

from codex_plugin_scanner.guard import native_cloud_policy_inputs as cloud
from codex_plugin_scanner.guard import native_policy_authority_managed as managed
from codex_plugin_scanner.guard import native_policy_authority_read as authority
from codex_plugin_scanner.guard import native_policy_snapshot_publisher_context as context
from codex_plugin_scanner.guard import store_maintenance
from codex_plugin_scanner.guard import store_secret_policy_integrity as integrity
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_connection_schema import StoreConnectionSchemaMixin
from scripts import native_publication_worker_diagnostic as diagnostic


class _Observed(BaseException):
    """Stop at the selected existing dependency before any authority decision."""


def _invocation(
    phase: str,
    store: GuardStore,
    publisher: NativePolicySnapshotPublisher,
    stop: Callable[..., NoReturn],
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[], object]:
    if phase == "v3_source_capture":
        monkeypatch.setattr(context, "refresh_source_requirement", stop)
        return lambda: context.compiled_v3_compatible_policy(publisher)
    if phase == "authority_capture":
        monkeypatch.setattr(authority, "read_frozen_native_managed_authority", stop)
        return lambda: authority.read_native_policy_authority_inputs(store, now=0.0)
    if phase == "authority_sql_capture":
        monkeypatch.setattr(store, "_connect", nullcontext)
        monkeypatch.setattr(store, "_policy_integrity_secret_material", stop)
        return lambda: authority._capture_native_policy_authority_inputs(store, now=0.0, managed=None)
    if phase == "managed_authority_capture":
        monkeypatch.setattr(store, "_authority_key", stop)
        return lambda: managed.read_frozen_native_managed_authority(store)
    if phase == "unenrolled_authority_check":
        monkeypatch.setattr(store, "_authority_key", stop)
        return lambda: managed.require_unenrolled_secrets(store)
    if phase == "cloud_input_validation":
        monkeypatch.setattr(store, "_connect", stop)
        return lambda: cloud.read_native_cloud_policy_inputs(store, now=0.0)
    if phase == "integrity_material":
        store._cached_policy_integrity_secret_material = None
        monkeypatch.setattr(store, "_policy_integrity_cache_marker", stop)
        return lambda: store._policy_integrity_secret_material(create=False)
    if phase == "integrity_control":
        store._cached_policy_integrity_control_state = None
        monkeypatch.setattr(store, "_policy_integrity_cache_marker", stop)
        return lambda: store._load_policy_integrity_control_state(create=False)
    if phase == "integrity_marker":
        monkeypatch.setattr(store, "_connect", stop)
        return store._policy_integrity_cache_marker
    if phase == "store_connection":
        monkeypatch.setattr(store_maintenance, "maintenance_lookup", stop)
        return lambda: store._connect_once().__enter__()
    if phase == "store_permissions":
        monkeypatch.setattr(integrity, "_set_private_mode_compat", stop)
        return store._repair_store_permissions
    raise AssertionError("Unknown finite phase")


@pytest.mark.parametrize(
    "phase",
    [
        "v3_source_capture",
        "authority_capture",
        "authority_sql_capture",
        "managed_authority_capture",
        "unenrolled_authority_check",
        "cloud_input_validation",
        "integrity_material",
        "integrity_control",
        "integrity_marker",
        "store_connection",
        "store_permissions",
    ],
)
def test_actual_source_frames_select_finite_phase_without_rendering_private_values(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    # Nominal receivers allow entry to the real source function without
    # constructing a daemon, opening a database, or changing native authority.
    store = object.__new__(GuardStore)
    store.guard_home = Path("synthetic-private-path-canary")
    store.path = store.guard_home / "guard.db"
    publisher = object.__new__(NativePolicySnapshotPublisher)
    publisher.store = store
    sentinel = _Observed()
    observations: list[tuple[str, str]] = []
    calls = []

    def stop(*args: object, **kwargs: object) -> NoReturn:
        private_canary = {"synthetic-private-key-canary": "synthetic-private-value-canary"}
        calls.append((args, kwargs))
        observations.append(diagnostic._stack_phase(sys._getframe()))
        assert private_canary
        raise sentinel

    invoke = _invocation(phase, store, publisher, stop, monkeypatch)
    with pytest.raises(_Observed) as caught:
        _ = invoke()
    assert caught.value is sentinel and len(calls) == 1
    assert observations == [(phase, "matched")]
    assert "private" not in repr(observations) and "canary" not in repr(observations)


def test_deeper_actual_authority_frame_takes_precedence_over_its_public_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = object.__new__(GuardStore)
    observations: list[tuple[str, str]] = []
    sentinel = _Observed()

    def stop(*args: object, **kwargs: object) -> NoReturn:
        observations.append(diagnostic._stack_phase(sys._getframe()))
        raise sentinel

    monkeypatch.setattr(authority, "read_frozen_native_managed_authority", lambda *args, **kwargs: None)
    monkeypatch.setattr(store, "_connect", nullcontext)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", stop)
    with pytest.raises(_Observed) as caught:
        _ = authority.read_native_policy_authority_inputs(store, now=0.0)
    assert caught.value is sentinel
    assert observations == [("authority_sql_capture", "matched")]


def test_contextmanager_uses_only_its_own_body_code_and_rejects_hostile_wrapped_values() -> None:
    @contextmanager
    def unrelated():
        yield

    selected = diagnostic._wrapped_source_code(StoreConnectionSchemaMixin._connect_once)
    assert selected is not None
    assert selected is not StoreConnectionSchemaMixin._connect_once.__code__
    assert selected is not diagnostic._wrapped_source_code(unrelated)
    assert (selected, "store_connection") in diagnostic._PHASE_CODES

    class Hostile:
        def __getattribute__(self, name: str) -> object:
            pytest.fail("Diagnostic inspected an untrusted object")

    assert diagnostic._wrapped_source_code(Hostile()) is None

    def plain() -> None:
        pass

    assert diagnostic._wrapped_source_code(plain) is None
    vars(plain)["__wrapped__"] = Hostile()
    assert diagnostic._wrapped_source_code(plain) is None


def test_new_source_phase_rejects_spoofed_function_names_and_paths() -> None:
    def sample() -> tuple[str, str]:
        return diagnostic._stack_phase(sys._getframe())

    trusted = authority._capture_native_policy_authority_inputs.__code__
    spoofed = FunctionType(sample.__code__.replace(co_name=trusted.co_name, co_filename=trusted.co_filename), globals())
    phase, _scan = spoofed()
    assert phase == "unknown"

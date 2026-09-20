from __future__ import annotations

import json
import os
import threading
import time

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch
from codex_plugin_scanner.guard import native_policy_control_runtime as control
from codex_plugin_scanner.guard import native_policy_control_transport as transport
from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult


def _payload(**overrides):
    return {
        "protocol_version": 1,
        "runtime_version": "3.0.1",
        "rule_digest": "abc",
        "build_sha": "test",
        "target": "test",
        "features": ["policy-snapshot-control-v1"],
        **overrides,
    }


def _fixture(tmp_path, monkeypatch, **overrides):
    binary = tmp_path / "runtime"
    payload = json.dumps(_payload(**overrides), separators=(",", ":"))
    binary.write_text("#!/bin/sh\nprintf '%s\\n' '" + payload + "'\n")
    binary.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(runtime, "_runtime_candidates", lambda: (binary,))
    monkeypatch.setattr(runtime, "_is_bundled_candidate", lambda path: False)
    monkeypatch.setattr(runtime, "_python_package_version", lambda: "3.0.1")
    return binary, payload


def _select(seconds: float = 1):
    return control.native_policy_control_runtime_status(deadline_monotonic=time.monotonic() + seconds)


@pytest.mark.skipif(os.name == "nt", reason="actual capability fixture uses a POSIX shell")
@pytest.mark.parametrize("overrides", [{}, {"protocol_version": 2}, {"runtime_version": "0.0"}])
def test_actual_deadline_selection_retains_ordinary_contract(tmp_path, monkeypatch, overrides):
    _fixture(tmp_path, monkeypatch, **overrides)
    assert _select() == runtime.native_runtime_status()


@pytest.mark.skipif(os.name == "nt", reason="actual capability fixture uses a POSIX shell")
def test_actual_selection_uses_one_worker_slot_without_nested_admission(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(transport, "_CONTROL_SLOTS", slots)
    status = _select()
    assert status is not None and status.compatible
    assert slots.acquire(blocking=False)
    slots.release()


def test_capability_probe_retains_original_cap_and_absolute_remaining(tmp_path, monkeypatch):
    _, payload = _fixture(tmp_path, monkeypatch)
    observed = []

    def run(*args, **kwargs):
        observed.append((time.monotonic(), kwargs))
        return BoundedHookProcessResult(0, payload, False, False)

    monkeypatch.setattr(control, "run_isolated_hook_process", run)
    for budget in (0.2, 2.0):
        deadline = time.monotonic() + budget
        status = control.native_policy_control_runtime_status(deadline_monotonic=deadline)
        assert status is not None and status.compatible
        called, kwargs = observed[-1]
        assert kwargs["deadline_monotonic"] <= deadline
        assert kwargs["deadline_monotonic"] - called <= 1.0
        assert kwargs["bound_input_to_deadline"] is True
        assert kwargs["output_limit"] == runtime._MAX_RESPONSE_BYTES
        assert "timeout_seconds" not in kwargs


def test_deadline_specific_probe_never_reads_or_poisons_shared_capability_cache(tmp_path, monkeypatch):
    binary, payload = _fixture(tmp_path, monkeypatch)
    before = runtime._capabilities_for_identity.cache_info()
    monkeypatch.setattr(
        control, "run_isolated_hook_process", lambda *a, **k: BoundedHookProcessResult(0, payload, False, False)
    )
    assert _select() is not None
    assert runtime._capabilities_for_identity.cache_info() == before
    binary.write_bytes(binary.read_bytes() + b"# changed\n")
    new_status = _select()
    assert new_status is not None and new_status.identity is not None
    fresh_identity = runtime._validate_binary(binary)
    assert fresh_identity is not None
    assert new_status.identity.sha256 == fresh_identity.sha256
    assert runtime._capabilities_for_identity.cache_info() == before


def test_expired_input_never_enters_candidate_selection(monkeypatch):
    monkeypatch.setattr(runtime, "_runtime_candidates", lambda: pytest.fail("selected after deadline"))
    assert control.native_policy_control_runtime_status(deadline_monotonic=time.monotonic() - 1) is None


def test_hash_setup_overrun_cannot_start_capabilities_or_accept_late_identity(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)
    original = runtime._validate_binary
    finished = threading.Event()

    def validate(path, **kwargs):
        try:
            time.sleep(0.12)
            return original(path, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(runtime, "_validate_binary", validate)
    monkeypatch.setattr(control, "run_isolated_hook_process", lambda *a, **k: pytest.fail("late capability launch"))
    begin = time.monotonic()
    assert _select(0.03) is None
    assert time.monotonic() - begin < 0.10
    assert finished.wait(1)


@pytest.mark.skipif(os.name == "nt", reason="actual capability fixture uses a POSIX shell")
def test_actual_cold_capability_spawn_is_owned_past_caller_deadline(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)
    original = launch._spawn_hook_process
    completed = threading.Event()
    processes = []
    original_run = control.run_isolated_hook_process

    def spawn(*args, **kwargs):
        time.sleep(0.12)
        result = original(*args, **kwargs)
        processes.append(result[0])
        return result

    def run(*args, **kwargs):
        try:
            return original_run(*args, **kwargs)
        finally:
            completed.set()

    monkeypatch.setattr(launch, "_spawn_hook_process", spawn)
    monkeypatch.setattr(control, "run_isolated_hook_process", run)
    started = time.monotonic()
    assert _select(0.03) is None
    assert time.monotonic() - started < 0.10
    assert completed.wait(2)
    assert len(processes) == 1
    assert processes[0].poll() is not None


def test_setup_owner_keeps_its_slot_until_actual_completion(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(transport, "_CONTROL_SLOTS", slots)
    original = runtime._validate_binary

    def validate(path, **kwargs):
        started.set()
        try:
            assert release.wait(1)
            return original(path, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(runtime, "_validate_binary", validate)
    try:
        assert _select(0.03) is None
        assert started.is_set()
        assert not slots.acquire(blocking=False)
        assert _select(0.03) is None
    finally:
        release.set()
    assert finished.wait(1)
    # Completion releases the slot after the function unwinds.
    assert slots.acquire(timeout=1)
    slots.release()


def test_bundled_manifest_checks_are_shared_and_precede_capability_probe(tmp_path, monkeypatch):
    binary, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(runtime, "_is_bundled_candidate", lambda path: True)
    monkeypatch.setattr(runtime, "_manifest_for_bundled_identity", lambda identity: (None, "native_manifest_invalid"))
    monkeypatch.setattr(control, "run_isolated_hook_process", lambda *a, **k: pytest.fail("manifest bypass"))
    status = _select()
    assert status is not None and status.reason == "native_manifest_invalid"
    assert status.identity is not None and status.identity.path == binary.resolve()


def test_hash_chunk_continuation_checks_are_not_annotation_or_cached_identity(tmp_path):
    binary = tmp_path / "large-runtime"
    binary.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    binary.chmod(0o700)
    checks = []
    identity = runtime._validate_binary(binary, check_continuation=lambda: checks.append(True))
    assert identity is not None
    assert len(checks) == 4


@pytest.mark.parametrize("payload", ["[]", "[" * 2000, "not json"])
def test_malformed_capability_output_is_finite_unavailability(tmp_path, monkeypatch, payload):
    _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        control, "run_isolated_hook_process", lambda *a, **k: BoundedHookProcessResult(0, payload, False, False)
    )
    status = _select()
    assert status is not None and status.reason == "native_unavailable"


@pytest.mark.skipif(os.name == "nt", reason="actual capability fixture uses a POSIX shell")
def test_original_status_keeps_ordinary_capability_startup_semantics(tmp_path, monkeypatch):
    _fixture(tmp_path, monkeypatch)
    original = launch._spawn_hook_process

    def spawn(*args, **kwargs):
        time.sleep(0.10)
        return original(*args, **kwargs)

    monkeypatch.setattr(launch, "_spawn_hook_process", spawn)
    start = time.monotonic()
    status = runtime.native_runtime_status()
    assert status.compatible
    assert time.monotonic() - start >= 0.10

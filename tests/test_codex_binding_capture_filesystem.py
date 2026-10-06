"""Bounded, opt-in Codex ingress to native-edge receipt diagnostics."""

from __future__ import annotations

import errno
import json
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_binding_capture as capture
from codex_plugin_scanner.guard import codex_binding_capture_fs as capture_fs
from codex_plugin_scanner.guard.codex_binding_capture import (
    CAPTURE_MARKER_NAME,
    CAPTURE_OUTPUT_PREFIX,
    CAPTURE_OUTPUT_SUFFIX,
    MAX_CAPTURE_BYTES,
    initialize_capture_marker,
    join_binding_records,
    record_bridge_ingress,
)
from codex_plugin_scanner.guard.codex_binding_capture_bounds import canonical_json_bytes
from codex_plugin_scanner.guard.codex_binding_capture_join import valid_existing_records
from tests.codex_binding_capture_support import (
    _capture_pair,
    _enable_capture,
    _output_path,
    _rows,
    _session,
)


@pytest.mark.parametrize("failure", [BlockingIOError("synthetic lock contention"), OSError(errno.EINTR, "interrupted")])
def test_capture_retries_brief_lock_contention(tmp_path: Path, monkeypatch, failure: OSError) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    assert capture.fcntl is not None
    real_flock = capture.fcntl.flock
    attempts = []

    def briefly_busy(fd: int, operation: int) -> None:
        if operation & capture.fcntl.LOCK_NB:
            attempts.append(fd)
            if len(attempts) == 1:
                raise failure
        real_flock(fd, operation)

    monkeypatch.setattr(capture.fcntl, "flock", briefly_busy)
    assert record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"contended-call"}',
        event_name="PreToolUse",
    )
    assert len(attempts) == 2
    assert len(_rows(directory)) == 1


@pytest.mark.parametrize(
    "failure", [BlockingIOError("synthetic persistent contention"), OSError(errno.EINTR, "interrupted")]
)
def test_capture_abandons_persistent_contention(tmp_path: Path, monkeypatch, failure: OSError) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    assert capture.fcntl is not None
    attempts = []
    times = iter([0.0, 0.0, 0.021])

    def always_busy(fd: int, operation: int) -> None:
        attempts.append(fd)
        raise failure

    monkeypatch.setattr(capture.fcntl, "flock", always_busy)
    monkeypatch.setattr(capture.time, "monotonic", lambda: next(times, 0.021))
    monkeypatch.setattr(capture.time, "sleep", lambda _: None)
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"contended-call"}',
        event_name="PreToolUse",
    )
    assert len(attempts) == 2
    assert _output_path(directory).read_bytes() == b""


def test_no_marker_is_inert_and_does_not_create_capture_directory(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"

    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-1"}',
        event_name="PreToolUse",
    )
    assert not (guard_home / "diagnostics").exists()


@pytest.mark.parametrize("written", [0, -1])
def test_capture_output_nonpositive_write_stops_without_retry(tmp_path: Path, monkeypatch, written: int) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    calls = []

    def stalled_write(fd: int, payload: bytes) -> int:
        calls.append((fd, len(payload)))
        if len(calls) > 1:
            raise AssertionError("zero-progress capture must not retry")
        return written

    monkeypatch.setattr(os, "write", stalled_write)
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"stalled-call"}',
        event_name="PreToolUse",
    )
    assert len(calls) == 1
    assert _output_path(directory).read_bytes() == b""


@pytest.mark.parametrize("failure", [OSError(errno.EIO, "failed write"), None])
def test_partial_capture_write_restores_existing_rows(tmp_path: Path, monkeypatch, failure: OSError | None) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    kwargs = {
        "guard_home": guard_home,
        "raw_payload": '{"hook_event_name":"PreToolUse","tool_use_id":"partial-write"}',
        "event_name": "PreToolUse",
    }
    assert record_bridge_ingress(**kwargs)
    before = _output_path(directory).read_bytes()
    real_write = os.write
    calls = []

    def partial_write(fd: int, data: bytes) -> int:
        calls.append(fd)
        if len(calls) == 1:
            return real_write(fd, data[:20])
        if failure is not None:
            raise failure
        return 0

    monkeypatch.setattr(os, "write", partial_write)
    assert not record_bridge_ingress(**kwargs)
    assert len(calls) == 2
    assert _output_path(directory).read_bytes() == before
    monkeypatch.setattr(os, "write", real_write)
    assert record_bridge_ingress(**kwargs)
    assert len(_rows(directory)) == 2


@pytest.mark.parametrize("persistent", [False, True])
def test_interrupted_capture_write_uses_original_retry_deadline(tmp_path: Path, monkeypatch, persistent: bool) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    real_write = os.write
    clock = [0.0]
    calls = []

    def interrupted_write(fd: int, data: bytes) -> int:
        calls.append(fd)
        if persistent or len(calls) == 1:
            clock[0] += 0.01
            raise OSError(errno.EINTR, "interrupted")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", interrupted_write)
    monkeypatch.setattr(capture.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(capture.time, "sleep", lambda _: None)
    assert (
        record_bridge_ingress(
            guard_home=guard_home,
            raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"interrupted-write"}',
            event_name="PreToolUse",
        )
        is not persistent
    )
    assert len(calls) == 2
    if persistent:
        assert _output_path(directory).read_bytes() == b""
    else:
        assert len(_rows(directory)) == 1


def test_aggregate_capture_limits_include_newlines_and_session_cap(tmp_path: Path) -> None:
    many_rows = [{"padding": "x" * 1_000} for _ in range(70)]
    result = join_binding_records(many_rows)
    assert result["status"] == "invalid"
    assert result["joins"] == []
    assert result["issues"] == [{"status": "invalid", "reason": "record_size"}]

    guard_home, rows = _capture_pair(tmp_path / "tight")
    tight_session = replace(_session(guard_home), max_bytes=1)
    tight_result = join_binding_records(rows, capture_session=tight_session)
    assert tight_result["status"] == "invalid"
    assert tight_result["joins"] == []
    assert tight_result["issues"] == [{"status": "invalid", "reason": "record_size"}]

    oversized_raw = b"{}\n" * (MAX_CAPTURE_BYTES // 3 + 1)
    assert valid_existing_records(oversized_raw, run_id="run-1", capture_session=_session(guard_home)) is None


def test_session_record_limit_prevents_pair_binding_and_existing_rows(tmp_path: Path) -> None:
    guard_home, rows = _capture_pair(tmp_path)
    session = replace(_session(guard_home), max_records=1)

    result = join_binding_records(rows, capture_session=session)
    assert result["status"] == "ambiguous"
    assert result["joins"] == []
    assert result["issues"] == [{"status": "ambiguous", "reason": "record_limit_exceeded"}]

    raw = _output_path(guard_home / "diagnostics").read_bytes()
    assert valid_existing_records(raw, run_id="run-1", capture_session=session) is None


def test_ingress_rejects_oversized_utf8_before_json_parse_and_deep_json(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    oversized = (
        '{"hook_event_name":"PreToolUse","tool_use_id":"call-preparse","tool_input":{"command":"'
        + ("x" * MAX_CAPTURE_BYTES)
        + '"}}'
    )
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=oversized, event_name="PreToolUse")
    unicode_oversized = (
        '{"hook_event_name":"PreToolUse","tool_use_id":"call-utf8","tool_input":{"command":"'
        + ("é" * (MAX_CAPTURE_BYTES // 2))
        + '"}}'
    )
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=unicode_oversized, event_name="PreToolUse")
    assert not (directory / f"{CAPTURE_OUTPUT_PREFIX}run-1{CAPTURE_OUTPUT_SUFFIX}").exists()

    deep: dict[str, object] = {"hook_event_name": "PreToolUse", "tool_use_id": "call-deep"}
    cursor = deep
    for _ in range(70):
        nested: dict[str, object] = {}
        cursor["nested"] = nested
        cursor = nested
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=json.dumps(deep), event_name="PreToolUse")


def test_canonical_json_rejects_deep_and_cyclic_values_without_serializing_unbounded() -> None:
    deep: list[object] = []
    cursor = deep
    for _ in range(70):
        nested: list[object] = []
        cursor.append(nested)
        cursor = nested
    assert canonical_json_bytes(deep) is None

    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    assert canonical_json_bytes(cyclic) is None


def test_event_alias_is_canonicalized_and_prompt_rows_are_not_applicable(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"pre_tool_use","tool_use_id":"call-alias-event"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="pre_tool_use")
    assert _rows(directory)[0]["event_name"] == "PreToolUse"

    prompt_home = tmp_path / "prompt"
    prompt_directory = _enable_capture(prompt_home)
    assert record_bridge_ingress(
        guard_home=prompt_home,
        raw_payload='{"hook_event_name":"UserPromptSubmit","tool_use_id":"prompt-1"}',
        event_name="UserPromptSubmit",
    )
    assert (
        join_binding_records(_rows(prompt_directory), capture_session=_session(prompt_home))["status"]
        == "not_applicable"
    )


def test_expired_or_unsafe_marker_is_inert(tmp_path: Path) -> None:
    expired_home = tmp_path / "expired"
    expired_directory = _enable_capture(expired_home, expires_at=int(time.time()) - 1)
    assert not record_bridge_ingress(
        guard_home=expired_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-expired"}',
        event_name="PreToolUse",
    )
    assert not _output_path(expired_directory).exists()

    unsafe_home = tmp_path / "unsafe"
    unsafe_directory = _enable_capture(unsafe_home)
    (unsafe_directory / CAPTURE_MARKER_NAME).chmod(0o644)
    assert not record_bridge_ingress(
        guard_home=unsafe_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-unsafe"}',
        event_name="PreToolUse",
    )
    assert not _output_path(unsafe_directory).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_marker_initializer_rejects_symlinked_directories_and_overwrite(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_home = real_parent / "real-guard-home"
    real_home.mkdir(mode=0o700, parents=True)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    assert (
        initialize_capture_marker(
            alias_parent / "real-guard-home",
            run_id="run-symlink",
            expires_at=int(time.time()) + 300,
        )
        is None
    )

    first = initialize_capture_marker(real_home, run_id="run-existing", expires_at=int(time.time()) + 300)
    assert first is not None
    second = initialize_capture_marker(real_home, run_id="run-overwrite", expires_at=int(time.time()) + 300)
    assert second is None

    swapped_home = tmp_path / "swapped-home"
    swapped_home.mkdir(mode=0o700)
    foreign_diagnostics = tmp_path / "foreign-diagnostics"
    foreign_diagnostics.mkdir(mode=0o700)
    (swapped_home / "diagnostics").symlink_to(foreign_diagnostics, target_is_directory=True)
    assert (
        initialize_capture_marker(
            swapped_home,
            run_id="run-swap",
            expires_at=int(time.time()) + 300,
        )
        is None
    )


def test_marker_write_failure_preserves_replacement_sentinel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    directory = guard_home / "diagnostics"
    directory.mkdir(mode=0o700)
    marker = directory / CAPTURE_MARKER_NAME
    replacement = directory / "renamed-original-marker"
    sentinel = b"replacement-sentinel"
    state = {"swapped": False}

    def fail_after_replacement(_descriptor: int, _payload: bytes) -> int:
        if not state["swapped"]:
            marker.rename(replacement)
            marker.write_bytes(sentinel)
            marker.chmod(0o600)
            state["swapped"] = True
        raise OSError("injected marker write failure")

    monkeypatch.setattr(capture_fs.os, "write", fail_after_replacement)
    assert (
        initialize_capture_marker(
            guard_home,
            run_id="run-write-failure",
            expires_at=int(time.time()) + 300,
        )
        is None
    )
    assert marker.read_bytes() == sentinel
    assert replacement.exists()


@pytest.mark.parametrize("write_result", [0, -1])
def test_marker_nonpositive_write_is_bounded_and_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_result: int,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)

    monkeypatch.setattr(capture_fs.os, "write", lambda _descriptor, _payload: write_result)
    started = time.monotonic()
    assert (
        initialize_capture_marker(
            guard_home,
            run_id="run-no-progress",
            expires_at=int(time.time()) + 300,
        )
        is None
    )
    assert time.monotonic() - started < 1.0
    assert (guard_home / "diagnostics" / CAPTURE_MARKER_NAME).exists()


def test_record_and_byte_bounds_reject_without_decision_side_effect(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home, max_records=1)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-once"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    assert len(_rows(directory)) == 1

    oversized_home = tmp_path / "oversized"
    oversized_directory = _enable_capture(oversized_home)
    oversized = json.dumps(
        {"hook_event_name": "PreToolUse", "tool_use_id": "call-large", "tool_input": {"command": "x" * 70_000}}
    )
    assert not record_bridge_ingress(guard_home=oversized_home, raw_payload=oversized, event_name="PreToolUse")
    assert not _output_path(oversized_directory).exists()


@pytest.mark.skipif(not hasattr(os, "link"), reason="hard links unavailable")
def test_output_hardlink_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    raw = '{"hook_event_name":"PreToolUse","tool_use_id":"call-hardlink"}'
    assert record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")
    output = _output_path(directory)
    alias = directory / "alias"
    os.link(output, alias)
    assert not record_bridge_ingress(guard_home=guard_home, raw_payload=raw, event_name="PreToolUse")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_marker_symlink_is_rejected(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home)
    marker = directory / CAPTURE_MARKER_NAME
    target = tmp_path / "foreign-marker.json"
    target.write_text(marker.read_text(encoding="utf-8"), encoding="utf-8")
    target.chmod(0o600)
    marker.unlink()
    marker.symlink_to(target)
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-symlink"}',
        event_name="PreToolUse",
    )
    assert not _output_path(directory).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links unavailable")
def test_guard_home_ancestor_symlink_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_home = real_parent / "real-guard-home"
    directory = _enable_capture(real_home)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    alias = alias_parent / "real-guard-home"

    assert not record_bridge_ingress(
        guard_home=alias,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-alias"}',
        event_name="PreToolUse",
    )
    assert not _output_path(directory).exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_marker_and_output_fifos_are_nonblocking_and_inert(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    directory = guard_home / "diagnostics"
    directory.mkdir(mode=0o700)
    marker = directory / CAPTURE_MARKER_NAME
    os.mkfifo(marker, 0o600)

    started = time.monotonic()
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-marker-fifo"}',
        event_name="PreToolUse",
    )
    assert time.monotonic() - started < 1.0

    marker.unlink()
    _enable_capture(guard_home)
    output = _output_path(directory)
    os.mkfifo(output, 0o600)
    started = time.monotonic()
    assert not record_bridge_ingress(
        guard_home=guard_home,
        raw_payload='{"hook_event_name":"PreToolUse","tool_use_id":"call-output-fifo"}',
        event_name="PreToolUse",
    )
    assert time.monotonic() - started < 1.0

"""Diagnostic retention must preserve failures without retaining private state."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts.native_slo_diagnostics import (
    capture_inflight_failure,
    capture_transport_refusals,
    preserve_session_diagnostics,
)


def test_diagnostics_are_inactive_by_default():
    # A default call cannot even inspect the session, create files or read logs.
    preserve_session_diagnostics(object(), None)


def test_live_stack_capture_excludes_exception_text_and_frame_values(tmp_path):
    private_value = "synthetic-private-content-not-for-evidence"
    destination = tmp_path / "failure.json"
    assert capture_inflight_failure(None, None, None, destination=destination) is False
    assert not destination.exists()
    assert capture_inflight_failure(RuntimeError, RuntimeError(private_value), None, destination=destination) is False
    serialized = destination.read_text()
    assert private_value not in serialized
    snapshot = json.loads(serialized)
    assert 0 < len(snapshot["threads"]) <= 256
    assert all(0 < len(stack) <= 32 for stack in snapshot["threads"])
    assert all(set(frame) == {"file", "function", "line"} for stack in snapshot["threads"] for frame in stack)


def test_only_numeric_counters_and_bounded_owned_logs_are_retained(tmp_path):
    guard = tmp_path / "guard"
    (guard / "logs").mkdir(parents=True)
    (guard / "native-runtime").mkdir()
    (guard / "logs/daemon.log").write_bytes(b"synthetic diagnostic\n")
    (guard / "native-runtime/managed-resident-phases.v1.log").symlink_to(guard / "logs/daemon.log")
    (guard / "daemon-state.json").write_text("synthetic credential must stay private")
    server = SimpleNamespace(active_requests=3, rejected_requests="private text", active_hook_requests=True)
    destination = tmp_path / "diagnostics"
    preserve_session_diagnostics(SimpleNamespace(guard_home=guard, daemon=SimpleNamespace(_server=server)), destination)
    assert destination.stat().st_mode & 0o777 == 0o700
    assert {p.name for p in destination.iterdir()} == {"server-counts.json", "daemon.log"}
    assert json.loads((destination / "server-counts.json").read_text()) == {"active_requests": 3}
    assert (destination / "daemon.log").read_bytes() == b"synthetic diagnostic\n"


def test_oversize_log_is_rejected_before_copying(tmp_path):
    guard = tmp_path / "guard"
    (guard / "logs").mkdir(parents=True)
    (guard / "logs/daemon.log").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    destination = tmp_path / "diagnostics"
    with pytest.raises(RuntimeError, match="bounded log limit"):
        preserve_session_diagnostics(
            SimpleNamespace(guard_home=guard, daemon=SimpleNamespace(_server=SimpleNamespace())), destination
        )
    assert not (destination / "daemon.log").exists()


def test_observer_preserves_original_transport_effects_and_exceptions():
    sentinel = object()
    effects = []

    def discard(request):
        effects.append(request)
        return sentinel

    def close(request):
        effects.append(request)
        raise ConnectionError("synthetic private request text")

    server = SimpleNamespace(_discard_request=discard, _close_unclassified_socket=close)
    capture_transport_refusals(server)
    request = object()
    assert server._discard_request(request) is sentinel
    with pytest.raises(ConnectionError):
        server._close_unclassified_socket(request)
    assert effects == [request, request]
    assert dict(server._cigar_probe_transport_counts) == {
        "discard_request:other": 1,
        "close_unclassified_socket:other": 1,
    }
    assert "private" not in json.dumps(server._cigar_probe_transport_counts)

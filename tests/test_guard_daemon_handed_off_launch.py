"""A launch whose daemon published its handoff must not wedge later retirement.

Desktop updates launch the updated Core from an older CLI. When the Core takes
longer to start than the launcher waits, the launcher exits before it sees the
handoff, so it never tombstones its receipt. The daemon's signed state still
binds that launch, and that binding resolves the receipt.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module

_LAUNCH_PID = 64_321
_LAUNCH_MARKER = "posix:launch-start"
_LAUNCH_OWNER = "launch-owner"
_LAUNCH_PORT = 5410
_NONCE = "a" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH


class _RetirementProceededError(Exception):
    pass


def _write_launch_receipt(guard_home: Path) -> None:
    daemon_manager_module._ensure_private_directory(guard_home)
    payload: dict[str, object] = {
        "state_kind": "daemon_launch_pending",
        "guard_home": str(guard_home.resolve()),
        "pid": _LAUNCH_PID,
        "port": _LAUNCH_PORT,
        "launch_nonce": _NONCE,
        "launch_generation": _NONCE,
        "generation": _NONCE,
        "process_start_marker": _LAUNCH_MARKER,
        "process_creation_time": 4_242_424,
        "user": _LAUNCH_OWNER,
        "owner": _LAUNCH_OWNER,
        "runtime_fingerprint": "launcher-runtime",
    }
    discovery_key = daemon_manager_module.ensure_daemon_discovery_key(guard_home)
    pending = daemon_manager_module.authenticate_daemon_state(payload, discovery_key=discovery_key)
    daemon_manager_module._write_private_atomic_text(
        daemon_manager_module._pending_launch_path(guard_home),
        json.dumps(pending, sort_keys=True),
    )


def _live_daemon_state(monkeypatch, guard_home: Path, overrides: dict[str, object] | None = None) -> None:
    """Publish signed state from a live daemon started by the updated Core."""

    state: dict[str, object] = {
        "guard_home": str(guard_home.resolve()),
        "pid": _LAUNCH_PID,
        "port": _LAUNCH_PORT,
        "launch_nonce": _NONCE,
        "launch_generation": _NONCE,
        "generation": _NONCE,
        "process_start_marker": _LAUNCH_MARKER,
        "user": _LAUNCH_OWNER,
        "owner": _LAUNCH_OWNER,
        "runtime_fingerprint": "updated-core-runtime",
        **(overrides or {}),
    }
    monkeypatch.setattr(daemon_manager_module, "_load_authenticated_daemon_identity", lambda _home: (state, "token"))
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: _LAUNCH_MARKER)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: _LAUNCH_OWNER)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: None)


def _stop_after_the_receipt_gate(monkeypatch) -> None:
    def proceeded(_home: Path) -> None:
        raise _RetirementProceededError

    # Reading the daemon state is the first step after the receipt gate.
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", proceeded)


def test_handoff_from_another_executable_matches_only_when_the_runtime_may_differ(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    _write_launch_receipt(guard_home)
    _live_daemon_state(monkeypatch, guard_home)

    assert daemon_manager_module._guard_daemon_handoff_matches_launch(
        guard_home,
        launch_nonce=_NONCE,
        expected_pid=_LAUNCH_PID,
        expected_port=_LAUNCH_PORT,
        require_same_runtime=False,
    )
    assert not daemon_manager_module._guard_daemon_handoff_matches_launch(
        guard_home,
        launch_nonce=_NONCE,
        expected_pid=_LAUNCH_PID,
        expected_port=_LAUNCH_PORT,
    )


@pytest.mark.parametrize("lifecycle", ["retire", "ensure"])
def test_a_handed_off_launch_from_another_executable_no_longer_blocks_the_home(tmp_path, monkeypatch, lifecycle):
    guard_home = tmp_path / "guard-home"
    _write_launch_receipt(guard_home)
    _live_daemon_state(monkeypatch, guard_home)

    if lifecycle == "retire":
        _stop_after_the_receipt_gate(monkeypatch)
        with pytest.raises(_RetirementProceededError):
            daemon_manager_module._retire_guard_daemons_for_home(guard_home, keep_port=None, deadline=None)
    else:
        monkeypatch.setattr(
            daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_live_or_newer_daemon_url",
            lambda *_args, **_kwargs: f"http://127.0.0.1:{_LAUNCH_PORT}",
        )
        assert daemon_manager_module.ensure_guard_daemon(guard_home) == f"http://127.0.0.1:{_LAUNCH_PORT}"

    assert daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


@pytest.mark.parametrize(
    ("field", "foreign_value"),
    [
        ("launch_nonce", "b" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH),
        ("generation", "b" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH),
        ("port", _LAUNCH_PORT + 1),
        ("owner", "other-owner"),
        ("guard_home", "/elsewhere"),
    ],
)
def test_a_daemon_that_does_not_bind_the_launch_leaves_it_unresolved(tmp_path, monkeypatch, field, foreign_value):
    guard_home = tmp_path / "guard-home"
    _write_launch_receipt(guard_home)
    _live_daemon_state(monkeypatch, guard_home, {field: foreign_value})
    _stop_after_the_receipt_gate(monkeypatch)

    assert daemon_manager_module._retire_guard_daemons_for_home(guard_home, keep_port=None, deadline=None) == []
    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)


def test_a_launch_of_another_executable_accepts_its_handoff_while_it_waits(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    _write_launch_receipt(guard_home)
    _live_daemon_state(monkeypatch, guard_home)
    url = f"http://127.0.0.1:{_LAUNCH_PORT}"
    monkeypatch.setattr(daemon_manager_module, "_live_guard_daemon_url", lambda *_args, **_kwargs: url)

    assert (
        daemon_manager_module._wait_for_guard_daemon_url(
            guard_home,
            timeout=1.0,
            require_current_runtime=False,
            expected_pid=_LAUNCH_PID,
            expected_launch_nonce=_NONCE,
        )
        == url
    )

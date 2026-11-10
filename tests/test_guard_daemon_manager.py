"""Focused tests for Guard daemon startup coordination."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import nullcontext, suppress
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard import windows_paths as windows_paths_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.discovery import (
    daemon_discovery_key_path,
    load_authenticated_daemon_state,
)


@pytest.fixture(autouse=True)
def _no_orphaned_worker_reap(monkeypatch: pytest.MonkeyPatch) -> None:
    # Daemon starts here fake `subprocess.Popen`; the reap's runtime launch is
    # judged in tests/test_orphaned_daemon_workers.py.
    monkeypatch.setattr(daemon_manager_module, "reap_orphaned_daemon_workers", lambda **_kwargs: None)


def _write_subprocess_launch_wrapper(
    path: Path,
    *,
    source_root: Path,
    publish_handoff: bool,
) -> Path:
    """Create a disposable launch target that never touches a real daemon."""

    if publish_handoff:
        body = f"""
import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, {str(source_root)!r})
from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state

parser = argparse.ArgumentParser()
parser.add_argument("daemon")
parser.add_argument("--serve", action="store_true")
parser.add_argument("--guard-home", required=True)
parser.add_argument("--home", required=True)
parser.add_argument("--port", required=True, type=int)
args = parser.parse_args()
guard_home = Path(args.guard_home).resolve()
token = "test-handoff-token"
write_guard_daemon_state(guard_home, args.port, token)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            payload = {{"ok": True, "compatibility_version": 2}}
        elif self.path == "/v1/healthz/details":
            payload = {{"ok": True, "guard_home": str(guard_home)}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        return

HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
"""
    else:
        body = f"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, {str(source_root)!r})
from codex_plugin_scanner.guard.live_process_identity import process_owner_marker, process_start_token

parser = argparse.ArgumentParser()
parser.add_argument("daemon")
parser.add_argument("--serve", action="store_true")
parser.add_argument("--guard-home", required=True)
parser.add_argument("--home", required=True)
parser.add_argument("--port", required=True, type=int)
args = parser.parse_args()
guard_home = Path(args.guard_home).resolve()
helper = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"],
    start_new_session=True,
)
(guard_home / "escaped-helper.pid").write_text(str(helper.pid), encoding="utf-8")
helper_start_marker = process_start_token(helper.pid)
helper_owner = process_owner_marker(helper.pid)
if not isinstance(helper_start_marker, str) or not helper_start_marker:
    raise RuntimeError("escaped helper start marker unavailable")
if not isinstance(helper_owner, str) or not helper_owner:
    raise RuntimeError("escaped helper owner marker unavailable")
(guard_home / "escaped-helper-receipt.json").write_text(
    json.dumps({{"pid": helper.pid, "process_start_marker": helper_start_marker, "owner": helper_owner}}),
    encoding="utf-8",
)
def reap_helper():
    helper.wait()

threading.Thread(target=reap_helper, daemon=True).start()
time.sleep(60)
"""
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def _wait_for_verified_process_death(
    pid: int,
    *,
    start_marker: str,
    owner: str,
    timeout: float = 5.0,
) -> bool:
    def dead_or_reaped() -> bool:
        if not daemon_manager_module._guard_daemon_pid_is_proven_dead(pid):
            return False
        if not daemon_manager_module._guard_daemon_pid_is_running(pid):
            return True
        return _reap_verified_posix_direct_child(
            pid,
            start_marker=start_marker,
            owner=owner,
        )

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if dead_or_reaped():
            return True
        if (
            daemon_manager_module.process_start_token(pid) != start_marker
            or daemon_manager_module.process_owner_marker(pid) != owner
        ):
            return not daemon_manager_module._guard_daemon_pid_is_running(pid)
        time.sleep(0.05)
    return dead_or_reaped()


def _reap_verified_posix_direct_child(pid: int, *, start_marker: str, owner: str) -> bool:
    """Reap one exact test-owned direct child after PPID and identity proof."""

    if os.name == "nt" or daemon_manager_module._guard_daemon_parent_pid(pid) != os.getpid():
        return False
    actual_start_marker = daemon_manager_module.process_start_token(pid)
    actual_owner = daemon_manager_module.process_owner_marker(pid)
    if (
        not isinstance(actual_start_marker, str)
        or actual_start_marker != start_marker
        or not isinstance(actual_owner, str)
        or actual_owner != owner
    ):
        return False
    try:
        waited_pid, _status = os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError, ValueError):
        return False
    return waited_pid == pid


def _terminate_verified_posix_process(pid: int, *, start_marker: str, owner: str) -> None:
    if not daemon_manager_module._guard_daemon_pid_is_running(pid):
        return
    assert daemon_manager_module.process_start_token(pid) == start_marker
    assert daemon_manager_module.process_owner_marker(pid) == owner
    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    if _wait_for_verified_process_death(pid, start_marker=start_marker, owner=owner):
        return
    assert daemon_manager_module._guard_daemon_pid_is_running(pid)
    assert daemon_manager_module.process_start_token(pid) == start_marker
    assert daemon_manager_module.process_owner_marker(pid) == owner
    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    assert _wait_for_verified_process_death(pid, start_marker=start_marker, owner=owner)


def _load_escaped_helper_receipt(guard_home: Path) -> tuple[int, str, str] | None:
    try:
        receipt = json.loads((guard_home / "escaped-helper-receipt.json").read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return None
    if not isinstance(receipt, dict):
        return None
    pid = receipt.get("pid")
    start_marker = receipt.get("process_start_marker")
    owner = receipt.get("owner")
    if (
        not isinstance(pid, int)
        or pid <= 0
        or not isinstance(start_marker, str)
        or not start_marker
        or not isinstance(owner, str)
        or not owner
    ):
        return None
    return pid, start_marker, owner


class _WindowsOSProxy:
    """Expose Windows branching without mutating process-wide ``os.name``."""

    name = "nt"

    def __getattr__(self, name: str):
        return getattr(os, name)


class _PosixOSProxy:
    """Expose POSIX branching without mutating process-wide ``os.name``."""

    name = "posix"

    def __getattr__(self, name: str):
        return getattr(os, name)


def _disable_duplicate_retire(monkeypatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module,
        "_schedule_duplicate_guard_daemon_retirement",
        lambda _guard_home: None,
    )


def _run_ephemeral_reap_synchronously(monkeypatch) -> None:
    def schedule(*, exclude_guard_home=None) -> None:
        daemon_manager_module._reap_stale_ephemeral_guard_daemons(
            exclude_guard_home=exclude_guard_home,
            force=True,
        )

    monkeypatch.setattr(daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", schedule)


def _inspect_command(command: str) -> dict[str, object]:
    return daemon_manager_module._lifecycle("inspect_command", {"command": command})


def test_stale_ephemeral_reap_is_nonblocking_and_single_flight(tmp_path, monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls: list[Path | None] = []

    def blocking_reap(*, exclude_guard_home=None, force=False) -> None:
        assert force
        calls.append(exclude_guard_home)
        entered.set()
        release.wait(timeout=2.0)
        finished.set()

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", blocking_reap)
    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module, "_EPHEMERAL_REAP_IN_FLIGHT", False)
    guard_home = tmp_path / "guard-home"

    started = time.monotonic()
    daemon_manager_module._schedule_stale_ephemeral_guard_daemon_reap(exclude_guard_home=guard_home)
    daemon_manager_module._schedule_stale_ephemeral_guard_daemon_reap(exclude_guard_home=guard_home)

    assert time.monotonic() - started < 1.0
    assert entered.wait(timeout=1.0)
    assert calls == [guard_home]
    release.set()
    assert finished.wait(timeout=1.0)


def test_duplicate_retirement_is_nonblocking_and_single_flight(tmp_path, monkeypatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls: list[Path] = []

    def blocking_retirement(guard_home: Path) -> None:
        calls.append(guard_home)
        entered.set()
        release.wait(timeout=2.0)
        finished.set()

    monkeypatch.setattr(daemon_manager_module, "_retire_current_duplicate_guard_daemons", blocking_retirement)
    monkeypatch.setattr(daemon_manager_module, "_DUPLICATE_RETIRE_IN_FLIGHT", set())
    guard_home = tmp_path / "guard-home"

    started = time.monotonic()
    daemon_manager_module._schedule_duplicate_guard_daemon_retirement(guard_home)
    daemon_manager_module._schedule_duplicate_guard_daemon_retirement(guard_home)
    for index in range(64):
        daemon_manager_module._schedule_duplicate_guard_daemon_retirement(tmp_path / f"other-guard-home-{index}")

    assert time.monotonic() - started < 1.0
    assert entered.wait(timeout=1.0)
    assert calls == [guard_home]
    release.set()
    assert finished.wait(timeout=1.0)


def test_schedule_guard_daemon_ensure_is_reserved_and_nonblocking(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    spawned: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_claim_guard_daemon_wake_reservation",
        lambda _home: "wake-token",
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **kwargs: spawned.append((list(command), dict(kwargs))) or SimpleNamespace(pid=123),
    )

    url = daemon_manager_module.schedule_guard_daemon_ensure(
        guard_home,
        home_dir=tmp_path,
    )

    assert url == daemon_manager_module.guard_daemon_url_for_home(guard_home)
    assert len(spawned) == 1
    command, kwargs = spawned[0]
    assert command[-9:] == [
        "guard",
        "daemon",
        "ensure",
        "--guard-home",
        str(guard_home),
        "--home",
        str(tmp_path),
        "--wake-token",
        "wake-token",
    ]
    assert kwargs["stdin"] == daemon_manager_module.subprocess.DEVNULL
    assert kwargs["stdout"] == daemon_manager_module.subprocess.DEVNULL
    assert kwargs["stderr"] == daemon_manager_module.subprocess.DEVNULL
    if os.name == "nt":
        assert "start_new_session" not in kwargs
        assert isinstance(kwargs.get("creationflags"), int)
    else:
        assert kwargs.get("start_new_session") is True


def test_schedule_guard_daemon_ensure_suppresses_duplicate_reservation(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_claim_guard_daemon_wake_reservation", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("reserved wake must not spawn another helper"),
    )

    assert daemon_manager_module.schedule_guard_daemon_ensure(
        guard_home
    ) == daemon_manager_module.guard_daemon_url_for_home(guard_home)


def test_schedule_guard_daemon_ensure_clears_reservation_after_spawn_failure(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    cleared: list[tuple[Path, str]] = []
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_claim_guard_daemon_wake_reservation",
        lambda _home: "wake-token",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "clear_guard_daemon_wake_reservation",
        lambda home, *, token: cleared.append((home, token)) or True,
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("spawn failed")),
    )

    daemon_manager_module.schedule_guard_daemon_ensure(guard_home)

    assert cleared == [(guard_home, "wake-token")]


def test_schedule_guard_daemon_ensure_contains_reservation_failure(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_claim_guard_daemon_wake_reservation",
        lambda _home: (_ for _ in ()).throw(OSError("state unavailable")),
    )

    assert daemon_manager_module.schedule_guard_daemon_ensure(
        guard_home
    ) == daemon_manager_module.guard_daemon_url_for_home(guard_home)


def test_schedule_guard_daemon_ensure_contains_spawn_and_cleanup_failure(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_claim_guard_daemon_wake_reservation",
        lambda _home: "wake-token",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "clear_guard_daemon_wake_reservation",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("state unavailable")),
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("spawn failed")),
    )

    assert daemon_manager_module.schedule_guard_daemon_ensure(
        guard_home,
        home_dir=tmp_path,
    ) == daemon_manager_module.guard_daemon_url_for_home(guard_home)


def test_schedule_guard_daemon_ensure_contains_home_validation_failure(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    missing_home = tmp_path / "missing-home"
    cleared: list[tuple[Path, str]] = []
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_claim_guard_daemon_wake_reservation",
        lambda _home: "wake-token",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "clear_guard_daemon_wake_reservation",
        lambda home, *, token: cleared.append((home, token)) or True,
    )

    assert daemon_manager_module.schedule_guard_daemon_ensure(
        guard_home,
        home_dir=missing_home,
    ) == daemon_manager_module.guard_daemon_url_for_home(guard_home)
    assert cleared == [(guard_home, "wake-token")]


def test_schedule_guard_daemon_ensure_skips_spawn_during_preflight(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("preflight must not spawn a daemon"),
    )

    assert daemon_manager_module.schedule_guard_daemon_ensure(tmp_path / "guard-home") == ""


def test_duplicate_retirement_reauthenticates_replacement_before_cleanup(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    active_url = {"value": "http://127.0.0.1:5474"}
    processes = {"value": [(111, 5474), (222, 5475)]}
    killed: list[int] = []
    retired = threading.Event()

    monkeypatch.setattr(daemon_manager_module, "_DUPLICATE_RETIRE_IN_FLIGHT", set())
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: active_url["value"])
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _home: list(processes["value"]),
    )
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda pid: f"linux:duplicate-{pid}")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")

    def retire(pid: int, *, expected_guard_home=None, **_identity) -> bool:
        del expected_guard_home
        killed.append(pid)
        processes["value"] = [entry for entry in processes["value"] if entry[0] != pid]
        retired.set()
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)
    monkeypatch.setattr(daemon_manager_module, "_rewrite_kept_daemon_state_if_missing", lambda *_args, **_kwargs: None)

    with daemon_manager_module._guard_daemon_start_lock(guard_home):
        daemon_manager_module._schedule_duplicate_guard_daemon_retirement(guard_home)
        active_url["value"] = "http://127.0.0.1:5475"

    assert retired.wait(timeout=1.0)
    assert killed == [111]


def test_duplicate_retirement_worker_failure_allows_subsequent_schedule(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    attempts: list[Path] = []
    attempted = threading.Event()

    def failing_retirement(candidate: Path) -> None:
        attempts.append(candidate)
        attempted.set()
        raise RuntimeError("injected maintenance failure")

    monkeypatch.setattr(daemon_manager_module, "_retire_current_duplicate_guard_daemons", failing_retirement)
    monkeypatch.setattr(daemon_manager_module, "_DUPLICATE_RETIRE_IN_FLIGHT", set())

    for expected_attempts in (1, 2):
        attempted.clear()
        daemon_manager_module._schedule_duplicate_guard_daemon_retirement(guard_home)
        assert attempted.wait(timeout=1.0)
        deadline = time.monotonic() + 1.0
        while daemon_manager_module._DUPLICATE_RETIRE_IN_FLIGHT and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not daemon_manager_module._DUPLICATE_RETIRE_IN_FLIGHT
        assert len(attempts) == expected_attempts


@pytest.mark.parametrize(
    ("scheduler", "state_name", "state_value"),
    [
        ("_schedule_stale_ephemeral_guard_daemon_reap", "_EPHEMERAL_REAP_IN_FLIGHT", False),
        ("_schedule_duplicate_guard_daemon_retirement", "_DUPLICATE_RETIRE_IN_FLIGHT", set()),
    ],
)
def test_maintenance_thread_start_failure_clears_single_flight_state(
    tmp_path,
    monkeypatch,
    scheduler,
    state_name,
    state_value,
) -> None:
    class FailingThread:
        def __init__(self, **_kwargs) -> None:
            return None

        def start(self) -> None:
            raise RuntimeError("thread capacity exhausted")

    monkeypatch.setattr(daemon_manager_module.threading, "Thread", FailingThread)
    monkeypatch.setattr(daemon_manager_module, state_name, state_value)
    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    guard_home = tmp_path / "guard-home"

    schedule = getattr(daemon_manager_module, scheduler)
    if scheduler == "_schedule_stale_ephemeral_guard_daemon_reap":
        schedule(exclude_guard_home=guard_home)
    else:
        schedule(guard_home)

    state = getattr(daemon_manager_module, state_name)
    assert state is False or state == set()
    if scheduler == "_schedule_stale_ephemeral_guard_daemon_reap":
        assert daemon_manager_module._LAST_EPHEMERAL_REAP_AT == 0.0


def test_hook_failure_preserves_an_older_authenticated_daemon(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    old_state = {"started_at": "2020-01-01T00:00:00+00:00"}
    retired: list[Path] = []
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_lock", lambda _home, **_kwargs: nullcontext())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: old_state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda home: retired.append(home) or pytest.fail("hook traffic must not retire an authenticated daemon"),
    )
    monkeypatch.setattr(daemon_manager_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None, **_kwargs: "http://127.0.0.1:5475",
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(guard_home)

    assert recovered == "http://127.0.0.1:5474"
    assert retired == []


def test_hook_failure_preserves_a_concurrently_started_replacement(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    recent_state = {"started_at": datetime.now(timezone.utc).isoformat()}
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_lock", lambda _home, **_kwargs: nullcontext())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: recent_state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:5475")
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda _home: pytest.fail("recent replacement must not be retired"),
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(guard_home)

    assert recovered == "http://127.0.0.1:5475"


def test_write_guard_daemon_state_keeps_auth_token_out_of_state_file(tmp_path):
    guard_home = tmp_path / "guard-home"

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")

    state_path = daemon_manager_module._state_path(guard_home)
    token_path = daemon_manager_module._auth_token_path(guard_home)
    discovery_key_path = daemon_discovery_key_path(guard_home)
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))

    assert state_payload["port"] == 4781
    assert "auth_token" not in state_payload
    assert daemon_manager_module.load_guard_daemon_auth_token(guard_home) == "secret-token"
    assert token_path.read_text(encoding="utf-8") == "secret-token"
    assert load_authenticated_daemon_state(guard_home) == state_payload
    if os.name != "nt":
        assert stat.S_IMODE(state_path.stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE(token_path.stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE(discovery_key_path.stat().st_mode) & 0o077 == 0


def test_write_guard_daemon_state_authenticates_trust_snapshot(tmp_path):
    guard_home = tmp_path / "guard-home"
    trust_status = {
        "backend": "system-keyring",
        "degraded_reasons": [],
        "enforcement": "enforce",
        "mode": "protected",
    }

    daemon_manager_module.write_guard_daemon_state(
        guard_home,
        4781,
        "secret-token",
        trust_status=trust_status,
    )

    authenticated = load_authenticated_daemon_state(guard_home)
    assert authenticated is not None
    assert authenticated["trust_status"] == trust_status

    state_path = daemon_manager_module._state_path(guard_home)
    tampered = json.loads(state_path.read_text(encoding="utf-8"))
    tampered["trust_status"]["mode"] = "degraded"
    state_path.write_text(json.dumps(tampered), encoding="utf-8")

    assert load_authenticated_daemon_state(guard_home) is None


def test_clear_guard_daemon_state_preserves_auth_token_file(tmp_path):
    guard_home = tmp_path / "guard-home"

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")
    daemon_manager_module.clear_guard_daemon_state(guard_home)

    assert json.loads(daemon_manager_module._state_path(guard_home).read_text(encoding="utf-8")) == {}
    assert daemon_manager_module._auth_token_path(guard_home).read_text(encoding="utf-8") == "secret-token"


def test_load_guard_daemon_auth_token_never_uses_legacy_mutable_state(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    daemon_manager_module._state_path(guard_home).write_text(
        json.dumps({"port": 4781, "auth_token": "legacy-mutable-token"}),
        encoding="utf-8",
    )

    assert daemon_manager_module.load_guard_daemon_auth_token(guard_home) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode enforcement")
def test_load_guard_daemon_auth_token_rejects_non_private_file(tmp_path):
    guard_home = tmp_path / "guard-home"
    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")
    os.chmod(daemon_manager_module._auth_token_path(guard_home), 0o644)

    assert daemon_manager_module.load_guard_daemon_auth_token(guard_home) is None
    assert daemon_manager_module._load_authenticated_daemon_identity(guard_home) is None


def test_load_guard_daemon_url_rejects_unsigned_legacy_state_before_network(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    daemon_manager_module._state_path(guard_home).write_text(
        json.dumps(
            {
                "port": 4781,
                "pid": os.getpid(),
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        daemon_manager_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not probe unsigned state")),
    )

    assert daemon_manager_module.load_guard_daemon_url(guard_home) is None


def test_load_guard_daemon_url_rejects_live_port_when_state_pid_is_not_guard_daemon(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    other_guard_home = tmp_path / "other-guard-home"
    daemon_manager_module.write_guard_daemon_state(guard_home, 4833, "secret-token")

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "ok": True,
                    "tables": ["guard_connect_states"],
                    "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "guard_home": str(other_guard_home),
                }
            ).encode("utf-8")

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: False,
    )
    monkeypatch.setattr(
        daemon_manager_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(),
    )

    assert daemon_manager_module.load_guard_daemon_url(guard_home) is None


def test_load_guard_daemon_url_accepts_matching_healthz_guard_home_for_in_process_daemon(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    daemon_manager_module.write_guard_daemon_state(guard_home, 4833, "secret-token")
    requested_urls: list[str] = []
    requested_headers: list[dict[str, str]] = []

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self, _limit: int = -1) -> bytes:
            return json.dumps(
                {
                    "ok": True,
                    "tables": ["guard_connect_states"],
                    "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "guard_home": str(guard_home),
                }
            ).encode("utf-8")

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: False,
    )

    def fake_urlopen(request, *_args, **_kwargs):
        requested_urls.append(request.full_url if hasattr(request, "full_url") else str(request))
        if hasattr(request, "header_items"):
            requested_headers.append(dict(request.header_items()))
        else:
            requested_headers.append({})
        return FakeResponse()

    monkeypatch.setattr(daemon_manager_module.urllib.request, "urlopen", fake_urlopen)

    assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:4833"
    assert requested_urls == [
        "http://127.0.0.1:4833/healthz",
        "http://127.0.0.1:4833/v1/healthz/details",
    ]
    assert requested_headers[0] == {}
    assert requested_headers[1]["X-guard-token"] == "secret-token"


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX os.fchmod permission semantics")
def test_write_guard_daemon_state_hardens_permissions_on_open_descriptor(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    fchmod_calls: list[tuple[int, int, int]] = []

    def fake_fchmod(descriptor: int, mode: int) -> None:
        metadata = daemon_manager_module.os.fstat(descriptor)
        fchmod_calls.append((metadata.st_dev, metadata.st_ino, mode))

    monkeypatch.setattr(daemon_manager_module.os, "fchmod", fake_fchmod)

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")

    state_metadata = daemon_manager_module._state_path(guard_home).stat()
    assert (state_metadata.st_dev, state_metadata.st_ino, 0o600) in fchmod_calls
    assert all(mode == 0o600 for _, _, mode in fchmod_calls)


def test_authenticated_daemon_state_rejects_post_write_tampering(tmp_path):
    guard_home = tmp_path / "guard-home"
    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")
    state_path = daemon_manager_module._state_path(guard_home)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["port"] = 4782
    state_path.write_text(json.dumps(state), encoding="utf-8")
    os.chmod(state_path, 0o600)

    assert load_authenticated_daemon_state(guard_home) is None


def test_daemon_token_and_state_use_atomic_replacement(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    replacements: list[tuple[Path, Path]] = []
    monkeypatch.setattr(daemon_manager_module, "_current_guard_daemon_runtime_fingerprint", lambda: "f" * 64)
    real_replace = daemon_manager_module.os.replace

    def recording_replace(source, destination) -> None:
        replacements.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(daemon_manager_module.os, "replace", recording_replace)

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")
    destinations = {destination for _temporary_path, destination in replacements}
    assert destinations == {
        daemon_manager_module._auth_token_path(guard_home),
        daemon_manager_module._state_path(guard_home),
    }
    assert all(temporary_path.parent == guard_home for temporary_path, _destination in replacements)
    assert all(temporary_path != destination for temporary_path, destination in replacements)


def test_concurrent_daemon_restarts_leave_matching_authenticated_state_and_token(tmp_path):
    guard_home = tmp_path / "guard-home"
    writer_count = 8
    start = threading.Barrier(writer_count)

    def write_generation(index: int) -> None:
        start.wait()
        daemon_manager_module.write_guard_daemon_state(
            guard_home,
            4781 + index,
            f"restart-token-{index}",
            pid=10_000 + index,
            state_id=f"restart-state-{index}",
        )

    threads = [threading.Thread(target=write_generation, args=(index,)) for index in range(writer_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    state = load_authenticated_daemon_state(guard_home)
    token = daemon_manager_module.load_guard_daemon_auth_token(guard_home)
    assert state is not None
    assert token is not None
    assert state["auth_token_id"] == hashlib.sha256(token.encode("utf-8")).hexdigest()


def test_healthz_payload_is_current_accepts_redacted_public_healthz() -> None:
    payload = json.dumps(
        {
            "ok": True,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        }
    )

    assert daemon_manager_module._healthz_payload_is_current(payload) is True


def test_guard_daemon_url_port_rejects_invalid_port_text() -> None:
    assert daemon_manager_module._guard_daemon_url_port("http://127.0.0.1:not-a-port") is None


def test_windows_daemon_breakaway_flag_is_only_added_when_explicitly_authorized() -> None:
    default_flags = daemon_manager_module._windows_daemon_creation_flags(allow_job_breakaway=False)
    refresh_flags = daemon_manager_module._windows_daemon_creation_flags(allow_job_breakaway=True)

    assert default_flags & daemon_manager_module._WINDOWS_CREATE_BREAKAWAY_FROM_JOB == 0
    assert refresh_flags == default_flags | daemon_manager_module._WINDOWS_CREATE_BREAKAWAY_FROM_JOB


def test_windows_daemon_pid_probe_never_uses_os_kill(monkeypatch) -> None:
    probe = MagicMock(return_value=True)
    monkeypatch.setattr(daemon_manager_module.os, "name", "nt")
    monkeypatch.setattr(daemon_manager_module, "windows_process_is_running", probe)
    monkeypatch.setattr(
        daemon_manager_module.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(AssertionError("Windows liveness probes must be non-destructive")),
    )

    assert daemon_manager_module._guard_daemon_pid_is_running(4321) is True
    probe.assert_called_once_with(4321)


def _fake_lifecycle_runtime(monkeypatch, answer: dict[str, object] | None) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def fake_answer(
        request: dict[str, object],
        *,
        output_limit: int,
        deadline: float | None = None,
    ) -> dict[str, object] | None:
        assert output_limit > 0
        requests.append(request if deadline is None else {**request, "deadline": deadline})
        return answer

    monkeypatch.setattr(windows_paths_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(windows_paths_module, "_lifecycle_answer", fake_answer)
    return requests


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ({"liveness": [False]}, False),
        ({"liveness": [True]}, True),
        ({"liveness": [None]}, None),
        ({"liveness": [0]}, None),
        ({"liveness": [False, False]}, None),
        ({}, None),
        (None, None),
    ],
)
def test_windows_process_liveness_is_dead_only_when_the_runtime_proves_it(
    monkeypatch,
    answer: dict[str, object] | None,
    expected: bool | None,
) -> None:
    requests = _fake_lifecycle_runtime(monkeypatch, answer)

    assert windows_paths_module.windows_process_liveness(4321) is expected
    assert windows_paths_module.windows_process_is_running(4321) is (expected is not False)
    assert requests[0] == {"op": "liveness", "pids": [4321]}


def test_windows_process_facts_refuse_malformed_runtime_answers(monkeypatch) -> None:
    _fake_lifecycle_runtime(
        monkeypatch,
        {"creation_times": [133_000_000_000_000_000], "owner_sids": ["sid:S-1-5-21-1"]},
    )
    assert windows_paths_module.windows_process_creation_time(4321) == 133_000_000_000_000_000
    assert windows_paths_module.windows_process_owner_sid(4321) == "sid:S-1-5-21-1"

    for creation_time in (0, -1, True, "133", None):
        _fake_lifecycle_runtime(monkeypatch, {"creation_times": [creation_time]})
        assert windows_paths_module.windows_process_creation_time(4321) is None
    for owner_sid in ("S-1-5-21-1", "sid:", 7, None):
        _fake_lifecycle_runtime(monkeypatch, {"owner_sids": [owner_sid]})
        assert windows_paths_module.windows_process_owner_sid(4321) is None


def test_windows_process_lifecycle_never_asks_the_runtime_about_invalid_pids(monkeypatch) -> None:
    requests = _fake_lifecycle_runtime(monkeypatch, {"terminated": True})

    assert windows_paths_module.windows_process_liveness(0) is False
    assert windows_paths_module.windows_process_creation_time(-1) is None
    assert windows_paths_module.windows_process_owner_sid(0) is None
    assert windows_paths_module.windows_terminate_process_if_creation_time(0, 77) is False
    assert windows_paths_module.windows_terminate_process_if_creation_time(4321, 0) is False
    assert windows_paths_module.windows_command_line_to_argv("") is None
    assert requests == []


def test_windows_exact_termination_sends_the_generation_and_bounded_timeout(monkeypatch) -> None:
    requests = _fake_lifecycle_runtime(monkeypatch, {"terminated": True})
    monkeypatch.setattr(windows_paths_module, "time", SimpleNamespace(monotonic=lambda: 100.0))

    assert windows_paths_module.windows_terminate_process_if_creation_time(4321, 77)
    assert windows_paths_module.windows_terminate_process_if_creation_time(4321, 77, timeout=0.25)
    assert windows_paths_module.windows_terminate_process_if_creation_time(4321, 77, timeout=-3.0)
    assert windows_paths_module.windows_terminate_process_if_creation_time(4321, 77, timeout=10_000.0)
    assert requests == [
        {"op": "terminate_if_creation_time", "pid": 4321, "expected_creation_time": 77},
        {
            "op": "terminate_if_creation_time",
            "pid": 4321,
            "expected_creation_time": 77,
            "timeout_ms": 250,
            "deadline": 101.25,
        },
        {
            "op": "terminate_if_creation_time",
            "pid": 4321,
            "expected_creation_time": 77,
            "timeout_ms": 0,
            "deadline": 101.0,
        },
        {
            "op": "terminate_if_creation_time",
            "pid": 4321,
            "expected_creation_time": 77,
            "timeout_ms": 600_000,
            "deadline": 701.0,
        },
    ]

    refused: list[dict[str, object] | None] = [{"terminated": False}, {"terminated": 1}, {}, None]
    for answer in refused:
        _fake_lifecycle_runtime(monkeypatch, answer)
        assert windows_paths_module.windows_terminate_process_if_creation_time(4321, 77) is False


@pytest.mark.skipif(os.name != "nt", reason="Windows process liveness regression")
def test_windows_daemon_pid_probe_leaves_live_process_running() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert daemon_manager_module._guard_daemon_pid_is_running(process.pid) is True
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_post_update_daemon_start_forwards_explicit_windows_breakaway_authorization(
    tmp_path,
    monkeypatch,
) -> None:
    ensure = MagicMock(return_value="http://127.0.0.1:4781")
    monkeypatch.setattr(daemon_manager_module, "ensure_guard_daemon", ensure)
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"

    assert (
        daemon_manager_module.ensure_guard_daemon_after_update(
            guard_home,
            home_dir=home_dir,
            preferred_port=4781,
            allow_windows_job_breakaway=True,
        )
        == "http://127.0.0.1:4781"
    )
    ensure.assert_called_once_with(
        guard_home,
        home_dir=home_dir,
        start_timeout=daemon_manager_module._post_update_guard_daemon_start_timeout(),
        preferred_port=4781,
        allow_windows_job_breakaway=True,
    )


def test_running_guard_daemon_processes_for_guard_home_returns_empty_on_ps_timeout(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"

    monkeypatch.setattr(
        daemon_manager_module.posix_processes, "posix_process_inventory", lambda *_args, **_kwargs: None
    )

    assert daemon_manager_module._running_guard_daemon_processes_for_guard_home(guard_home) == []


@pytest.mark.skipif(os.name == "nt", reason="models POSIX ps output and console-script command syntax")
def test_running_guard_daemon_processes_for_guard_home_accepts_console_script_launch(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    command = (
        "/Users/test/.local/pipx/venvs/hol-guard/bin/python "
        "/Users/test/.local/bin/hol-guard guard daemon --serve "
        f"--guard-home {guard_home} --port 5474"
    )

    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda *_args, **_kwargs: f"12345 {command}\n",
    )

    assert daemon_manager_module._running_guard_daemon_processes_for_guard_home(guard_home) == [(12345, 5474)]


def test_guard_daemon_command_matches_accepts_console_script_shortcuts() -> None:
    assert _inspect_command("/Users/test/.local/bin/hol-guard daemon --serve --guard-home /tmp/guard-home --port 5474")[
        "matches"
    ]
    assert _inspect_command(
        "/Users/test/.local/bin/plugin-guard daemon --serve --guard-home /tmp/guard-home --port 5474"
    )["matches"]


def test_ensure_guard_daemon_retires_duplicate_ports_for_same_guard_home(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    killed: list[int] = []
    retired = threading.Event()

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module, "load_guard_daemon_url", lambda _guard_home, **kwargs: "http://127.0.0.1:5474"
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home, **kwargs: [(111, 5474), (222, 5475)],
    )
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda pid: f"linux:duplicate-{pid}")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")

    def retire(pid: int, *, expected_guard_home=None, **_identity) -> bool:
        del expected_guard_home
        killed.append(pid)
        retired.set()
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5474"
    assert retired.wait(timeout=1.0)
    assert killed == [222]


def test_ensure_guard_daemon_expired_outer_deadline_has_no_launch_or_home_mutation(tmp_path, monkeypatch):
    guard_home = tmp_path / "uncreated-guard-home"

    def unexpected_preparation(*_args, **_kwargs):
        pytest.fail("expired admission must not prepare or launch a daemon")

    monkeypatch.setattr(daemon_manager_module, "_trusted_daemon_home", unexpected_preparation)
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", unexpected_preparation)
    with pytest.raises(TimeoutError, match="operation deadline exceeded"):
        daemon_manager_module.ensure_guard_daemon(guard_home, deadline_monotonic=time.monotonic() - 1)
    assert not guard_home.exists()


@pytest.mark.skipif(os.name == "nt", reason="models POSIX PID generation checks")
@pytest.mark.parametrize("fault", ["expired", "foreign_token", "reused_before_signal", "query_expired"])
def test_exact_retirement_refuses_expiry_or_pid_reuse_before_signaling(monkeypatch, fault):
    from codex_plugin_scanner.guard import live_process_identity

    clock, queries = {"value": 100.0}, []
    deadline = 99.0 if fault == "expired" else 101.0
    monkeypatch.setattr(daemon_manager_module.time, "monotonic", lambda: clock["value"])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)

    def token(pid, *, deadline_monotonic):
        assert pid == 123 and deadline_monotonic == deadline
        queries.append(pid)
        if fault == "query_expired":
            clock["value"] = deadline + 1
        return "foreign" if fault == "foreign_token" or len(queries) == 2 else "expected"

    def unexpected_signal(*_args, **_kwargs):
        pytest.fail("retirement signaled an unbound or expired process generation")

    monkeypatch.setattr(live_process_identity, "process_start_token", token)
    monkeypatch.setattr(daemon_manager_module.os, "kill", unexpected_signal)
    assert not daemon_manager_module._retire_guard_daemon_pid(
        123,
        deadline_monotonic=deadline,
        expected_start_token="expected",
    )
    assert len(queries) == {"expired": 0, "foreign_token": 1, "query_expired": 1, "reused_before_signal": 2}[fault]


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX subprocess identity markers")
def test_real_matching_handoff_keeps_only_nonce_bound_daemon_alive(tmp_path):
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "user-home"
    guard_home.mkdir()
    home_dir.mkdir()
    wrapper = _write_subprocess_launch_wrapper(
        tmp_path / "launch-with-matching-handoff",
        source_root=Path(daemon_manager_module.__file__).resolve().parents[3],
        publish_handoff=True,
    )

    process: tuple[int, str, str] | None = None
    try:
        url = daemon_manager_module.ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            executable=wrapper,
            start_timeout=20.0,
        )
        assert url.startswith("http://127.0.0.1:")
        process_pid = int(load_authenticated_daemon_state(guard_home)["pid"])
        state = load_authenticated_daemon_state(guard_home)
        pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
        assert state is not None
        assert pending is None
        assert process_pid > 0
        assert state["launch_nonce"]
        assert state["launch_generation"] == state["launch_nonce"]
        assert state["generation"] == state["launch_nonce"]
        process_start_marker = state["process_start_marker"]
        process_owner = state.get("owner", state["user"])
        assert isinstance(process_start_marker, str) and process_start_marker
        assert isinstance(process_owner, str) and process_owner
        assert state["runtime_fingerprint"]
        assert state["guard_home"] == str(guard_home.resolve())
        assert daemon_manager_module._guard_daemon_pid_is_running(process_pid)
        assert daemon_manager_module.process_start_token(process_pid) == process_start_marker
        assert daemon_manager_module.process_owner_marker(process_pid) == process_owner
        process = (process_pid, process_start_marker, process_owner)
    finally:
        if process is not None:
            _terminate_verified_posix_process(
                process[0],
                start_marker=process[1],
                owner=process[2],
            )


def test_launch_handoff_requires_every_generation_binding(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    nonce = "a" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    pending = {
        "guard_home": str(guard_home.resolve()),
        "pid": 12_345,
        "port": 5_432,
        "launch_nonce": nonce,
        "launch_generation": nonce,
        "generation": nonce,
        "process_start_marker": "marker",
        "user": "owner",
        "owner": "owner",
        "runtime_fingerprint": "runtime",
    }
    state = {
        **pending,
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "process_start_marker": "marker",
    }
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: pending)
    monkeypatch.setattr(daemon_manager_module, "_load_authenticated_daemon_identity", lambda _home: (state, "token"))
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "marker")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "owner")

    assert daemon_manager_module._guard_daemon_handoff_matches_launch(
        guard_home,
        launch_nonce=nonce,
        expected_pid=12_345,
        expected_port=5_432,
    )

    for field, invalid_value in (
        ("launch_nonce", "b" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH),
        ("launch_generation", "b" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH),
        ("generation", "b" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH),
        ("pid", 12_346),
        ("process_start_marker", "other-marker"),
        ("owner", "other-owner"),
        ("runtime_fingerprint", "other-runtime"),
        ("guard_home", str(tmp_path / "other-home")),
    ):
        invalid_state = {**state, field: invalid_value}
        monkeypatch.setattr(
            daemon_manager_module,
            "_load_authenticated_daemon_identity",
            lambda _home, invalid_state=invalid_state: (invalid_state, "token"),
        )
        assert not daemon_manager_module._guard_daemon_handoff_matches_launch(
            guard_home,
            launch_nonce=nonce,
            expected_pid=12_345,
            expected_port=5_432,
        ), field


def test_guard_daemon_state_matches_same_fingerprint_from_different_source_root():
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": "/different/install/path",
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
    }

    assert daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_rejects_different_runtime_fingerprint():
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": "stale-runtime-fingerprint",
    }

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


class _FingerprintRuntime:
    def __init__(self, answer: dict[str, object] | None) -> None:
        self.answer_value = answer
        self.requests: list[dict[str, object]] = []

    def answer(self, feature: str, command: str, request: dict[str, object], **_options: object) -> object:
        assert (feature, command) == ("native-runtime-fingerprint-v1", "runtime-fingerprint")
        self.requests.append(request)
        return self.answer_value


def _fingerprint_runtime(tmp_path, monkeypatch, answer: dict[str, object] | None) -> tuple[_FingerprintRuntime, Path]:
    fake = _FingerprintRuntime(answer)
    cache_dir = tmp_path / "fp-cache" / "runtime-fingerprint-cache"
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", fake.answer)
    monkeypatch.setattr(daemon_manager_module, "_current_guard_daemon_source_root", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "_runtime_fingerprint_cache_dir", lambda: cache_dir)
    monkeypatch.setattr(daemon_manager_module, "_runtime_fingerprint_cache", None)
    return fake, cache_dir


def test_runtime_fingerprint_hands_the_cache_dir_to_the_native_runtime(tmp_path, monkeypatch):
    """The walk, hashes and cache file are pinned in `runtime_fingerprint_tests.rs`."""
    fake, cache_dir = _fingerprint_runtime(
        tmp_path, monkeypatch, {"tree_sig": "t" * 8, "fingerprint": "a" * 64, "reused": True}
    )

    assert daemon_manager_module._current_guard_daemon_runtime_fingerprint() == "a" * 64
    fake.answer_value = {"tree_sig": "u" * 8, "fingerprint": "b" * 64, "reused": False}
    # The answer is memoised for the life of the process.
    assert daemon_manager_module._current_guard_daemon_runtime_fingerprint() == "a" * 64
    assert daemon_manager_module._runtime_fingerprint_cache == ("t" * 8, "a" * 64)
    assert fake.requests == [
        {
            "schema": "runtime-fingerprint.v1",
            "source_root": str(tmp_path),
            "version": daemon_manager_module.__version__,
            "cache_dir": str(cache_dir),
        }
    ]


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        {"tree_sig": "t", "fingerprint": "not-a-digest", "reused": False},
        {"tree_sig": "t", "fingerprint": "a" * 64},
    ],
)
def test_runtime_fingerprint_without_a_native_answer_is_refused(tmp_path, monkeypatch, answer):
    _fingerprint_runtime(tmp_path, monkeypatch, answer)

    with pytest.raises(RuntimeError, match="requires the native runtime"):
        daemon_manager_module._current_guard_daemon_runtime_fingerprint()
    assert daemon_manager_module._runtime_fingerprint_cache is None


def test_same_install_native_upgrade_rejects_live_previous_generation(tmp_path, monkeypatch):
    package = tmp_path / "codex_plugin_scanner"
    native = package / "_native"
    native.mkdir(parents=True)
    (package / "version.py").write_text('__version__ = "0.0.0"\n', encoding="utf-8")
    manifest = native / "runtime-manifest.json"
    manifest.write_text(json.dumps({"runtime_sha256": "a" * 64}), encoding="utf-8")
    monkeypatch.setattr(daemon_manager_module, "_current_guard_daemon_source_root", lambda: str(tmp_path))
    monkeypatch.setattr(
        daemon_manager_module,
        "_runtime_fingerprint_cache_dir",
        lambda: tmp_path / "fp-cache" / "runtime-fingerprint-cache",
    )
    monkeypatch.setattr(daemon_manager_module, "_runtime_fingerprint_cache", None)
    previous_generation = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": daemon_manager_module.__version__,
        "source_root": str(tmp_path),
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
    }
    assert daemon_manager_module._guard_daemon_state_matches_current_runtime(previous_generation)

    manifest.write_text(json.dumps({"runtime_sha256": "b" * 64}), encoding="utf-8")
    monkeypatch.setattr(daemon_manager_module, "_runtime_fingerprint_cache", None)

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(previous_generation)


def test_desktop_ensure_uses_post_update_timeout(monkeypatch):
    # The resident decides the budget: the larger of the base timeout and the
    # start floor plus its margin (14 s + 5 s), so a slow cold start is not cut
    # off. Windows runs the same arithmetic over its own budgets, because the
    # packaged runtime there spends half a minute before it publishes a port.
    windows = os.name == "nt"
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    assert daemon_manager_module._default_guard_daemon_start_timeout() == (75.0 if windows else 30.0)
    monkeypatch.delenv("HOL_GUARD_DESKTOP")
    assert daemon_manager_module._default_guard_daemon_start_timeout() == (60.0 if windows else 19.0)


def test_ensure_guard_daemon_refuses_desktop_preflight(tmp_path, monkeypatch):
    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")
    with pytest.raises(RuntimeError, match="disabled during Desktop preflight"):
        daemon_manager_module.ensure_guard_daemon(tmp_path / "guard-home")


def test_start_in_progress_requires_current_runtime_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_load_state",
        lambda _guard_home, **kwargs: {
            "pid": 4242,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": daemon_manager_module._current_guard_daemon_source_root(),
            "runtime_fingerprint": "stale-runtime-fingerprint",
        },
    )
    assert not daemon_manager_module._guard_daemon_start_in_progress(tmp_path / "guard-home")
    monkeypatch.setattr(
        daemon_manager_module,
        "_load_state",
        lambda _guard_home, **kwargs: {
            "pid": 4242,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": "/different/install/path",
            "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        },
    )
    assert daemon_manager_module._guard_daemon_start_in_progress(tmp_path / "guard-home")


def test_isolated_daemon_bootstrap_ignores_python_startup_hooks(tmp_path, monkeypatch):
    trusted_root = tmp_path / "trusted"
    poison_root = tmp_path / "poison"
    trusted_root.mkdir()
    poison_root.mkdir()
    trusted_marker = tmp_path / "trusted-marker"
    poisoned_module_marker = tmp_path / "poisoned-module-marker"
    sitecustomize_marker = tmp_path / "sitecustomize-marker"
    pth_marker = tmp_path / "pth-marker"

    (trusted_root / "trusted_daemon_probe.py").write_text(
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('trusted', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (trusted_root / "startup-hook.pth").write_text(
        f"import pathlib; pathlib.Path({str(pth_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (poison_root / "trusted_daemon_probe.py").write_text(
        f"from pathlib import Path\nPath({str(poisoned_module_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (poison_root / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(sitecustomize_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(poison_root))
    monkeypatch.setenv("PYTHONHOME", str(poison_root))
    monkeypatch.setenv("PYTHONSTARTUP", str(poison_root / "sitecustomize.py"))
    monkeypatch.setenv("VIRTUAL_ENV", str(poison_root / "venv"))

    command = daemon_manager_module._isolated_python_module_command(
        "trusted_daemon_probe",
        (trusted_root,),
        [str(trusted_marker)],
    )
    child_env = daemon_manager_module._daemon_launcher_env()
    result = subprocess.run(
        command,
        cwd=poison_root,
        env=child_env,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert trusted_marker.read_text(encoding="utf-8") == "trusted"
    assert not poisoned_module_marker.exists()
    assert not sitecustomize_marker.exists()
    assert not pth_marker.exists()
    assert "-I" in command
    assert "-S" in command
    if sys.version_info >= (3, 11):
        assert "-P" in command
    else:
        assert "-P" not in command
    assert all(key not in child_env for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV"))


def test_frozen_desktop_daemon_launcher_preserves_managed_context(tmp_path, monkeypatch):
    monkeypatch.setattr(daemon_manager_module.sys, "frozen", True, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "untrusted-parent-value")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    child_env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert child_env["HOL_GUARD_DESKTOP"] == "1"


def test_frozen_non_desktop_daemon_launcher_does_not_gain_desktop_context(tmp_path, monkeypatch):
    monkeypatch.setattr(daemon_manager_module.sys, "frozen", True, raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)

    child_env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert "HOL_GUARD_DESKTOP" not in child_env


def test_non_frozen_daemon_launcher_drops_desktop_context(tmp_path, monkeypatch):
    monkeypatch.setattr(daemon_manager_module.sys, "frozen", False, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    child_env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path)

    assert "PYINSTALLER_RESET_ENVIRONMENT" not in child_env
    assert "HOL_GUARD_DESKTOP" not in child_env


def test_ephemeral_runtime_probe_skips_policy_integrity_priming_and_preserves_heartbeat_semantics(
    tmp_path, monkeypatch
):
    guard_home = tmp_path / "pytest-of-user" / "pytest-4" / "test-active" / "home"
    fixed_now = datetime(2026, 7, 19, 6, 0, 0, tzinfo=timezone.utc)
    runtime_state = {"last_heartbeat_at": "2026-07-19T05:59:59+00:00"}
    constructor_calls: list[tuple[Path, bool]] = []

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz is not None else fixed_now.replace(tzinfo=None)

    class RuntimeStateStore:
        def __init__(self, store_guard_home: Path, *, prime_policy_integrity: bool) -> None:
            constructor_calls.append((store_guard_home, prime_policy_integrity))

        def get_runtime_state(self) -> dict[str, object]:
            return dict(runtime_state)

    monkeypatch.setattr(guard_store_module, "GuardStore", RuntimeStateStore)
    monkeypatch.setattr(daemon_manager_module, "datetime", FixedDateTime)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: expected_guard_home == guard_home,
    )
    state_payload: dict[str, object] = {"pid": 44444}

    assert not daemon_manager_module._ephemeral_guard_home_is_inactive(
        guard_home,
        fallback_age_seconds=60.0,
        state_payload=state_payload,
    )

    runtime_state["last_heartbeat_at"] = "2026-07-19T05:58:59+00:00"
    assert daemon_manager_module._ephemeral_guard_home_is_inactive(
        guard_home,
        fallback_age_seconds=60.0,
        state_payload=state_payload,
    )
    assert constructor_calls == [(guard_home, False), (guard_home, False)]


def test_retire_all_honors_keep_port_for_authenticated_state(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_daemon_state",
        lambda _guard_home: {
            "pid": 55_555,
            "port": 4781,
            "guard_home": str(guard_home),
            "process_start_marker": "linux:authenticated-generation",
            "user": "uid:501",
        },
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [],
    )
    retire = MagicMock(return_value=True)
    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home, keep_port=4781)

    assert retired == []
    retire.assert_not_called()


def test_retire_all_without_authenticated_state_or_enumeration_is_inert(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [],
    )
    retire = MagicMock(return_value=True)
    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home)

    assert retired == []
    retire.assert_not_called()


def test_ephemeral_guard_daemon_state_paths_only_scan_pytest_roots_and_honor_limit(tmp_path, monkeypatch):
    pytest_root = tmp_path / "pytest-of-user"
    first_state = pytest_root / "pytest-1" / "case-a" / "home" / "daemon-state.json"
    second_state = pytest_root / "pytest-2" / "case-b" / "home" / "daemon-state.json"
    third_state = pytest_root / "pytest-3" / "case-c" / "home" / "daemon-state.json"
    ignored_state = tmp_path / "unrelated-tool" / "daemon-state.json"
    for path in (first_state, second_state, third_state, ignored_state):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(daemon_manager_module, "_EPHEMERAL_GUARD_DAEMON_MAX_STATES", 2)

    results = daemon_manager_module._ephemeral_guard_daemon_state_paths(tmp_path)

    assert results == [first_state, second_state]
    assert ignored_state not in results


def test_windows_guard_daemon_pid_matches_command(tmp_path, monkeypatch):
    expected_guard_home = tmp_path / "guard home"
    parsed_command = [
        "python",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "daemon",
        "--serve",
        "--guard-home",
        str(expected_guard_home),
        "--port",
        "4781",
    ]
    command = subprocess.list2cmdline(parsed_command)
    captured_pids: list[tuple[int, int]] = []
    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(
        daemon_manager_module,
        "windows_command_line_to_argv",
        lambda raw_command: parsed_command if raw_command == command else None,
    )

    def native_command_line(pid: int, *, max_command_line_bytes: int) -> str:
        captured_pids.append((pid, max_command_line_bytes))
        return command

    monkeypatch.setattr(
        daemon_manager_module.windows_processes,
        "windows_process_command_line",
        native_command_line,
    )

    assert daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=expected_guard_home,
    )
    assert not daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=tmp_path / "other-home",
    )
    assert captured_pids == [
        (12345, daemon_manager_module._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES),
        (12345, daemon_manager_module._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES),
    ]


def test_guard_daemon_pid_matches_command_accepts_console_script_launch(tmp_path, monkeypatch):
    expected_guard_home = tmp_path / "guard-home"
    command = (
        "/Users/test/.local/pipx/venvs/hol-guard/bin/python "
        "/Users/test/.local/bin/hol-guard guard daemon --serve "
        f"--guard-home {expected_guard_home} --port 5474"
    )

    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_command_for_pid",
        lambda _pid: command,
    )

    assert daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=expected_guard_home,
    )
    assert not daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=tmp_path / "other-home",
    )


def test_guard_daemon_start_lock_prevents_concurrent_starts(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)

    events: list[str] = []
    errors: list[Exception] = []
    t1_entered = threading.Event()
    release_holder = threading.Event()

    def holder() -> None:
        try:
            with daemon_manager_module._guard_daemon_start_lock(guard_home):
                events.append("t1-entered")
                t1_entered.set()
                release_holder.wait(timeout=5)
                events.append("t1-exited")
        except Exception as exc:
            errors.append(exc)

    def waiter() -> None:
        try:
            with daemon_manager_module._guard_daemon_start_lock(guard_home):
                events.append("t2-entered")
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=holder)
    t1.start()
    t1_entered.wait(timeout=5)
    t2 = threading.Thread(target=waiter)
    t2.start()
    release_holder.set()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not errors, f"Lock worker raised: {errors}"
    assert events.index("t1-exited") < events.index("t2-entered"), (
        "Second thread entered before first released the lock"
    )


def test_guard_daemon_start_lock_file_created_and_released(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    lock_path = guard_home / "daemon-start.lock"

    assert not lock_path.exists()

    with daemon_manager_module._guard_daemon_start_lock(guard_home):
        assert lock_path.exists()

    assert lock_path.exists()


def test_guard_daemon_start_lock_recovers_after_exception(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)

    raised = False
    try:
        with daemon_manager_module._guard_daemon_start_lock(guard_home):
            raised = True
            raise RuntimeError("simulated crash")
    except RuntimeError:
        pass

    assert raised

    acquired = False
    with daemon_manager_module._guard_daemon_start_lock(guard_home):
        acquired = True
    assert acquired, "Lock was not released after exception; stale lock not recoverable"


@pytest.mark.skipif(os.name != "nt", reason="requires the native Windows command-line parser")
def test_windows_command_line_to_argv_round_trips_native_quoting() -> None:
    arguments = [
        r"C:\Program Files\Python 3.12\python.exe",
        "-m",
        "codex_plugin_scanner.cli",
        "--guard-home",
        "C:\\Users\\深紫色\\Guard Home\\nested\\",
        "--payload",
        r"alpha\\beta\\gamma",
    ]

    parsed = windows_paths_module.windows_command_line_to_argv(subprocess.list2cmdline(arguments))

    assert parsed == arguments


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ({"argv": ["guard.exe", "--status"]}, ["guard.exe", "--status"]),
        ({"argv": []}, None),
        ({"argv": None}, None),
        ({"argv": ["guard.exe", 7]}, None),
        ({}, None),
        (None, None),
    ],
)
def test_windows_command_line_to_argv_keeps_only_a_split_the_runtime_made(
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object] | None,
    expected: list[str] | None,
) -> None:
    requests = _fake_lifecycle_runtime(monkeypatch, answer)

    assert windows_paths_module.windows_command_line_to_argv("guard.exe --status") == expected
    assert requests == [{"op": "command_line_to_argv", "command": "guard.exe --status"}]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process handles")
def test_windows_exact_creation_time_termination_rejects_pid_reuse() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        creation_time = windows_paths_module.windows_process_creation_time(process.pid)
        assert isinstance(creation_time, int) and creation_time > 0

        assert not windows_paths_module.windows_terminate_process_if_creation_time(
            process.pid,
            creation_time ^ 1,
        )
        time.sleep(0.05)
        assert process.poll() is None

        assert windows_paths_module.windows_terminate_process_if_creation_time(process.pid, creation_time)
        process.wait(timeout=2.0)
        assert process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2.0)


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "waitid"), reason="requires POSIX waitid")
def test_daemon_death_wait_observes_exact_exited_child_without_poll_delay(monkeypatch) -> None:
    process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(17)"])
    try:
        os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
        assert daemon_manager_module._guard_daemon_pid_is_running(process.pid)

        def unexpected_sleep(_seconds: float) -> None:
            pytest.fail("An exited daemon must not consume a signal grace period")

        monkeypatch.setattr(daemon_manager_module.time, "sleep", unexpected_sleep)
        assert daemon_manager_module._wait_for_guard_daemon_pid_death(process.pid)
        assert daemon_manager_module._guard_daemon_pid_is_proven_dead(process.pid)
        assert process.wait(timeout=5) == 17
    finally:
        process.wait(timeout=5)


@pytest.mark.skipif(
    sys.platform != "linux"
    or not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")),
    reason="requires POSIX waitid",
)
def test_daemon_cleanup_reaps_only_verified_direct_child() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    reaped = False
    process_start_marker = daemon_manager_module.process_start_token(process.pid)
    process_owner = daemon_manager_module.process_owner_marker(process.pid)
    assert isinstance(process_start_marker, str) and process_start_marker
    assert isinstance(process_owner, str) and process_owner
    try:
        os.kill(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + 5.0
        while not daemon_manager_module._guard_daemon_pid_is_proven_dead(process.pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert daemon_manager_module._guard_daemon_pid_is_proven_dead(process.pid)
        assert daemon_manager_module._guard_daemon_pid_is_running(process.pid)
        assert _reap_verified_posix_direct_child(
            process.pid,
            start_marker=process_start_marker,
            owner=process_owner,
        )
        reaped = True
        assert not daemon_manager_module._guard_daemon_pid_is_running(process.pid)
    finally:
        if not reaped:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX child processes")
def test_daemon_death_wait_preserves_live_child_and_non_child() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert not daemon_manager_module._wait_for_guard_daemon_pid_death(process.pid, timeout=0)
        assert process.poll() is None
        assert not daemon_manager_module._wait_for_guard_daemon_pid_death(os.getpid(), timeout=0)
    finally:
        process.terminate()
        process.wait(timeout=5)


@pytest.mark.parametrize("pid", (0, -1, -42))
def test_daemon_child_exit_probe_never_waits_for_a_process_group(monkeypatch, pid: int) -> None:
    def unexpected_wait(*_args: object) -> tuple[int, int]:
        pytest.fail("Only an exact positive daemon PID can be observed")

    monkeypatch.setattr(daemon_manager_module.os, "waitid", unexpected_wait, raising=False)
    assert not daemon_manager_module._guard_daemon_child_has_exited(pid)


@pytest.mark.parametrize("outcome", (None, "wrong-pid", "stopped", "error"))
def test_daemon_child_exit_probe_preserves_uncertain_liveness(monkeypatch, outcome: str | None) -> None:
    proxy = _PosixOSProxy()
    monkeypatch.setattr(daemon_manager_module, "os", proxy)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    for name, value in (
        ("P_PID", 1),
        ("WEXITED", 4),
        ("WNOHANG", 1),
        ("WNOWAIT", 8),
        ("CLD_EXITED", 1),
        ("CLD_KILLED", 2),
        ("CLD_DUMPED", 3),
    ):
        monkeypatch.setattr(proxy, name, value, raising=False)

    def observe(*_args: object) -> object:
        if outcome == "error":
            raise PermissionError("unavailable process status")
        if outcome is None:
            return None
        return SimpleNamespace(
            si_pid=1235 if outcome == "wrong-pid" else 1234, si_code=4 if outcome == "stopped" else proxy.CLD_EXITED
        )

    monkeypatch.setattr(proxy, "waitid", observe, raising=False)
    assert not daemon_manager_module._guard_daemon_pid_is_proven_dead(1234)


def test_daemon_child_exit_probe_preserves_platform_without_waitid(monkeypatch) -> None:
    class WithoutWaitid(_PosixOSProxy):
        def __getattr__(self, name: str):
            if name == "waitid":
                raise AttributeError(name)
            return super().__getattr__(name)

    monkeypatch.setattr(daemon_manager_module, "os", WithoutWaitid())
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    assert not daemon_manager_module._guard_daemon_pid_is_proven_dead(1234)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: False)
    assert daemon_manager_module._guard_daemon_pid_is_proven_dead(1234)


def test_posix_daemon_retirement_waits_for_sigkill_to_finish(monkeypatch) -> None:
    pid = 62_223
    signals: list[int] = []
    waits = iter((False, True))
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:terminate-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda _pid: next(waits),
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda _pid, sig: signals.append(sig))

    assert (
        daemon_manager_module._retire_guard_daemon_pid(
            pid,
            expected_start_marker="linux:terminate-generation",
            expected_owner_marker="uid:501",
        )
        is True
    )
    assert signals == [signal.SIGTERM, sigkill]


@pytest.mark.parametrize("failing_signal", (signal.SIGTERM, getattr(signal, "SIGKILL", 9)))
def test_posix_daemon_retirement_does_not_accept_signal_permission_error(monkeypatch, failing_signal) -> None:
    pid = 62_224
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module.signal, "SIGKILL", sigkill, raising=False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args: True)
    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", lambda _pid: False)

    def deny_signal(_pid: int, sent_signal: int) -> None:
        if sent_signal == failing_signal:
            raise PermissionError("signal denied")

    monkeypatch.setattr(daemon_manager_module.os, "kill", deny_signal)

    assert daemon_manager_module._retire_guard_daemon_pid(pid) is False


def test_malformed_windows_lifecycle_records_remain_when_inventory_is_unknown(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state_path = daemon_manager_module._state_path(guard_home)
    state_path.write_bytes(b"{broken-state")

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: None,
    )

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []
    assert state_path.read_bytes() == b"{broken-state"
    assert not (guard_home / "daemon-state.invalid.json").exists()


def test_windows_daemon_inventory_uses_native_api(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard home"
    captured: dict[str, object] = {}
    daemon_parts = [
        "python.exe",
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "daemon",
        "--serve",
        "--guard-home",
        str(guard_home),
        "--port",
        "5410",
    ]

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "windows_command_line_to_argv", lambda _command: daemon_parts)

    def native_inventory(**kwargs: object) -> list[tuple[int, str]]:
        captured.update(kwargs)
        return [(63_333, "native command line")]

    monkeypatch.setattr(
        daemon_manager_module.windows_processes,
        "windows_process_command_line_inventory",
        native_inventory,
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(guard_home) == [(63_333, 5410)]
    candidates = captured["candidate_executable_names"]
    assert isinstance(candidates, frozenset)
    assert {"hol-guard.exe", "plugin-guard.exe", "python.exe"}.issubset(candidates)
    assert captured["max_command_line_bytes"] == (daemon_manager_module._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_ignores_malformed_unrelated_process_with_guard_text(tmp_path, monkeypatch) -> None:
    command_line = '/Applications/Host UI.app/Contents/MacOS/Host turn-ended {"prompt":"guard daemon --serve'
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_fails_closed_for_malformed_python_guard_process(tmp_path, monkeypatch) -> None:
    command_line = '/usr/bin/python3 -m codex_plugin_scanner.cli guard daemon --serve "'
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_skips_serve_without_guard_home(tmp_path, monkeypatch) -> None:
    command_line = "/usr/local/bin/hol-guard daemon --serve --port 5474"
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_adopts_implicit_default_home(tmp_path, monkeypatch) -> None:
    default_home = tmp_path / "default-home"
    default_home.mkdir()
    monkeypatch.setattr(daemon_manager_module, "_implicit_daemon_guard_home", lambda: default_home)
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: "123 /usr/local/bin/hol-guard daemon --serve --port 5474\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(default_home) == [(123, 5474)]
    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_parses_equals_guard_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 /usr/local/bin/hol-guard daemon --serve --guard-home={tmp_path} --port 5474\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == [(123, 5474)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_fails_closed_for_equals_home_without_port(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 /usr/local/bin/hol-guard daemon --serve --guard-home={tmp_path}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
@pytest.mark.parametrize("port_args", ["", " --port 0", " --port=0"])
def test_daemon_inventory_admits_own_dynamic_port_but_preserves_unknown_competitor(tmp_path, monkeypatch, port_args):
    current = os.getpid()
    command = f"/usr/local/bin/hol-guard daemon --serve --guard-home={tmp_path}{port_args}"
    query = MagicMock(return_value=f"{current} {command}\n")
    monkeypatch.setattr(daemon_manager_module.posix_processes, "posix_process_inventory", query)
    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []
    query.return_value = f"{current} {command}\n{current + 1000} {command}\n"
    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX frozen bootloader coverage")
@pytest.mark.parametrize("trusted", [False, True])
def test_dynamic_bootloader_parent_requires_existing_exact_identity_proof(tmp_path, monkeypatch, trusted):
    from codex_plugin_scanner.guard import frozen_daemon_runtime

    parent = os.getppid()
    command = f"/usr/local/bin/hol-guard daemon --serve --guard-home={tmp_path} --port 0"
    monkeypatch.setattr(daemon_manager_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        daemon_manager_module.posix_processes, "posix_process_inventory", lambda: f"{parent} {command}\n"
    )
    proof = MagicMock(return_value=parent if trusted else None)
    monkeypatch.setattr(frozen_daemon_runtime, "_trusted_frozen_bootloader_parent_pid", proof)
    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == ([] if trusted else None)
    proof.assert_called_once_with(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_ignores_bounded_hook_launcher(tmp_path, monkeypatch) -> None:
    command_line = (
        "/usr/local/bin/hol-guard __guard-bounded-hook "
        '{"python_executable":"/usr/local/bin/hol-guard","cli_args":["guard","hook"]}'
    )
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_fails_closed_for_matching_home_without_port(tmp_path, monkeypatch) -> None:
    command_line = f"/usr/local/bin/hol-guard daemon --serve --guard-home {tmp_path}"
    monkeypatch.setattr(
        daemon_manager_module.posix_processes,
        "posix_process_inventory",
        lambda: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="Windows argv parsing has no unterminated-quote failure")
@pytest.mark.parametrize(
    "command_line",
    (
        '"C:\\Program Files\\HOL Guard\\hol-guard.exe" --_hol-guard-daemon-serve "{broken',
        '"C:\\Program Files\\HOL Guard\\hol-guard.exe --_hol-guard-daemon-serve {broken',
    ),
)
def test_malformed_frozen_guard_command_with_quoted_executable_fails_closed(command_line: str, tmp_path, monkeypatch):
    monkeypatch.setattr(
        daemon_manager_module.posix_processes, "posix_process_inventory", lambda: f"123 {command_line}\n"
    )
    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(b"{}", True), (b"{}\n", False), (b"{ }", False), (b" {}", False)],
)
def test_daemon_lifecycle_tombstone_requires_exact_canonical_bytes(tmp_path, raw, expected) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    state_path = daemon_manager_module._state_path(guard_home)
    state_path.write_bytes(raw)

    assert daemon_manager_module._daemon_lifecycle_artifact_is_exact_tombstone(state_path) is expected


def test_authenticated_state_clear_compares_full_signed_snapshot_under_lock(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    expected_state = {"pid": 65_555, "port": 5410, "state_id": "old", "signature": "old-signature"}
    replacement_state = {**expected_state, "state_id": "new", "signature": "new-signature"}
    write = MagicMock()

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_state_write_lock", lambda _home: nullcontext())
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_daemon_state",
        lambda _home: replacement_state,
    )
    monkeypatch.setattr(daemon_manager_module, "_write_private_atomic_text", write)

    assert not daemon_manager_module._clear_authenticated_guard_daemon_state_if_current(
        guard_home,
        expected_state=expected_state,
    )
    write.assert_not_called()


@pytest.mark.parametrize("state_text", ["{not-json", '{"pid": 12345, "port": 5410}'])
def test_guard_daemon_retirement_completeness_fails_closed_for_untrusted_nonempty_state(
    tmp_path,
    monkeypatch,
    state_text,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    daemon_manager_module._state_path(guard_home).write_text(state_text, encoding="utf-8")
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [],
    )

    assert not daemon_manager_module.guard_daemon_retirement_is_complete(guard_home)


def test_guard_daemon_retirement_completeness_accepts_explicitly_empty_state(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    daemon_manager_module._state_path(guard_home).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )

    assert daemon_manager_module.guard_daemon_retirement_is_complete(guard_home)

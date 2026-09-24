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
from typing import Any
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard import windows_paths as windows_paths_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.discovery import (
    authenticate_daemon_state,
    daemon_discovery_key_path,
    ensure_daemon_discovery_key,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
    verify_daemon_state,
)


def _write_subprocess_launch_wrapper(
    path: Path,
    *,
    source_root: Path,
    publish_handoff: bool,
    publish_containment_receipt: bool = False,
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
from codex_plugin_scanner.guard.daemon.discovery import authenticate_daemon_state, ensure_daemon_discovery_key
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
if {publish_containment_receipt!r}:
    launch_nonce = os.environ["HOL_GUARD_DAEMON_LAUNCH_NONCE"]
    launch_start_marker = process_start_token(os.getpid())
    launch_owner = process_owner_marker(os.getpid())
    if not isinstance(launch_start_marker, str) or not launch_start_marker:
        raise RuntimeError("launch start marker unavailable")
    if not isinstance(launch_owner, str) or not launch_owner:
        raise RuntimeError("launch owner marker unavailable")
    containment_payload = {{
        "state_kind": "daemon_launch_containment",
        "guard_home": str(guard_home),
        "launch_nonce": launch_nonce,
        "launch_generation": launch_nonce,
        "generation": launch_nonce,
        "launch_pid": os.getpid(),
        "launch_process_start_marker": launch_start_marker,
        "launch_owner": launch_owner,
        "pid": helper.pid,
        "process_start_marker": helper_start_marker,
        "owner": helper_owner,
    }}
    signed_containment = authenticate_daemon_state(
        containment_payload,
        discovery_key=ensure_daemon_discovery_key(guard_home),
    )
    containment_path = guard_home / "daemon-launch-containment.json"
    containment_path.write_text(json.dumps(signed_containment), encoding="utf-8")
    containment_path.chmod(0o600)
time.sleep(60)
"""
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o700)
    return path


def _write_real_production_launch_wrapper(path: Path, *, source_root: Path) -> Path:
    """Create a real daemon launch that stalls after the production worker spawn."""

    runtime_paths = [entry for entry in sys.path if entry]
    body = f"""
import sys
import time
from pathlib import Path

sys.path[:0] = {runtime_paths!r}
sys.path.insert(0, {str(source_root)!r})
from codex_plugin_scanner.guard.daemon.hook_process_spawner import spawn_hook_worker

if __name__ == "__main__":
    argv = sys.argv[1:]
    guard_home = Path(argv[argv.index("--guard-home") + 1]).resolve()
    guard_home.mkdir(parents=True, exist_ok=True)
    slot = spawn_hook_worker(guard_home)
    receipt_path = guard_home / "daemon-launch-containment.json"
    deadline = time.monotonic() + 10
    while not receipt_path.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
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


def _terminate_verified_posix_process_group(pid: int, *, start_marker: str, owner: str) -> None:
    """Signal a worker session only after exact identity and session ownership are proven."""

    if not daemon_manager_module._guard_daemon_pid_is_running(pid):
        return
    assert daemon_manager_module.process_start_token(pid) == start_marker
    assert daemon_manager_module.process_owner_marker(pid) == owner
    assert os.getpgid(pid) == pid
    with suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGTERM)
    if _wait_for_verified_process_death(pid, start_marker=start_marker, owner=owner):
        return
    assert daemon_manager_module._guard_daemon_pid_is_running(pid)
    assert daemon_manager_module.process_start_token(pid) == start_marker
    assert daemon_manager_module.process_owner_marker(pid) == owner
    assert os.getpgid(pid) == pid
    with suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)
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


def _disable_daemon_adoption(monkeypatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module,
        "_adopt_existing_guard_daemon",
        lambda _guard_home, **kwargs: None,
    )


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


def test_malformed_process_command_only_blocks_proven_daemon_launchers() -> None:
    pytest_command = "python -m pytest 'tests/test_guard_cli.py::test_guard_daemon --serve["
    daemon_command = (
        "python -I -c 'import runpy; runpy.run_module("
        " codex_plugin_scanner.cli guard daemon --serve --guard-home guard-home"
    )

    assert not daemon_manager_module._malformed_command_may_launch_guard(pytest_command)
    assert daemon_manager_module._malformed_command_may_launch_guard(daemon_command)
    assert daemon_manager_module._malformed_command_may_launch_guard(
        "hol-guard.exe --_hol-guard-daemon-serve '{broken'"
    )


def test_frozen_daemon_inventory_rejects_payload_resolution_errors(monkeypatch) -> None:
    parts = ["hol-guard.exe", daemon_manager_module.FROZEN_DAEMON_SERVE_ARG, "{}"]

    for error_type in (OSError, RuntimeError, TypeError, ValueError):

        def raise_error(_payload: str, error_type=error_type):
            raise error_type("malformed payload")

        monkeypatch.setattr(daemon_manager_module, "decode_frozen_daemon_serve_payload", raise_error)
        assert daemon_manager_module._frozen_daemon_serve_context(parts) is None


def test_frozen_daemon_launch_uses_signed_guard_executable(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_bytes(b"guard")
    executable.chmod(0o755)
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()

    monkeypatch.setattr(daemon_manager_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(daemon_manager_module.sys, "executable", str(executable))

    command = daemon_manager_module._guard_daemon_launch_command(
        guard_home,
        4781,
        home_dir=tmp_path,
    )

    assert command == [
        str(executable.resolve()),
        "daemon",
        "--serve",
        "--guard-home",
        str(guard_home),
        "--home",
        str(tmp_path.resolve()),
        "--port",
        "4781",
    ]
    assert "-c" not in command
    assert "-I" not in command


def test_frozen_daemon_launch_uses_signed_command_for_windows_gate(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_bytes(b"guard")
    executable.chmod(0o755)
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()

    monkeypatch.setattr(daemon_manager_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(daemon_manager_module.sys, "executable", str(executable))

    command = daemon_manager_module._guard_daemon_launch_command(
        guard_home,
        4781,
        home_dir=tmp_path,
        gate_on_stdin=True,
    )

    assert command[0] == str(executable.resolve())
    assert command[1] == "--_hol-guard-daemon-serve"
    assert json.loads(command[2]) == {
        "guard_home": str(guard_home.resolve()),
        "home_dir": str(tmp_path.resolve()),
        "port": 4781,
    }
    assert "-c" not in command
    assert "daemon" not in command


def test_frozen_private_daemon_command_is_inventory_compatible(tmp_path) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_bytes(b"guard")
    executable.chmod(0o755)
    guard_home = tmp_path / "guard home"
    home_dir = tmp_path / "user home"
    guard_home.mkdir()
    home_dir.mkdir()

    command = daemon_manager_module.frozen_daemon_serve_command(
        guard_home,
        home_dir,
        4781,
        executable=str(executable),
    )
    rendered_command = (
        subprocess.list2cmdline(list(command)) if os.name == "nt" else daemon_manager_module.shlex.join(command)
    )

    assert daemon_manager_module._guard_daemon_command_matches(rendered_command)
    assert daemon_manager_module._guard_home_from_command(rendered_command) == guard_home.resolve()
    assert daemon_manager_module._guard_daemon_port_from_command(rendered_command) == 4781

    tampered_payload = json.loads(command[2])
    tampered_payload["port"] = 0
    tampered_parts = (command[0], command[1], json.dumps(tampered_payload))
    tampered_command = (
        subprocess.list2cmdline(list(tampered_parts))
        if os.name == "nt"
        else daemon_manager_module.shlex.join(tampered_parts)
    )
    assert not daemon_manager_module._guard_daemon_command_matches(tampered_command)


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


@pytest.mark.skipif(os.name == "nt", reason="exercises the POSIX daemon process-adoption workflow")
def test_ensure_guard_daemon_quarantines_unsigned_legacy_state_before_adoption(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    daemon_manager_module._state_path(guard_home).write_text(
        json.dumps(
            {
                "guard_home": str(guard_home),
                "port": 4781,
                "pid": 12345,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            }
        ),
        encoding="utf-8",
    )
    retired: list[dict[str, object]] = []
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_process",
        lambda payload: retired.append(payload) or True,
    )

    def adopt_after_retirement(_guard_home: Path, **_kwargs: object) -> str:
        assert retired == []
        assert json.loads(daemon_manager_module._state_path(guard_home).read_text(encoding="utf-8")) == {}
        assert json.loads((guard_home / "daemon-state.invalid.json").read_text(encoding="utf-8"))["pid"] == 12345
        return "http://127.0.0.1:4782"

    monkeypatch.setattr(daemon_manager_module, "_adopt_existing_guard_daemon", adopt_after_retirement)
    monkeypatch.setattr(daemon_manager_module, "_retire_duplicate_guard_daemons", lambda *_args, **_kwargs: None)

    assert daemon_manager_module.ensure_guard_daemon(guard_home) == "http://127.0.0.1:4782"


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


@pytest.mark.parametrize(
    ("last_error", "expected"),
    [(87, False), (5, None), (1234, None)],
)
def test_windows_process_liveness_only_treats_invalid_pid_as_proven_dead(
    monkeypatch,
    last_error,
    expected,
) -> None:
    class FakeFunction:
        def __init__(self, result: object) -> None:
            self.result = result
            self.argtypes: list[object] = []
            self.restype: object | None = None

        def __call__(self, *_args: object) -> object:
            return self.result

    kernel32 = SimpleNamespace(
        OpenProcess=FakeFunction(None),
        WaitForSingleObject=FakeFunction(daemon_manager_module._WINDOWS_CREATE_NEW_PROCESS_GROUP),
        CloseHandle=FakeFunction(True),
    )
    monkeypatch.setattr(windows_paths_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(windows_paths_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(windows_paths_module.ctypes, "get_last_error", lambda: last_error, raising=False)

    assert windows_paths_module.windows_process_liveness(4321) is expected


def test_windows_process_liveness_wait_failure_is_unknown(monkeypatch) -> None:
    class FakeFunction:
        def __init__(self, result: object) -> None:
            self.result = result
            self.argtypes: list[object] = []
            self.restype: object | None = None

        def __call__(self, *_args: object) -> object:
            return self.result

    kernel32 = SimpleNamespace(
        OpenProcess=FakeFunction(1),
        WaitForSingleObject=FakeFunction(0xFFFFFFFF),
        CloseHandle=FakeFunction(True),
    )
    monkeypatch.setattr(windows_paths_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(windows_paths_module.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)

    assert windows_paths_module.windows_process_liveness(4321) is None


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
        start_timeout=daemon_manager_module.GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS,
        preferred_port=4781,
        allow_windows_job_breakaway=True,
    )


def test_guard_daemon_port_from_command_supports_equals_syntax() -> None:
    command = "python -m codex_plugin_scanner.cli guard daemon --serve --guard-home /tmp/guard-home --port=5474"
    assert daemon_manager_module._guard_daemon_port_from_command(command) == 5474


def test_running_guard_daemon_processes_for_guard_home_returns_empty_on_ps_timeout(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"

    monkeypatch.setattr(daemon_manager_module, "_bounded_process_query_stdout", lambda *_args, **_kwargs: None)

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
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda *_args, **_kwargs: f"12345 {command}\n",
    )

    assert daemon_manager_module._running_guard_daemon_processes_for_guard_home(guard_home) == [(12345, 5474)]


def test_guard_daemon_command_matches_accepts_console_script_shortcuts() -> None:
    assert daemon_manager_module._guard_daemon_command_matches(
        "/Users/test/.local/bin/hol-guard daemon --serve --guard-home /tmp/guard-home --port 5474"
    )
    assert daemon_manager_module._guard_daemon_command_matches(
        "/Users/test/.local/bin/plugin-guard daemon --serve --guard-home /tmp/guard-home --port 5474"
    )


def test_ensure_guard_daemon_reuses_inflight_pid_before_respawning(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    responses = iter((None, None, "http://127.0.0.1:5409"))

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_guard_daemon_url",
        lambda _guard_home, **kwargs: next(responses, "http://127.0.0.1:5409"),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_load_state",
        lambda _guard_home, **kwargs: {
            "pid": 12345,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": daemon_manager_module._current_guard_daemon_source_root(),
            "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        },
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not spawn a new daemon")),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5409"


@pytest.mark.skipif(os.name == "nt", reason="exercises POSIX process discovery and daemon adoption")
def test_ensure_guard_daemon_adopts_running_guard_daemon_before_respawning(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    observed_start_markers: list[int] = []
    observed_owner_markers: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home, **kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_adoptable_guard_daemon_ports", lambda _guard_home, **kwargs: [5474])
    monkeypatch.setattr(
        daemon_manager_module,
        "_initialize_existing_guard_daemon",
        lambda _guard_home, port: {"url": f"http://127.0.0.1:{port}", "auth_token": "secret-token", "pid": 111},
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "process_start_token",
        lambda pid: observed_start_markers.append(pid) or "adopted-start-marker",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "process_owner_marker",
        lambda pid: observed_owner_markers.append(pid) or "adopted-owner",
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not spawn a new daemon")),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home, **kwargs: [],
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5474"
    assert daemon_manager_module.load_guard_daemon_auth_token(guard_home) == "secret-token"
    state_payload = json.loads(daemon_manager_module._state_path(guard_home).read_text(encoding="utf-8"))
    assert state_payload["port"] == 5474
    assert state_payload["pid"] == 111
    assert state_payload["process_start_marker"] == "adopted-start-marker"
    assert state_payload["owner"] == "adopted-owner"
    assert observed_start_markers == [111]
    assert observed_owner_markers == [111]


def test_adopt_existing_guard_daemon_skips_scan_on_windows(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"

    monkeypatch.setattr(daemon_manager_module.os, "name", "nt", raising=False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_initialize_existing_guard_daemon",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not attempt adoption")),
    )

    url = daemon_manager_module._adopt_existing_guard_daemon(guard_home)

    assert url is None


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


@pytest.mark.skipif(
    os.name == "nt",
    reason="its fake Popen omits the native Windows process identity required by daemon launch",
)
def test_ensure_guard_daemon_serializes_parallel_start_attempts(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    launched_envs: list[dict[str, str]] = []
    launched_event = threading.Event()
    barrier = threading.Barrier(8)

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)

    def fake_load_guard_daemon_url(_guard_home):
        if launched_event.is_set():
            return "http://127.0.0.1:5410"
        return None

    def fake_popen(command, **_kwargs):
        launched_commands.append(list(command))
        launched_envs.append(dict(_kwargs["env"]))
        launched_event.set()
        return SimpleNamespace()

    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5410])
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    results: list[str] = []
    failures: list[str] = []

    def worker() -> None:
        try:
            barrier.wait()
            results.append(daemon_manager_module.ensure_guard_daemon(guard_home))
        except Exception as exc:  # pragma: no cover - test assertion path
            failures.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert failures == []
    assert results == ["http://127.0.0.1:5410"] * 8
    assert len(launched_commands) == 1
    assert launched_commands[0][-2:] == ["--port", "5410"]
    assert "-I" in launched_commands[0]
    assert "-S" in launched_commands[0]
    if sys.version_info >= (3, 11):
        assert "-P" in launched_commands[0]
    else:
        assert "-P" not in launched_commands[0]
    assert daemon_manager_module._GUARD_DAEMON_BOOTSTRAP in launched_commands[0]
    assert "PYTHONPATH" not in launched_envs[0]
    assert launched_envs[0]["PYTHONNOUSERSITE"] == "1"
    assert launched_envs[0]["PYTHONSAFEPATH"] == "1"


@pytest.mark.skipif(
    os.name == "nt",
    reason="its fake Popen omits the native Windows process identity required by daemon launch",
)
def test_ensure_guard_daemon_advances_ports_after_early_process_exit(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    poll_count = {"value": 0}

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)

    class FakeProcess:
        def __init__(self, *, alive: bool) -> None:
            self._alive = alive

        def poll(self) -> int | None:
            if self._alive:
                return None
            return 1

    def fake_load_guard_daemon_url(_guard_home):
        if poll_count["value"] < 4:
            poll_count["value"] += 1
            return None
        return "http://127.0.0.1:5411"

    def fake_popen(command, **_kwargs):
        launched_commands.append(list(command))
        return FakeProcess(alive=len(launched_commands) > 1)

    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5410, 5411])
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5411"
    assert [command[-1] for command in launched_commands] == ["5410", "5411"]


def test_ensure_guard_daemon_accepts_nonce_bound_default_launch_handoff_only_for_launcher_pid(
    tmp_path,
    monkeypatch,
):
    """The default launch path must bind a signed handoff to its Popen PID."""

    guard_home = tmp_path / "guard-home"
    port = 5_416
    launch_pid = 54_216
    process_marker = "launcher-generation"
    process_owner = "test-owner"

    class FakeProcess:
        pid = launch_pid
        stdin = None

        def __init__(self) -> None:
            self.terminated = False

        def poll(self) -> int | None:
            return 0 if self.terminated else None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, *, timeout: float) -> int:
            del timeout
            return 0

    process = FakeProcess()
    record_pending_launch = daemon_manager_module._record_guard_daemon_pending_launch

    def record_pending(*_args, launch, port: int, **_kwargs):
        pending_creation_time = record_pending_launch(
            guard_home,
            launch=launch,
            port=port,
        )
        monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, launch.launch_nonce)
        try:
            daemon_manager_module.write_guard_daemon_state(
                guard_home,
                port,
                "test-token",
                pid=launch.process.pid,
            )
        finally:
            monkeypatch.delenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, raising=False)
        return pending_creation_time

    original_handoff_match = daemon_manager_module._guard_daemon_handoff_matches_launch
    observed_handoffs: list[tuple[int, str, int | None]] = []

    def observe_handoff_match(
        handoff_home: Path,
        *,
        launch_nonce: str,
        expected_pid: int,
        expected_port: int | None = None,
    ) -> bool:
        observed_handoffs.append((expected_pid, launch_nonce, expected_port))
        return original_handoff_match(
            handoff_home,
            launch_nonce=launch_nonce,
            expected_pid=expected_pid,
            expected_port=expected_port,
        )

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _guard_home: False)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **_kwargs: [port])
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_launch_command",
        lambda *_args, **_kwargs: ["guard-daemon"],
    )
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(daemon_manager_module, "_record_guard_daemon_pending_launch", record_pending)
    monkeypatch.setattr(daemon_manager_module, "_release_guard_daemon_launch_gate", lambda _process: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_spawned_guard_daemon_pending_launch",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "load_guard_daemon_url",
        lambda _guard_home: f"http://127.0.0.1:{port}"
        if daemon_manager_module._pending_launch_path(guard_home).is_file()
        else None,
    )
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: process_marker)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: process_owner)
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: 13_371)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_handoff_matches_launch", observe_handoff_match)

    url = daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=1.0)

    assert url == f"http://127.0.0.1:{port}"
    assert observed_handoffs
    assert {expected_pid for expected_pid, _nonce, _port in observed_handoffs} == {launch_pid}
    pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
    assert pending is not None
    assert {nonce for _pid, nonce, _port in observed_handoffs} == {pending["launch_nonce"]}
    assert not original_handoff_match(
        guard_home,
        launch_nonce=str(pending["launch_nonce"]),
        expected_pid=launch_pid + 1,
        expected_port=port,
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason="its fake Popen omits the native Windows process identity required by daemon launch",
)
def test_ensure_guard_daemon_uses_one_start_deadline_across_candidate_ports(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_ports: list[str] = []
    clock = {"value": 100.0}

    class FakeProcess:
        pid = 54_210

        def poll(self) -> None:
            return None

    def fake_wait(
        _guard_home: Path,
        *,
        timeout: float,
        process: FakeProcess | None = None,
        **_kwargs: object,
    ) -> None:
        del process
        clock["value"] += timeout
        return None

    def fake_popen(command, **_kwargs):
        launched_ports.append(command[-1])
        return FakeProcess()

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **_kwargs: [5410, 5411, 5412])
    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_url", fake_wait)
    monkeypatch.setattr(daemon_manager_module, "_record_guard_daemon_pending_launch", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_spawned_guard_daemon_pending_launch",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(daemon_manager_module, "_terminate_spawned_guard_daemon", lambda _process: True)
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "monotonic", lambda: clock["value"])

    with pytest.raises(RuntimeError, match="approval center did not start"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=5.0)

    assert launched_ports == ["5410"]


def test_ensure_guard_daemon_does_not_terminate_handed_off_process_on_pending_clear_failure(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    terminated: list[object] = []

    class FakeProcess:
        pid = 54_214
        stdin = None

        def poll(self) -> None:
            return None

    process = FakeProcess()
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **_kwargs: [5414])
    monkeypatch.setattr(daemon_manager_module, "_record_guard_daemon_pending_launch", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_release_guard_daemon_launch_gate", lambda _process: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_started_guard_daemon_url",
        lambda *_args, **_kwargs: "http://127.0.0.1:5414",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_spawned_guard_daemon_pending_launch",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_terminate_spawned_guard_daemon",
        lambda value: terminated.append(value) or True,
    )
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(RuntimeError, match="pending launch state could not be cleared safely"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=5.0)

    assert terminated == []


def test_ensure_guard_daemon_timeout_does_not_kill_unattributed_descendant_processes(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"

    class FakeDescendant:
        terminated = False

    descendant = FakeDescendant()

    class FakeProcess:
        pid = 54_215
        stdin = None
        children = (descendant,)

        def __init__(self) -> None:
            self.terminated = False

        def poll(self) -> int | None:
            return 0 if self.terminated else None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, *, timeout: float) -> int:
            del timeout
            return 0

        def kill(self) -> None:
            self.terminated = True

    process = FakeProcess()
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    monkeypatch.setattr(daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **_kwargs: [5415])

    def record_pending_receipt(*_args, launch, **_kwargs):
        del _args, _kwargs
        assert launch.process is process
        assert launch.launch_nonce
        assert launch.deadline > 0
        launch.receipt_recorded = True
        return None

    monkeypatch.setattr(daemon_manager_module, "_record_guard_daemon_pending_launch", record_pending_receipt)
    monkeypatch.setattr(daemon_manager_module, "_release_guard_daemon_launch_gate", lambda _process: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_started_guard_daemon_url",
        lambda *_args, **_kwargs: None,
    )
    pending_clear_calls: list[object] = []
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_spawned_guard_daemon_pending_launch",
        lambda *args, **kwargs: pending_clear_calls.append((args, kwargs)) or True,
    )
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(RuntimeError, match="ownership could not be proven contained"):
        daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=5.0)

    assert process.terminated is True
    # A child visible only through an untrusted/mock relationship is not owned
    # by this launch.  The real subprocess boundary test covers the durable
    # pending receipt that keeps replacement fail closed in this case.
    assert descendant.terminated is False
    assert pending_clear_calls == []


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX setsid subprocesses")
def test_real_timeout_keeps_escaped_helper_and_blocks_replacement_until_receipt_is_resolved(tmp_path):
    """An unreported setsid child keeps the launch receipt permanently fail closed."""

    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "user-home"
    guard_home.mkdir()
    home_dir.mkdir()
    wrapper = _write_subprocess_launch_wrapper(
        tmp_path / "launch-with-escaped-helper",
        source_root=Path(daemon_manager_module.__file__).resolve().parents[3],
        publish_handoff=False,
    )

    helper_identity: tuple[int, str, str] | None = None
    try:
        with pytest.raises(RuntimeError, match="approval center did not start"):
            daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=wrapper,
                start_timeout=20.0,
            )

        helper_pid_path = guard_home / "escaped-helper.pid"
        assert helper_pid_path.is_file()
        helper_identity = _load_escaped_helper_receipt(guard_home)
        assert helper_identity is not None
        helper_pid, helper_start_marker, helper_owner = helper_identity
        assert int(helper_pid_path.read_text(encoding="utf-8")) == helper_pid
        assert daemon_manager_module._guard_daemon_pid_is_running(helper_pid)
        assert daemon_manager_module.process_start_token(helper_pid) == helper_start_marker
        assert daemon_manager_module.process_owner_marker(helper_pid) == helper_owner

        pending_path = daemon_manager_module._pending_launch_path(guard_home)
        pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
        assert pending is not None
        assert pending_path.is_file()
        assert pending["pid"] > 0
        assert pending["launch_nonce"]
        assert pending["launch_generation"] == pending["launch_nonce"]
        assert pending["generation"] == pending["launch_nonce"]
        assert pending["guard_home"] == str(guard_home.resolve())

        with pytest.raises(RuntimeError, match="previous Guard daemon launch could not be retired safely"):
            daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=wrapper,
                start_timeout=5.0,
            )
    finally:
        if helper_identity is None:
            helper_identity = _load_escaped_helper_receipt(guard_home)
        if helper_identity is not None:
            _terminate_verified_posix_process(
                helper_identity[0],
                start_marker=helper_identity[1],
                owner=helper_identity[2],
            )

    # The current launch protocol has no controlled child receipt to prove
    # that this separately-created session belonged to the launch. Exact
    # helper death therefore does not make replacement safe by itself.
    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)
    with pytest.raises(RuntimeError, match="previous Guard daemon launch could not be retired safely"):
        daemon_manager_module.ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            executable=wrapper,
            start_timeout=5.0,
        )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX subprocess identity markers")
def test_real_dead_nonce_bound_escaped_helper_reconciles_at_retry_boundary(tmp_path):
    """A signed child generation permits retry only after exact child death."""

    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "user-home"
    guard_home.mkdir()
    home_dir.mkdir()
    escaped_wrapper = _write_subprocess_launch_wrapper(
        tmp_path / "launch-with-contained-escaped-helper",
        source_root=Path(daemon_manager_module.__file__).resolve().parents[3],
        publish_handoff=False,
        publish_containment_receipt=True,
    )
    handoff_wrapper = _write_subprocess_launch_wrapper(
        tmp_path / "launch-after-contained-helper-exit",
        source_root=Path(daemon_manager_module.__file__).resolve().parents[3],
        publish_handoff=True,
    )

    helper_identity: tuple[int, str, str] | None = None
    process_identity: tuple[int, str, str] | None = None
    try:
        with pytest.raises(RuntimeError, match="ownership could not be proven contained"):
            daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=escaped_wrapper,
                start_timeout=20.0,
            )

        helper_identity = _load_escaped_helper_receipt(guard_home)
        assert helper_identity is not None
        helper_pid, helper_start_marker, helper_owner = helper_identity
        assert daemon_manager_module._guard_daemon_pid_is_running(helper_pid)
        assert daemon_manager_module.process_start_token(helper_pid) == helper_start_marker
        assert daemon_manager_module.process_owner_marker(helper_pid) == helper_owner
        pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
        containment = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
        assert pending is not None
        assert containment is not None
        assert containment["launch_nonce"] == pending["launch_nonce"]
        assert containment["launch_pid"] == pending["pid"]
        assert containment["pid"] == helper_pid
        assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)

        with pytest.raises(RuntimeError, match="previous Guard daemon launch could not be retired safely"):
            daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=handoff_wrapper,
                start_timeout=5.0,
            )
        assert daemon_manager_module._guard_daemon_pid_is_running(helper_pid)
        assert daemon_manager_module.process_start_token(helper_pid) == helper_start_marker
        assert daemon_manager_module.process_owner_marker(helper_pid) == helper_owner

        _terminate_verified_posix_process(
            helper_pid,
            start_marker=helper_start_marker,
            owner=helper_owner,
        )

        url = daemon_manager_module.ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            executable=handoff_wrapper,
            start_timeout=45.0,
        )
        assert url.startswith("http://127.0.0.1:")
        assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is None
        state = load_authenticated_daemon_state(guard_home)
        assert state is not None
        process_pid = state["pid"]
        process_start_marker = state.get("process_start_marker")
        process_owner = state.get("owner", state.get("user"))
        assert isinstance(process_pid, int) and process_pid > 0
        assert isinstance(process_start_marker, str) and process_start_marker
        assert isinstance(process_owner, str) and process_owner
        process_identity = process_pid, process_start_marker, process_owner
    finally:
        if helper_identity is not None and daemon_manager_module._guard_daemon_pid_is_running(helper_identity[0]):
            _terminate_verified_posix_process(
                helper_identity[0],
                start_marker=helper_identity[1],
                owner=helper_identity[2],
            )
        if process_identity is not None:
            _terminate_verified_posix_process(
                process_identity[0],
                start_marker=process_identity[1],
                owner=process_identity[2],
            )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX worker process groups")
def test_real_production_worker_spawn_writes_containment_receipt_and_bounds_retry(tmp_path):
    """The real daemon worker boundary accounts for live escaped workers before retry."""

    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "user-home"
    guard_home.mkdir()
    home_dir.mkdir()
    production_wrapper = _write_real_production_launch_wrapper(
        tmp_path / "launch-real-daemon-workers",
        source_root=Path(daemon_manager_module.__file__).resolve().parents[3],
    )
    handoff_wrapper = _write_subprocess_launch_wrapper(
        tmp_path / "launch-after-real-worker-exit",
        source_root=Path(daemon_manager_module.__file__).resolve().parents[3],
        publish_handoff=True,
    )

    root_identity: tuple[int, str, str] | None = None
    worker_identities: list[tuple[int, str, str]] = []
    process_identity: tuple[int, str, str] | None = None
    try:
        with pytest.raises(RuntimeError, match="ownership could not be proven contained"):
            daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=production_wrapper,
                start_timeout=45.0,
            )

        pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
        containment = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
        assert pending is not None
        assert containment is not None
        assert containment["launch_nonce"] == pending["launch_nonce"]
        assert containment["launch_pid"] == pending["pid"]
        root_pid = pending["pid"]
        root_start_marker = pending["process_start_marker"]
        root_owner = pending["owner"]
        assert isinstance(root_pid, int)
        assert isinstance(root_start_marker, str) and root_start_marker
        assert isinstance(root_owner, str) and root_owner
        root_identity = root_pid, root_start_marker, root_owner

        children = containment.get("children")
        assert isinstance(children, list) and children
        for child in children:
            assert isinstance(child, dict)
            child_pid = child.get("pid")
            child_start_marker = child.get("process_start_marker")
            child_owner = child.get("owner")
            assert isinstance(child_pid, int) and child_pid > 0 and child_pid != root_pid
            assert isinstance(child_start_marker, str) and child_start_marker
            assert isinstance(child_owner, str) and child_owner == root_owner
            worker_identities.append((child_pid, child_start_marker, child_owner))

        retry_url: str | None = None
        try:
            retry_url = daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=handoff_wrapper,
                start_timeout=5.0,
            )
        except RuntimeError as error:
            assert "previous Guard daemon launch could not be retired safely" in str(error)
            for child_pid, child_start_marker, child_owner in worker_identities:
                if daemon_manager_module._guard_daemon_pid_is_running(child_pid):
                    _terminate_verified_posix_process_group(
                        child_pid,
                        start_marker=child_start_marker,
                        owner=child_owner,
                    )
            assert daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)
            assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is None
        else:
            assert daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)
            assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is None

        if retry_url is None:
            retry_url = daemon_manager_module.ensure_guard_daemon(
                guard_home,
                home_dir=home_dir,
                executable=handoff_wrapper,
                start_timeout=45.0,
            )
        url = retry_url
        assert url.startswith("http://127.0.0.1:")
        state = load_authenticated_daemon_state(guard_home)
        assert state is not None
        process_pid = state.get("pid")
        process_start_marker = state.get("process_start_marker")
        process_owner = state.get("owner", state.get("user"))
        assert isinstance(process_pid, int) and process_pid > 0
        assert isinstance(process_start_marker, str) and process_start_marker
        assert isinstance(process_owner, str) and process_owner
        process_identity = process_pid, process_start_marker, process_owner
    finally:
        for child_pid, child_start_marker, child_owner in worker_identities:
            if daemon_manager_module._guard_daemon_pid_is_running(child_pid):
                _terminate_verified_posix_process_group(
                    child_pid,
                    start_marker=child_start_marker,
                    owner=child_owner,
                )
        if root_identity is not None and daemon_manager_module._guard_daemon_pid_is_running(root_identity[0]):
            _terminate_verified_posix_process(
                root_identity[0],
                start_marker=root_identity[1],
                owner=root_identity[2],
            )
        if process_identity is not None:
            _terminate_verified_posix_process(
                process_identity[0],
                start_marker=process_identity[1],
                owner=process_identity[2],
            )


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


def _write_containment_pending_launch(
    guard_home: Path,
    *,
    launch_pid: int,
    launch_nonce: str,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[int, tuple[str, str]]:
    identities: dict[int, tuple[str, str]] = {
        launch_pid: ("launcher-generation", "test-owner"),
    }

    def process_start_marker(pid: int) -> str | None:
        identity = identities.get(pid)
        return identity[0] if identity is not None else None

    def process_owner(pid: int) -> str | None:
        identity = identities.get(pid)
        return identity[1] if identity is not None else None

    monkeypatch.setattr(daemon_manager_module, "process_start_token", process_start_marker)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", process_owner)
    # Windows binds pending launches to the native creation-time generation in
    # addition to the portable start marker and owner.  Keep synthetic PIDs
    # usable in the parent-bound fixture without probing the host process table.
    monkeypatch.setattr(
        daemon_manager_module,
        "windows_process_creation_time",
        lambda pid: 100_000_000 + pid if type(pid) is int and pid > 0 else None,
    )
    launch = SimpleNamespace(
        process=SimpleNamespace(pid=launch_pid),
        launch_nonce=launch_nonce,
        deadline=time.monotonic() + 1.0,
    )
    recorded_creation_time = daemon_manager_module._record_guard_daemon_pending_launch(
        guard_home,
        launch=launch,
        port=5_432,
    )
    if os.name == "nt":
        assert recorded_creation_time == 100_000_000 + launch_pid
    else:
        assert recorded_creation_time is None
    pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
    assert pending is not None
    if os.name == "nt":
        assert pending["process_creation_time"] == recorded_creation_time
    return identities


def test_record_guard_daemon_launch_containment_child_writes_direct_launcher_receipt(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 1
    nonce = "a" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)

    assert daemon_manager_module.record_guard_daemon_launch_containment_child(
        guard_home,
        pid=child_pid,
    )

    receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    assert receipt is not None
    assert receipt["launch_nonce"] == nonce
    assert receipt["launch_pid"] == launch_pid
    assert receipt["launch_process_start_marker"] == "launcher-generation"
    assert receipt["launch_owner"] == "test-owner"
    assert receipt["children"] == [
        {
            "pid": child_pid,
            "process_start_marker": "worker-generation",
            "owner": "test-owner",
        }
    ]
    assert "launch_parent_pid" not in receipt


def test_record_guard_daemon_launch_containment_child_writes_parent_bound_receipt(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    parent_pid = os.getpid() + 1_000
    launch_pid = parent_pid + 1
    child_pid = parent_pid + 2
    nonce = "b" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=parent_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[launch_pid] = ("child-launcher-generation", "test-owner")
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setattr(daemon_manager_module.os, "getpid", lambda: launch_pid)
    monkeypatch.setattr(daemon_manager_module.os, "getppid", lambda: parent_pid)
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)

    assert daemon_manager_module.record_guard_daemon_launch_containment_child(
        guard_home,
        pid=child_pid,
    )

    receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    assert receipt is not None
    assert receipt["launch_nonce"] == nonce
    assert receipt["launch_pid"] == launch_pid
    assert receipt["launch_process_start_marker"] == "child-launcher-generation"
    assert receipt["launch_parent_pid"] == parent_pid
    assert receipt["launch_parent_process_start_marker"] == "launcher-generation"
    assert receipt["launch_parent_owner"] == "test-owner"
    assert receipt["children"] == [
        {
            "pid": child_pid,
            "process_start_marker": "worker-generation",
            "owner": "test-owner",
        }
    ]


def test_record_guard_daemon_launch_containment_child_is_idempotent_for_duplicate_child(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 3
    nonce = "c" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)

    assert daemon_manager_module.record_guard_daemon_launch_containment_child(
        guard_home,
        pid=child_pid,
    )
    first_receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    assert first_receipt is not None

    assert daemon_manager_module.record_guard_daemon_launch_containment_child(
        guard_home,
        pid=child_pid,
    )
    second_receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    assert second_receipt is not None
    assert second_receipt["children"] == first_receipt["children"]


def test_record_guard_daemon_launch_containment_child_refuses_stale_nonce(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 4
    pending_nonce = "d" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=pending_nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setenv(
        daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV,
        "e" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH,
    )

    assert not daemon_manager_module.record_guard_daemon_launch_containment_child(
        guard_home,
        pid=child_pid,
    )
    assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is None


def test_record_guard_daemon_launch_containment_child_refuses_owner_mismatch(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 5
    nonce = "f" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "different-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)

    assert not daemon_manager_module.record_guard_daemon_launch_containment_child(
        guard_home,
        pid=child_pid,
    )
    assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is None


def test_record_guard_daemon_launch_containment_child_refuses_stale_receipt_for_new_generation(
    tmp_path,
    monkeypatch,
):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 6
    first_nonce = "1" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=first_nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, first_nonce)
    assert daemon_manager_module.record_guard_daemon_launch_containment_child(guard_home, pid=child_pid)
    first_receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    assert first_receipt is not None

    second_nonce = "2" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=second_nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, second_nonce)

    assert not daemon_manager_module.record_guard_daemon_launch_containment_child(guard_home, pid=child_pid)
    assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) == first_receipt


def test_spawn_hook_worker_records_containment_through_daemon_launch_caller(
    tmp_path,
    monkeypatch,
):
    """The production worker caller publishes the child generation into the launch receipt."""

    from codex_plugin_scanner.guard.daemon import hook_process_spawner

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 7
    nonce = "9" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)

    class FakeConnection:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        pid = child_pid

        def __init__(self) -> None:
            self.started = False

        def start(self) -> None:
            self.started = True

    parent_connection = FakeConnection()
    child_connection = FakeConnection()
    process = FakeProcess()

    class FakeContext:
        def Pipe(self, *, duplex: bool):  # noqa: N802
            assert duplex
            return parent_connection, child_connection

        def Process(self, *, target, args, name: str, daemon: bool):  # noqa: N802
            assert target is not None
            assert args[1] == str(guard_home)
            assert name == "hol-guard-hook-worker"
            assert daemon is False
            return process

    def get_context(method: str) -> FakeContext:
        assert method == "spawn"
        return FakeContext()

    monkeypatch.setattr(hook_process_spawner.multiprocessing, "get_context", get_context)

    slot = hook_process_spawner.spawn_hook_worker(guard_home)

    assert process.started
    assert child_connection.closed
    assert slot.process is process
    assert slot.connection is parent_connection
    receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    assert receipt is not None
    assert receipt["launch_nonce"] == nonce
    assert receipt["launch_pid"] == launch_pid
    assert receipt["children"] == [
        {
            "pid": child_pid,
            "process_start_marker": "worker-generation",
            "owner": "test-owner",
        }
    ]


def test_authenticated_pending_launch_loader_rejects_identity_gaps(tmp_path, monkeypatch):
    """A signed pending file still needs every generation identity field."""

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    nonce = "8" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
    discovery_key = load_daemon_discovery_key(guard_home)
    assert pending is not None
    assert discovery_key is not None

    pending_path = daemon_manager_module._pending_launch_path(guard_home)
    invalid_fields = [
        ("pid", "not-a-pid"),
        ("port", 0),
        ("guard_home", str(tmp_path / "other-home")),
        ("guard_home", None),
    ]
    if os.name == "nt":
        # Windows authenticates the native process creation generation at
        # load time; nonce and marker binding is enforced when the record is
        # admitted to a lifecycle operation.
        invalid_fields.append(("process_creation_time", 0))
    else:
        invalid_fields.extend(
            [
                ("launch_nonce", "short"),
                ("launch_generation", "mismatched-generation"),
                ("generation", "mismatched-generation"),
                ("process_start_marker", ""),
                ("owner", ""),
                ("runtime_fingerprint", ""),
            ]
        )
    for field, invalid_value in invalid_fields:
        candidate = dict(pending)
        candidate[field] = invalid_value
        candidate.pop("state_signature", None)
        authenticated = authenticate_daemon_state(candidate, discovery_key=discovery_key)
        pending_path.write_text(json.dumps(authenticated, sort_keys=True), encoding="utf-8")
        pending_path.chmod(0o600)
        assert daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home) is None, field


def test_pending_launch_reconciles_authenticated_containment_receipt_after_exact_death(
    tmp_path,
    monkeypatch,
):
    """Reconciliation clears both signed lifecycle artifacts only after exact death proofs."""

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 8
    nonce = "7" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)
    assert daemon_manager_module.record_guard_daemon_launch_containment_child(guard_home, pid=child_pid)

    observed_generations: list[tuple[int, str, str]] = []

    def exact_generation_is_dead(pid: int, *, process_start_marker: str, process_owner: str) -> bool:
        observed_generations.append((pid, process_start_marker, process_owner))
        return True

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_exact_generation_is_dead", exact_generation_is_dead)

    assert daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)
    assert observed_generations == [
        (launch_pid, "launcher-generation", "test-owner"),
        (launch_pid, "launcher-generation", "test-owner"),
        (child_pid, "worker-generation", "test-owner"),
    ]
    assert daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home) is None
    assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is None


def test_pending_launch_rejects_authenticated_containment_receipt_owner_reuse(
    tmp_path,
    monkeypatch,
):
    """A signed receipt with a recycled child owner cannot resolve a pending launch."""

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_pid = os.getpid()
    child_pid = launch_pid + 9
    nonce = "6" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    identities = _write_containment_pending_launch(
        guard_home,
        launch_pid=launch_pid,
        launch_nonce=nonce,
        monkeypatch=monkeypatch,
    )
    identities[child_pid] = ("worker-generation", "test-owner")
    monkeypatch.setenv(daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_ENV, nonce)
    assert daemon_manager_module.record_guard_daemon_launch_containment_child(guard_home, pid=child_pid)

    pending = daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home)
    receipt = daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home)
    discovery_key = load_daemon_discovery_key(guard_home)
    assert pending is not None
    assert receipt is not None
    assert discovery_key is not None
    receipt["children"] = [
        {
            "pid": child_pid,
            "process_start_marker": "worker-generation",
            "owner": "recycled-owner",
        }
    ]
    receipt.pop("state_signature", None)
    containment_path = guard_home / daemon_manager_module._GUARD_DAEMON_LAUNCH_CONTAINMENT_FILE
    containment_path.write_text(
        json.dumps(authenticate_daemon_state(receipt, discovery_key=discovery_key), sort_keys=True),
        encoding="utf-8",
    )
    containment_path.chmod(0o600)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_exact_generation_is_dead",
        lambda _pid, **_kwargs: True,
    )

    assert not daemon_manager_module._guard_daemon_pending_launch_state_is_resolved(guard_home)
    assert daemon_manager_module.load_authenticated_guard_daemon_pending_launch(guard_home) is not None
    assert daemon_manager_module._load_authenticated_guard_daemon_containment_receipt(guard_home) is not None


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


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX signal retirement and omits native Windows process creation identities",
)
def test_ensure_guard_daemon_retires_stale_daemon_from_different_runtime_fingerprint(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    killed: list[int] = []
    running = {"value": True}

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5412"
        return None

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(
        daemon_manager_module,
        "_load_state",
        lambda _guard_home, **kwargs: {
            "pid": 98765,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": daemon_manager_module._current_guard_daemon_source_root(),
            "runtime_fingerprint": "stale-runtime-fingerprint",
            "process_start_marker": "stale-start-marker",
            "user": "uid:501",
        },
    )
    observed_start_markers: list[int] = []
    monkeypatch.setattr(
        daemon_manager_module,
        "process_start_token",
        lambda pid: observed_start_markers.append(pid) or "stale-start-marker",
    )
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: running["value"])
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    def fake_kill(pid, _signal):
        killed.append(pid)
        running["value"] = False

    monkeypatch.setattr(daemon_manager_module.os, "kill", fake_kill)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5412])
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5412"
    assert killed == [98765]
    assert launched_commands[0][-2:] == ["--port", "5412"]
    assert observed_start_markers == [98765]


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


def test_runtime_fingerprint_ignores_mtime_and_tracks_content(tmp_path, monkeypatch):
    package = tmp_path / "codex_plugin_scanner" / "guard" / "daemon"
    package.mkdir(parents=True)
    target = package / "runtime.py"
    target.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(daemon_manager_module, "_current_guard_daemon_source_root", lambda: str(tmp_path))
    monkeypatch.setattr(
        daemon_manager_module,
        "_runtime_fingerprint_cache_path",
        lambda _source_root: tmp_path / "fp-cache" / "runtime-fingerprint-cache.json",
    )
    daemon_manager_module._runtime_fingerprint_cache = None
    try:
        first = daemon_manager_module._current_guard_daemon_runtime_fingerprint()
        os.utime(target, (1_700_000_000, 1_700_000_000))
        daemon_manager_module._runtime_fingerprint_cache = None
        second = daemon_manager_module._current_guard_daemon_runtime_fingerprint()
        assert first == second
        target.write_text("x = 2\n", encoding="utf-8")
        daemon_manager_module._runtime_fingerprint_cache = None
        third = daemon_manager_module._current_guard_daemon_runtime_fingerprint()
        assert third != first
    finally:
        daemon_manager_module._runtime_fingerprint_cache = None


def test_runtime_fingerprint_reuses_content_hash_when_tree_signature_matches(tmp_path, monkeypatch):
    package = tmp_path / "codex_plugin_scanner" / "guard" / "daemon"
    package.mkdir(parents=True)
    target = package / "runtime.py"
    target.write_text("x = 1\n", encoding="utf-8")
    cache_path = tmp_path / "fp-cache" / "runtime-fingerprint-cache.json"
    monkeypatch.setattr(daemon_manager_module, "_current_guard_daemon_source_root", lambda: str(tmp_path))
    monkeypatch.setattr(
        daemon_manager_module,
        "_runtime_fingerprint_cache_path",
        lambda _source_root: cache_path,
    )
    daemon_manager_module._runtime_fingerprint_cache = None
    opened_python: list[Path] = []
    real_open = Path.open

    def counting_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.suffix == ".py":
            opened_python.append(self)
        return real_open(self, *args, **kwargs)

    try:
        first = daemon_manager_module._current_guard_daemon_runtime_fingerprint()
        daemon_manager_module._runtime_fingerprint_cache = None
        monkeypatch.setattr(Path, "open", counting_open)
        second = daemon_manager_module._current_guard_daemon_runtime_fingerprint()
        assert first == second
        assert opened_python == []
        assert cache_path.is_file()
    finally:
        daemon_manager_module._runtime_fingerprint_cache = None


def test_desktop_ensure_uses_post_update_timeout(monkeypatch):
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    assert (
        daemon_manager_module._default_guard_daemon_start_timeout()
        == daemon_manager_module.GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS
    )
    monkeypatch.delenv("HOL_GUARD_DESKTOP")
    assert (
        daemon_manager_module._default_guard_daemon_start_timeout()
        == daemon_manager_module.GUARD_DAEMON_START_TIMEOUT_SECONDS
    )


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


@pytest.mark.skipif(
    os.name == "nt",
    reason="its fake Popen omits the native Windows process identity required by daemon launch",
)
def test_ensure_guard_daemon_spawns_with_current_package_import_path(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "real-user-home"
    home_dir.mkdir()
    neutral_home = tmp_path / "neutral-update-home"
    neutral_home.mkdir()
    responses = iter((None, None, "http://127.0.0.1:5412"))
    captured_command: list[str] = []
    captured_env: dict[str, str] = {}

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)

    def fake_load_guard_daemon_url(_guard_home):
        return next(responses, "http://127.0.0.1:5412")

    def fake_popen(command, **kwargs):
        captured_command.extend(command)
        captured_env.update(kwargs.get("env", {}))
        return SimpleNamespace(poll=lambda: None)

    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "poisoned-pythonpath"))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "poisoned-pythonhome"))
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "poisoned-venv"))
    monkeypatch.setenv("PIP_CONFIG_FILE", str(tmp_path / "poisoned-pip-config"))
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", str(tmp_path / "poisoned-loader"))
    monkeypatch.setenv("HOME", str(neutral_home))
    monkeypatch.setenv("USERPROFILE", str(neutral_home))
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home, **kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5412])
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    url = daemon_manager_module.ensure_guard_daemon(guard_home, home_dir=home_dir)

    assert url == "http://127.0.0.1:5412"
    bootstrap_index = captured_command.index(daemon_manager_module._GUARD_DAEMON_BOOTSTRAP)
    import_paths = json.loads(captured_command[bootstrap_index + 3])
    assert str(Path(daemon_manager_module.__file__).resolve().parents[3]) in import_paths
    assert captured_command[bootstrap_index + 4] == "codex_plugin_scanner.cli"
    assert captured_command[captured_command.index("--home") + 1] == str(home_dir.resolve())
    assert captured_env["HOME"] == str(home_dir.resolve())
    if os.name == "nt":
        assert captured_env["USERPROFILE"] == str(home_dir.resolve())
    rendered_command = daemon_manager_module.shlex.join(captured_command)
    assert daemon_manager_module._guard_daemon_command_matches(rendered_command)
    assert daemon_manager_module._guard_home_from_command(rendered_command) == guard_home
    assert daemon_manager_module._guard_daemon_port_from_command(rendered_command) == 5412
    assert all(
        key not in captured_env
        for key in (
            "PYTHONPATH",
            "PYTHONHOME",
            "VIRTUAL_ENV",
            "PIP_CONFIG_FILE",
            "DYLD_INSERT_LIBRARIES",
        )
    )


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


@pytest.mark.parametrize(
    ("script", "timeout_seconds", "output_limit_bytes"),
    (
        ("import os,time; os.write(1,b'x' * 65536); time.sleep(30)", 1.0, 1024),
        ("import time; time.sleep(30)", 0.05, 1024),
    ),
)
def test_bounded_process_query_stdout_rejects_adversarial_children(
    script,
    timeout_seconds,
    output_limit_bytes,
):
    started_at = time.monotonic()

    output = daemon_manager_module._bounded_process_query_stdout(
        [sys.executable, "-I", "-S", "-c", script],
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    )

    assert output is None
    assert time.monotonic() - started_at < 3.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-query regression")
def test_guard_daemon_process_query_ignores_hostile_path_and_loader_environment(tmp_path, monkeypatch):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker = tmp_path / "fake-ps-executed"
    fake_ps = fake_bin / "ps"
    fake_ps.write_text(f"#!/bin/sh\nprintf executed > {marker}\n", encoding="utf-8")
    fake_ps.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "python-path"))
    monkeypatch.setenv("LD_PRELOAD", str(tmp_path / "fake-loader.so"))
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", str(tmp_path / "fake-loader.dylib"))

    command = daemon_manager_module._guard_daemon_command_for_pid(os.getpid())

    assert command
    assert not marker.exists()
    trusted_ps = daemon_manager_module._trusted_posix_ps_path()
    assert trusted_ps in {"/bin/ps", "/usr/bin/ps"}
    assert daemon_manager_module._process_query_environment([trusted_ps]) == {
        "LANG": "C",
        "LC_ALL": "C",
    }


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and signal retirement",
)
def test_ensure_guard_daemon_reaps_stale_ephemeral_daemon_states(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-1" / "test-stale" / "home"
    stale_guard_home.mkdir(parents=True)
    stale_state_path = stale_guard_home / "daemon-state.json"
    stale_state_path.write_text(
        json.dumps(
            {
                "pid": 11111,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
                "process_start_marker": "linux:stale-generation",
                "user": "uid:501",
            }
        ),
        encoding="utf-8",
    )
    fresh_guard_home = tmp_path / "pytest-of-user" / "pytest-2" / "test-fresh" / "home"
    fresh_guard_home.mkdir(parents=True)
    fresh_state_path = fresh_guard_home / "daemon-state.json"
    fresh_state_path.write_text(
        json.dumps(
            {
                "pid": 22222,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
                "process_start_marker": "linux:fresh-generation",
                "user": "uid:501",
            }
        ),
        encoding="utf-8",
    )
    launched_commands: list[list[str]] = []
    killed: list[int] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5413"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module, "_EPHEMERAL_REAP_IN_FLIGHT", False)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(
        daemon_manager_module,
        "_candidate_ports",
        lambda _guard_home, **kwargs: [5413],
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_state_path_age_seconds",
        lambda path: 60.0 if path == stale_state_path else 0.0,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_runtime_state_age_seconds",
        lambda guard_home: 60.0 if guard_home == stale_guard_home else None,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_ephemeral_guard_daemon_processes",
        lambda: [(11111, stale_guard_home, 60.0)],
    )
    pid_running = {"value": True}

    def fake_pid_is_running(_pid):
        return pid_running["value"]

    def fake_kill(pid, _signal):
        killed.append(pid)
        pid_running["value"] = False

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", fake_pid_is_running)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:stale-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", fake_kill)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )
    reap_completed = threading.Event()
    original_reap = daemon_manager_module._reap_stale_ephemeral_guard_daemons

    def tracked_reap(**kwargs):
        try:
            original_reap(**kwargs)
        finally:
            reap_completed.set()

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", tracked_reap)

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5413"
    assert reap_completed.wait(timeout=1.0)
    assert killed == [11111]
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == {}
    assert json.loads(fresh_state_path.read_text(encoding="utf-8"))["pid"] == 22222


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and uses an incomplete fake Popen",
)
def test_ensure_guard_daemon_skips_runtime_probe_for_dead_ephemeral_state_pid(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    _run_ephemeral_reap_synchronously(monkeypatch)
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-11" / "test-stale" / "home"
    stale_guard_home.mkdir(parents=True)
    stale_state_path = stale_guard_home / "daemon-state.json"
    stale_state_path.write_text(
        json.dumps(
            {
                "pid": 12345,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            }
        ),
        encoding="utf-8",
    )
    launched_commands: list[list[str]] = []
    runtime_probe_calls = {"count": 0}

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5418"
        return None

    def fake_runtime_state_age_seconds(_guard_home):
        runtime_probe_calls["count"] += 1
        return 60.0

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module, "_EPHEMERAL_REAP_IN_FLIGHT", False)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5418])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", fake_runtime_state_age_seconds)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5418"
    assert runtime_probe_calls["count"] == 0
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == {}


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and uses an incomplete fake Popen",
)
def test_ensure_guard_daemon_skips_runtime_probe_for_ephemeral_state_without_pid(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-12" / "test-stale" / "home"
    stale_guard_home.mkdir(parents=True)
    stale_state_path = stale_guard_home / "daemon-state.json"
    stale_state_path.write_text("{}", encoding="utf-8")
    launched_commands: list[list[str]] = []
    runtime_probe_calls = {"count": 0}

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5419"
        return None

    def fake_runtime_state_age_seconds(_guard_home):
        runtime_probe_calls["count"] += 1
        return 60.0

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5419])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", fake_runtime_state_age_seconds)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5419"
    assert runtime_probe_calls["count"] == 0
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == {}


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and signal retirement",
)
def test_ensure_guard_daemon_keeps_ephemeral_state_with_recent_runtime_heartbeat(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    guard_home = tmp_path / "guard-home"
    active_guard_home = tmp_path / "pytest-of-user" / "pytest-3" / "test-active" / "home"
    active_guard_home.mkdir(parents=True)
    active_state_path = active_guard_home / "daemon-state.json"
    active_state_path.write_text(
        json.dumps(
            {
                "pid": 44444,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            }
        ),
        encoding="utf-8",
    )
    launched_commands: list[list[str]] = []
    killed: list[int] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5415"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5415])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home, **kwargs: 1.0)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5415"
    assert killed == []
    assert json.loads(active_state_path.read_text(encoding="utf-8"))["pid"] == 44444


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


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and uses an incomplete fake Popen",
)
def test_ensure_guard_daemon_does_not_clobber_unowned_ephemeral_state_files(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    guard_home = tmp_path / "guard-home"
    foreign_guard_home = tmp_path / "pytest-of-user" / "pytest-7" / "test-foreign" / "home"
    foreign_guard_home.mkdir(parents=True)
    foreign_state_path = foreign_guard_home / "daemon-state.json"
    foreign_state_path.write_text('"not-json-dict"', encoding="utf-8")
    launched_commands: list[list[str]] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5416"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5416])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home, **kwargs: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5416"
    assert foreign_state_path.read_text(encoding="utf-8") == '"not-json-dict"'


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and uses an incomplete fake Popen",
)
def test_ensure_guard_daemon_clears_stale_state_when_pid_no_longer_matches_guard_home(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    _run_ephemeral_reap_synchronously(monkeypatch)
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-8" / "test-reused-pid" / "home"
    stale_guard_home.mkdir(parents=True)
    stale_state_path = stale_guard_home / "daemon-state.json"
    stale_payload = {
        "pid": 66666,
        "guard_home": str(stale_guard_home),
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
    }
    stale_state_path.write_text(json.dumps(stale_payload), encoding="utf-8")
    launched_commands: list[list[str]] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5417"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5417])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home, **kwargs: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_command_identity",
        lambda _pid, expected_guard_home=None: False,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )
    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5417"
    # A live PID absent from the proven daemon inventory is left untouched.
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == stale_payload


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and signal retirement",
)
def test_ensure_guard_daemon_reaps_stale_ephemeral_processes_without_state_file(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
    _run_ephemeral_reap_synchronously(monkeypatch)
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-9" / "test-stale" / "home"
    stale_guard_home.mkdir(parents=True)
    launched_commands: list[list[str]] = []
    killed: list[int] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5414"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home, **kwargs: [5414])
    monkeypatch.setattr(daemon_manager_module, "_ephemeral_guard_daemon_state_paths", lambda _temp_root: [])
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_ephemeral_guard_daemon_processes",
        lambda: [(33333, stale_guard_home, 60.0)],
    )
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home, **kwargs: None)
    pid_running = {"value": True}

    def fake_pid_is_running(_pid):
        return pid_running["value"]

    def fake_kill(pid, _signal):
        killed.append(pid)
        pid_running["value"] = False

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", fake_pid_is_running)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "linux:ephemeral-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "uid:501")
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", fake_kill)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5414"
    assert killed == [33333]
    assert json.loads((stale_guard_home / "daemon-state.json").read_text(encoding="utf-8")) == {}


def test_retire_guard_daemon_process_clears_recycled_pid_for_different_guard_home(tmp_path, monkeypatch):
    killed: list[int] = []
    payload = {
        "pid": 55555,
        "guard_home": str(tmp_path / "expected-home"),
    }

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_command_identity",
        lambda _pid, expected_guard_home=None: False,
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))

    retired = daemon_manager_module._retire_guard_daemon_process(payload)

    # A proven-foreign pid returns True (nothing to kill) so the caller clears stale state.
    assert retired is True
    assert killed == []


def test_retire_all_uses_authenticated_state_when_platform_enumeration_is_empty(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    retired_calls: list[tuple[int, Path | None]] = []
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

    def retire(pid: int, *, expected_guard_home: Path | None = None, **_identity) -> bool:
        retired_calls.append((pid, expected_guard_home))
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home)

    assert retired == [55_555]
    assert retired_calls == [(55_555, guard_home)]


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


def test_retire_all_attempts_authenticated_state_pid_only_once(tmp_path, monkeypatch):
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
        lambda _guard_home: [(55_555, 4781)],
    )
    retire = MagicMock(return_value=True)
    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire)

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home)

    assert retired == [55_555]
    retire.assert_called_once_with(
        55_555,
        expected_guard_home=guard_home,
        expected_start_marker="linux:authenticated-generation",
        expected_owner_marker="uid:501",
    )


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


def test_candidate_ports_prefers_dashboard_update_port(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    ports = daemon_manager_module._candidate_ports(guard_home, preferred_port=5483)
    assert ports[0] == 5483
    assert len(ports) in (25, 26)
    assert 5483 not in ports[1:]


def test_prepend_preferred_port_dedupes() -> None:
    ordered = daemon_manager_module._prepend_preferred_port([5483, 5484, 5485], 5483)
    assert ordered == [5483, 5484, 5485]
    ordered = daemon_manager_module._prepend_preferred_port([5474, 5475], 5483)
    assert ordered[0] == 5483
    assert ordered[1:] == [5474, 5475]


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


@pytest.mark.parametrize("argument_count", [0, -1])
def test_windows_command_line_to_argv_frees_non_null_allocation_for_invalid_count(
    monkeypatch: pytest.MonkeyPatch,
    argument_count: int,
) -> None:
    class FakeFunction:
        def __init__(self, callback) -> None:
            self.callback = callback
            self.argtypes: list[object] = []
            self.restype: object | None = None

        def __call__(self, *args: object) -> object:
            return self.callback(*args)

    native_arguments = (windows_paths_module.wintypes.LPWSTR * 1)("unused")
    allocated_arguments = windows_paths_module.ctypes.cast(
        native_arguments,
        windows_paths_module.ctypes.POINTER(windows_paths_module.wintypes.LPWSTR),
    )
    freed_addresses: list[int | None] = []

    def fake_command_line_to_argv(_command: object, count_pointer: Any) -> object:
        native_count_pointer = windows_paths_module.ctypes.cast(
            count_pointer,
            windows_paths_module.ctypes.POINTER(windows_paths_module.ctypes.c_int),
        )
        native_count_pointer[0] = argument_count
        return allocated_arguments

    def fake_local_free(address: Any) -> None:
        freed_addresses.append(address.value)

    shell32 = SimpleNamespace(CommandLineToArgvW=FakeFunction(fake_command_line_to_argv))
    kernel32 = SimpleNamespace(LocalFree=FakeFunction(fake_local_free))

    def fake_win_dll(name: str, **_kwargs: object) -> object:
        return shell32 if name == "shell32" else kernel32

    monkeypatch.setattr(windows_paths_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(windows_paths_module.ctypes, "WinDLL", fake_win_dll, raising=False)

    assert windows_paths_module.windows_command_line_to_argv("guard.exe --status") is None
    assert freed_addresses == [windows_paths_module.ctypes.addressof(native_arguments)]


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


def _configure_isolated_windows_daemon_start(monkeypatch, *, port: int = 5410) -> None:
    """Remove unrelated daemon discovery from focused Windows launch tests."""

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_start_lock",
        lambda _guard_home, **_kwargs: nullcontext(),
    )
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_load_authenticated_daemon_identity", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_adopt_existing_guard_daemon",
        lambda _guard_home, **_kwargs: None,
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _guard_home: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_guard_daemon_pending_launch",
        lambda _guard_home: None,
    )
    monkeypatch.setattr(daemon_manager_module, "clear_guard_daemon_state", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_candidate_ports",
        lambda _guard_home, **_kwargs: [port],
    )
    monkeypatch.setattr(daemon_manager_module, "_daemon_launcher_env", lambda **_kwargs: {})
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_duplicate_guard_daemons",
        lambda _guard_home, **_kwargs: None,
    )


def test_update_breakaway_records_authenticated_pending_launch_before_gate_release(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    events: list[str] = []
    popen_kwargs: dict[str, object] = {}
    launch_gate_values: list[bool] = []
    process_creation_time = 133_713_371

    _configure_isolated_windows_daemon_start(monkeypatch)

    class RecordingGate:
        def write(self, payload: bytes) -> int:
            pending = json.loads(daemon_manager_module._pending_launch_path(guard_home).read_text(encoding="utf-8"))
            discovery_key = load_daemon_discovery_key(guard_home)
            assert discovery_key is not None
            assert pending["pid"] == 43_210
            assert pending["process_creation_time"] == process_creation_time
            assert verify_daemon_state(pending, discovery_key=discovery_key)
            events.append("gate-released")
            assert payload == b"1"
            return len(payload)

        def flush(self) -> None:
            return None

        def close(self) -> None:
            events.append("gate-closed")

    class FakeProcess:
        pid = 43_210
        stdin = RecordingGate()

        def poll(self) -> None:
            return None

    process = FakeProcess()

    def fake_launch_command(_guard_home, _port, *, home_dir=None, gate_on_stdin=False):
        launch_gate_values.append(gate_on_stdin)
        return ["trusted-python", "gated-bootstrap"]

    def fake_popen(_command, **kwargs):
        popen_kwargs.update(kwargs)
        return process

    def record_pending(_guard_home, *, launch, port):
        process = launch.process
        discovery_key = ensure_daemon_discovery_key(guard_home)
        pending = authenticate_daemon_state(
            {
                "state_kind": "daemon_launch_pending",
                "guard_home": str(guard_home.resolve()),
                "pid": process.pid,
                "port": port,
                "process_creation_time": process_creation_time,
            },
            discovery_key=discovery_key,
        )
        daemon_manager_module._pending_launch_path(guard_home).write_text(
            json.dumps(pending, sort_keys=True),
            encoding="utf-8",
        )
        events.append("pending-recorded")
        return process_creation_time

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_launch_command", fake_launch_command)
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module, "_record_guard_daemon_pending_launch", record_pending)
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_url",
        lambda _guard_home, **_kwargs: "http://127.0.0.1:5410",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_guard_daemon_pending_launch_if_current",
        lambda _guard_home, **_kwargs: events.append("pending-cleared") or True,
    )

    url = daemon_manager_module.ensure_guard_daemon_after_update(
        guard_home,
        home_dir=home_dir,
        allow_windows_job_breakaway=True,
    )

    assert url == "http://127.0.0.1:5410"
    assert launch_gate_values == [True]
    assert popen_kwargs["stdin"] == subprocess.PIPE
    assert int(popen_kwargs["creationflags"]) & daemon_manager_module._WINDOWS_CREATE_BREAKAWAY_FROM_JOB
    assert events == ["pending-recorded", "gate-released", "gate-closed", "pending-cleared"]


def test_gated_daemon_bootstrap_exits_before_module_execution_when_gate_is_withheld(tmp_path) -> None:
    marker = tmp_path / "daemon-executed"
    probe_module = tmp_path / "gated_daemon_probe.py"
    probe_module.write_text(
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    command = [
        sys.executable,
        "-S",
        "-c",
        daemon_manager_module._GUARD_DAEMON_GATED_BOOTSTRAP,
        sys.prefix,
        sys.exec_prefix,
        json.dumps([str(tmp_path)]),
        "gated_daemon_probe",
        str(marker),
    ]

    withheld = subprocess.run(command, input=b"", capture_output=True, timeout=5.0, check=False)

    assert withheld.returncode == 70
    assert not marker.exists()

    released = subprocess.run(command, input=b"1", capture_output=True, timeout=5.0, check=False)

    assert released.returncode == 0, released.stderr.decode("utf-8", errors="replace")
    assert marker.read_text(encoding="utf-8") == "executed"


def test_failed_pending_record_never_releases_gate_and_reaps_exact_child(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    events: list[str] = []

    _configure_isolated_windows_daemon_start(monkeypatch)

    class UnreleasedGate:
        def write(self, _payload: bytes) -> int:
            raise AssertionError("the launch gate must remain withheld")

        def flush(self) -> None:
            raise AssertionError("the launch gate must remain withheld")

        def close(self) -> None:
            events.append("gate-closed")

    class FakeProcess:
        pid = 54_321
        stdin = UnreleasedGate()

        def __init__(self) -> None:
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            events.append("terminate")
            self.returncode = 1

        def wait(self, *, timeout: float) -> int:
            events.append(f"wait:{timeout}")
            assert self.returncode is not None
            return self.returncode

        def kill(self) -> None:
            raise AssertionError("terminate should reap the exact child")

    process = FakeProcess()
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_launch_command",
        lambda *_args, **_kwargs: ["trusted-python", "gated-bootstrap"],
    )
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        daemon_manager_module,
        "_record_guard_daemon_pending_launch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("pending receipt write failed")),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_url",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("daemon must not execute")),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_guard_daemon_pending_launch_if_current",
        lambda *_args, **_kwargs: True,
    )

    with pytest.raises(RuntimeError, match="pending receipt write failed"):
        daemon_manager_module.ensure_guard_daemon_after_update(
            guard_home,
            home_dir=home_dir,
            allow_windows_job_breakaway=True,
        )

    assert events == ["gate-closed", "terminate", "wait:1.0"]
    assert process.poll() == 1


def test_missing_pending_launch_process_marker_keeps_gate_closed_and_reaps_exact_child(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    events: list[str] = []
    marker_probes: list[int] = []
    owner_probes: list[int] = []

    _configure_isolated_windows_daemon_start(monkeypatch)

    class UnreleasedGate:
        def write(self, _payload: bytes) -> int:
            raise AssertionError("the launch gate must remain withheld")

        def flush(self) -> None:
            raise AssertionError("the launch gate must remain withheld")

        def close(self) -> None:
            events.append("gate-closed")

    class FakeProcess:
        pid = 54_322
        stdin = UnreleasedGate()

        def __init__(self) -> None:
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            events.append("terminate")
            self.returncode = 1

        def wait(self, *, timeout: float) -> int:
            events.append(f"wait:{timeout}")
            assert self.returncode is not None
            return self.returncode

        def kill(self) -> None:
            raise AssertionError("terminate should reap the exact child")

    process = FakeProcess()
    monkeypatch.setattr(daemon_manager_module, "_live_or_newer_daemon_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_launch_command",
        lambda *_args, **_kwargs: ["trusted-python", "gated-bootstrap"],
    )
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        daemon_manager_module,
        "process_start_token",
        lambda pid: marker_probes.append(pid) or None,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "process_owner_marker",
        lambda pid: owner_probes.append(pid) or "unexpected-owner-probe",
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_started_guard_daemon_url",
        lambda *_args, **_kwargs: pytest.fail("unidentified daemon must not be released or observed"),
    )

    with pytest.raises(RuntimeError, match="process start marker could not be recorded"):
        daemon_manager_module.ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            start_timeout=60.0,
            allow_windows_job_breakaway=True,
        )

    assert marker_probes == [process.pid] * 10
    assert owner_probes == []
    assert events == ["gate-closed", "terminate", "wait:1.0"]
    assert process.poll() == 1


def test_existing_active_pending_launch_is_retired_or_blocks_before_spawn(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    events: list[str] = []
    pending = {"pid": 55_432, "port": 5410, "process_creation_time": 918_273}
    daemon_manager_module._pending_launch_path(guard_home).write_text(
        json.dumps(pending),
        encoding="utf-8",
    )

    _configure_isolated_windows_daemon_start(monkeypatch)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_guard_daemon_pending_launch",
        lambda _guard_home: pending,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda _guard_home: events.append("retire-attempted") or [],
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pending_launch_state_is_resolved",
        lambda _guard_home: events.append("pending-still-active") or False,
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not overwrite a live pending launch")),
    )

    with pytest.raises(RuntimeError, match="previous Guard daemon launch could not be retired"):
        daemon_manager_module.ensure_guard_daemon(guard_home)

    assert events == ["retire-attempted", "pending-still-active"]


def test_late_generation_bound_pending_launch_blocks_replacement_inside_start_lock(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_nonce = "a" * daemon_manager_module._GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
    pending = {
        "state_kind": "daemon_launch_pending",
        "pid": 64_321,
        "port": 5410,
        "launch_nonce": launch_nonce,
        "launch_generation": launch_nonce,
        "generation": launch_nonce,
    }
    pending_reads: list[Path] = []
    resolution_checks: list[Path] = []

    def load_pending(home: Path) -> dict[str, object] | None:
        pending_reads.append(home)
        return None if len(pending_reads) == 1 else pending

    monkeypatch.setattr(daemon_manager_module, "_schedule_stale_ephemeral_guard_daemon_reap", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_live_or_newer_daemon_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_adopt_existing_guard_daemon", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _home: False)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", load_pending)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pending_launch_state_is_resolved",
        lambda home: resolution_checks.append(home) or False,
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not replace an unresolved launch")),
    )

    with pytest.raises(RuntimeError, match="previous Guard daemon launch could not be retired safely"):
        daemon_manager_module.ensure_guard_daemon(guard_home)

    assert pending_reads == [guard_home, guard_home]
    assert resolution_checks == [guard_home]
    assert not daemon_manager_module._pending_launch_path(guard_home).exists()


@pytest.mark.parametrize(
    ("still_running", "expected_retired", "expected_clear_count"),
    [(True, [], 0), (False, [64_321], 1)],
)
def test_pending_launch_receipt_is_retained_until_exact_process_death(
    tmp_path,
    monkeypatch,
    still_running,
    expected_retired,
    expected_clear_count,
):
    guard_home = tmp_path / "guard-home"
    pending_creation_time = 4_242_424
    pending = {
        "pid": 64_321,
        "port": 5410,
        "process_creation_time": pending_creation_time,
    }
    retire_calls: list[tuple[int, Path | None, int | None]] = []
    clear_calls: list[tuple[int, int | None]] = []

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _guard_home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_guard_daemon_pending_launch",
        lambda _guard_home: pending,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "windows_process_creation_time",
        lambda pid: pending_creation_time if pid == 64_321 else None,
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: still_running)
    monkeypatch.setattr(
        daemon_manager_module,
        "windows_process_liveness",
        lambda _pid: bool(still_running),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda pid, *, expected_guard_home=None, expected_creation_time=None: (
            retire_calls.append((pid, expected_guard_home, expected_creation_time)) or True
        ),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_guard_daemon_pending_launch_if_current",
        lambda _guard_home, *, pid, creation_time: clear_calls.append((pid, creation_time)) or True,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [],
    )

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home)

    assert retired == expected_retired
    assert retire_calls == [(64_321, guard_home, pending_creation_time)]
    assert clear_calls == [(64_321, pending_creation_time)] * expected_clear_count


def test_matching_state_and_pending_receipt_use_exact_creation_identity_once(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    pending_creation_time = 7_654_321
    pending = {
        "pid": 61_111,
        "port": 5410,
        "process_creation_time": pending_creation_time,
    }
    state = {"pid": 61_111, "port": 5410, "guard_home": str(guard_home)}
    dead = {"value": False}
    retire_calls: list[int | None] = []
    pending_clears: list[int] = []
    state_clears: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_guard_daemon_pending_launch",
        lambda _home: pending,
    )
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: pending_creation_time)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: dead["value"])

    def retire_exact(_pid, *, expected_guard_home=None, expected_creation_time=None):
        retire_calls.append(expected_creation_time)
        dead["value"] = True
        return True

    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", retire_exact)
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_guard_daemon_pending_launch_if_current",
        lambda _home, *, pid, creation_time: pending_clears.append(pid) or True,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_authenticated_guard_daemon_state_if_current",
        lambda _home, *, expected_state: state_clears.append(expected_state["pid"]) or True,
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home)

    assert retired == [61_111]
    assert retire_calls == [pending_creation_time]
    assert pending_clears == [61_111]
    assert state_clears == [61_111]


def test_authenticated_state_with_proven_foreign_recycled_pid_is_tombstoned(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    state = {
        "pid": 62_222,
        "port": 5410,
        "guard_home": str(guard_home),
        "process_start_marker": "windows:62222-generation",
        "user": "sid:S-1-5-21",
    }
    state_clears: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_command_identity",
        lambda _pid, *, expected_guard_home=None: False,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_authenticated_guard_daemon_state_if_current",
        lambda _home, *, expected_state: state_clears.append(expected_state["pid"]) or True,
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []
    assert state_clears == [62_222]


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

    assert daemon_manager_module._retire_guard_daemon_pid(
        pid,
        expected_start_marker="linux:terminate-generation",
        expected_owner_marker="uid:501",
    ) is True
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


def test_malformed_windows_lifecycle_records_are_quarantined_after_two_empty_inventories(
    tmp_path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state_path = daemon_manager_module._state_path(guard_home)
    pending_path = daemon_manager_module._pending_launch_path(guard_home)
    state_path.write_bytes(b"{broken-state")
    pending_path.write_bytes(b"{broken-pending")
    inventory = MagicMock(side_effect=[[], []])

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", inventory)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_state_write_lock", lambda _home: nullcontext())

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []
    assert state_path.read_bytes() == b"{}"
    assert pending_path.read_bytes() == b"{}"
    assert (guard_home / "daemon-state.invalid.json").read_bytes() == b"{broken-state"
    assert (guard_home / "daemon-launch-pending.invalid.json").read_bytes() == b"{broken-pending"
    assert inventory.call_count == 2


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
    monkeypatch.setattr(
        daemon_manager_module,
        "_split_process_command",
        lambda _command: daemon_parts,
    )

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
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_fails_closed_for_malformed_python_guard_process(tmp_path, monkeypatch) -> None:
    command_line = '/usr/bin/python3 -m codex_plugin_scanner.cli guard daemon --serve "'
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_skips_serve_without_guard_home(tmp_path, monkeypatch) -> None:
    command_line = "/usr/local/bin/hol-guard daemon --serve --port 5474"
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_adopts_implicit_default_home(tmp_path, monkeypatch) -> None:
    default_home = tmp_path / "default-home"
    default_home.mkdir()
    monkeypatch.setattr(daemon_manager_module, "_implicit_daemon_guard_home", lambda: default_home)
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: "123 /usr/local/bin/hol-guard daemon --serve --port 5474\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(default_home) == [(123, 5474)]
    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_parses_equals_guard_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 /usr/local/bin/hol-guard daemon --serve --guard-home={tmp_path} --port 5474\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == [(123, 5474)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_fails_closed_for_equals_home_without_port(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 /usr/local/bin/hol-guard daemon --serve --guard-home={tmp_path}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_ignores_bounded_hook_launcher(tmp_path, monkeypatch) -> None:
    command_line = (
        "/usr/local/bin/hol-guard __guard-bounded-hook "
        '{"python_executable":"/usr/local/bin/hol-guard","cli_args":["guard","hook"]}'
    )
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-list coverage")
def test_daemon_inventory_fails_closed_for_matching_home_without_port(tmp_path, monkeypatch) -> None:
    command_line = f"/usr/local/bin/hol-guard daemon --serve --guard-home {tmp_path}"
    monkeypatch.setattr(daemon_manager_module, "_trusted_posix_ps_path", lambda: "/bin/ps")
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda _command: f"123 {command_line}\n",
    )

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(tmp_path) is None


@pytest.mark.parametrize(
    "command_line",
    (
        '"C:\\Program Files\\HOL Guard\\hol-guard.exe" --_hol-guard-daemon-serve "{broken',
        '"C:\\Program Files\\HOL Guard\\hol-guard.exe --_hol-guard-daemon-serve {broken',
    ),
)
def test_malformed_frozen_guard_command_with_quoted_executable_fails_closed(command_line: str) -> None:

    assert daemon_manager_module._malformed_command_may_launch_guard(command_line)


def test_inventoried_windows_daemon_termination_is_bound_to_sampled_creation_time(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    creation_time = 8_765_432
    live = {"value": True}
    inventory = MagicMock(side_effect=[[(64_444, 5410)], [], []])
    terminated: list[tuple[int, int]] = []

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", inventory)
    monkeypatch.setattr(daemon_manager_module, "windows_process_liveness", lambda _pid: live["value"])
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: creation_time)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "windows:inventory-generation")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: "sid:S-1-5-21")
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_command_identity",
        lambda _pid, *, expected_guard_home=None: True,
    )

    def terminate(pid, expected):
        terminated.append((pid, expected))
        live["value"] = False
        return True

    monkeypatch.setattr(daemon_manager_module, "windows_terminate_process_if_creation_time", terminate)
    monkeypatch.setattr(
        daemon_manager_module.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(AssertionError("Windows inventory retirement must not use os.kill")),
    )
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == [64_444]
    assert terminated == [(64_444, creation_time)]
    assert inventory.call_count == 3


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
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pending_launch_is_active", lambda _guard_home: False)
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
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pending_launch_is_active", lambda _guard_home: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )

    assert daemon_manager_module.guard_daemon_retirement_is_complete(guard_home)


def test_retire_all_blocks_on_unresolved_generation_bound_pending_receipt(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    launch_nonce = "ab" * 32
    pending = {
        "pid": 66_601,
        "port": 5410,
        "process_creation_time": 7_001,
        "launch_nonce": launch_nonce,
        "launch_generation": launch_nonce,
        "generation": launch_nonce,
    }
    pending_path = daemon_manager_module._pending_launch_path(guard_home)
    pending_path.write_text(json.dumps(pending), encoding="utf-8")
    signals: list[tuple[int, int]] = []
    waits: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: pending)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pending_launch_state_is_resolved", lambda _home: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_daemon_state",
        lambda _home: pytest.fail("unresolved launch must stop before authenticated state"),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: pytest.fail("unresolved launch must stop before inventory"),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda *_args, **_kwargs: pytest.fail("unresolved launch must not signal"),
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, sent_signal: signals.append((pid, sent_signal)))
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda pid: waits.append(pid) or True,
    )

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []
    assert pending_path.is_file()
    assert signals == []
    assert waits == []


def test_retire_all_clears_pending_receipt_when_creation_generation_is_replaced(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    pending = {
        "pid": 66_602,
        "port": 5410,
        "process_creation_time": 7_002,
    }
    pending_path = daemon_manager_module._pending_launch_path(guard_home)
    pending_path.write_text(json.dumps(pending), encoding="utf-8")
    clear_calls: list[tuple[int, int]] = []
    signals: list[tuple[int, int]] = []
    waits: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "load_authenticated_guard_daemon_pending_launch",
        lambda _home: pending,
    )
    monkeypatch.setattr(daemon_manager_module, "windows_process_creation_time", lambda _pid: 8_002)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_guard_daemon_pending_launch_if_current",
        lambda _home, *, pid, creation_time: (
            clear_calls.append((pid, creation_time)) or pending_path.unlink() or True
        ),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda *_args, **_kwargs: pytest.fail("replaced generation must not be signaled"),
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, sent_signal: signals.append((pid, sent_signal)))
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda pid: waits.append(pid) or True,
    )

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []
    assert clear_calls == [(66_602, 7_002)]
    assert not pending_path.exists()
    assert signals == []
    assert waits == []


def test_retire_all_signals_and_waits_for_exact_authenticated_generation(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    pid = 66_603
    start_marker = "linux:exact-generation"
    owner_marker = "uid:501"
    state = {
        "pid": pid,
        "port": 5410,
        "guard_home": str(guard_home),
        "process_start_marker": start_marker,
        "user": owner_marker,
    }
    dead = {"value": False}
    signals: list[tuple[int, int]] = []
    waits: list[int] = []
    state_clears: list[int] = []
    sigkill = getattr(signal, "SIGKILL", 9)

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: start_marker)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: owner_marker)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: dead["value"])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(daemon_manager_module, "record_daemon_lifecycle_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_authenticated_guard_daemon_state_if_current",
        lambda _home, *, expected_state: state_clears.append(expected_state["pid"]) or True,
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)

    def kill(pid_value: int, sent_signal: int) -> None:
        signals.append((pid_value, sent_signal))
        if sent_signal == sigkill:
            dead["value"] = True

    monkeypatch.setattr(daemon_manager_module.os, "kill", kill)

    def wait(pid_value: int) -> bool:
        waits.append(pid_value)
        return len(waits) == 2

    monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_pid_death", wait)

    retired = daemon_manager_module.retire_all_guard_daemons_for_home(guard_home)

    assert retired == [pid]
    assert signals == [(pid, signal.SIGTERM), (pid, sigkill)]
    assert waits == [pid, pid]
    assert state_clears == [pid]


@pytest.mark.parametrize(
    ("actual_start_marker", "actual_owner_marker"),
    (
        ("linux:recycled-generation", "uid:501"),
        ("linux:exact-generation", "uid:foreign"),
    ),
)
def test_retire_all_never_signals_after_generation_or_owner_mismatch(
    tmp_path,
    monkeypatch,
    actual_start_marker,
    actual_owner_marker,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    pid = 66_604
    state = {
        "pid": pid,
        "port": 5410,
        "guard_home": str(guard_home),
        "process_start_marker": "linux:exact-generation",
        "user": "uid:501",
    }
    signals: list[tuple[int, int]] = []
    waits: list[int] = []
    state_clears: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "os", _PosixOSProxy())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_guard_daemon_pending_launch", lambda _home: None)
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: actual_start_marker)
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", lambda _pid: actual_owner_marker)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_proven_dead", lambda _pid: False)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(daemon_manager_module, "record_daemon_lifecycle_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module,
        "_clear_authenticated_guard_daemon_state_if_current",
        lambda _home, *, expected_state: state_clears.append(expected_state["pid"]) or True,
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    monkeypatch.setattr(daemon_manager_module, "_reconcile_invalid_daemon_lifecycle_artifacts", lambda _home: True)
    monkeypatch.setattr(
        daemon_manager_module.os,
        "kill",
        lambda pid_value, sent_signal: signals.append((pid_value, sent_signal)),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_wait_for_guard_daemon_pid_death",
        lambda pid_value: waits.append(pid_value),
    )

    assert daemon_manager_module.retire_all_guard_daemons_for_home(guard_home) == []
    assert signals == []
    assert waits == []
    assert state_clears == []

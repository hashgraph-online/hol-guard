"""Focused tests for Guard daemon startup coordination."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from contextlib import nullcontext
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


class _WindowsOSProxy:
    """Expose Windows branching without mutating process-wide ``os.name``."""

    name = "nt"

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
        "_retire_duplicate_guard_daemons",
        lambda _guard_home, *, keep_port, start_lock_held=False: None,
    )


def test_hook_failure_restarts_an_older_unresponsive_daemon(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    old_state = {"started_at": "2020-01-01T00:00:00+00:00"}
    retired: list[Path] = []
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_lock", lambda _home: nullcontext())
    monkeypatch.setattr(daemon_manager_module, "load_authenticated_daemon_state", lambda _home: old_state)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        daemon_manager_module,
        "retire_all_guard_daemons_for_home",
        lambda home: retired.append(home) or [],
    )
    monkeypatch.setattr(daemon_manager_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "ensure_guard_daemon",
        lambda _home, *, home_dir=None: "http://127.0.0.1:5475",
    )

    recovered = daemon_manager_module.recover_guard_daemon_after_hook_failure(guard_home)

    assert recovered == "http://127.0.0.1:5475"
    assert retired == [guard_home]


def test_hook_failure_preserves_a_concurrently_started_replacement(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    recent_state = {"started_at": datetime.now(timezone.utc).isoformat()}
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_lock", lambda _home: nullcontext())
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

        def read(self) -> bytes:
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
    fchmod_calls: list[tuple[int, int]] = []

    def fake_fchmod(descriptor: int, mode: int) -> None:
        fchmod_calls.append((descriptor, mode))

    monkeypatch.setattr(daemon_manager_module.os, "fchmod", fake_fchmod)

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")

    assert len(fchmod_calls) == 3
    assert all(mode == 0o600 for _, mode in fchmod_calls)


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

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home, **kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "_adoptable_guard_daemon_ports", lambda _guard_home, **kwargs: [5474])
    monkeypatch.setattr(
        daemon_manager_module,
        "_initialize_existing_guard_daemon",
        lambda _guard_home, port: {"url": f"http://127.0.0.1:{port}", "auth_token": "secret-token", "pid": 111},
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


@pytest.mark.parametrize(
    ("package_version", "runtime_fingerprint", "expected"),
    [
        (
            daemon_manager_module.__version__,
            daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            True,
        ),
        ("older-release", daemon_manager_module._current_guard_daemon_runtime_fingerprint(), False),
        (daemon_manager_module.__version__, "older-runtime", False),
        (None, None, False),
    ],
)
def test_daemon_adoption_requires_exact_installed_runtime(
    package_version: object,
    runtime_fingerprint: object,
    expected: bool,
) -> None:
    assert (
        daemon_manager_module._daemon_healthz_details_match_current_runtime(
            {
                "package_version": package_version,
                "runtime_fingerprint": runtime_fingerprint,
            }
        )
        is expected
    )


def test_initialize_existing_guard_daemon_rejects_stale_runtime(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"

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
                    "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                }
            ).encode("utf-8")

    monkeypatch.setattr(daemon_manager_module.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse())
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_auth_token", lambda _guard_home: "secret-token")
    monkeypatch.setattr(
        daemon_manager_module,
        "_daemon_healthz_details_payload",
        lambda _url, _token: {
            "guard_home": str(guard_home.resolve()),
            "package_version": daemon_manager_module.__version__,
            "runtime_fingerprint": "older-runtime",
            "pid": 111,
        },
    )

    assert daemon_manager_module._initialize_existing_guard_daemon(guard_home, 5474) is None


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

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(
        daemon_manager_module, "load_guard_daemon_url", lambda _guard_home, **kwargs: "http://127.0.0.1:5474"
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home, **kwargs: [(111, 5474), (222, 5475)],
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda pid, *, expected_guard_home=None: killed.append(pid) or True,
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5474"
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


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX signal retirement and omits native Windows process creation identities",
)
def test_ensure_guard_daemon_retires_stale_daemon_from_different_source_root(tmp_path, monkeypatch):
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
            "source_root": "/tmp/older-source-root",
            "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        },
    )
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
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    pid_running = {"value": True}

    def fake_pid_is_running(_pid):
        return pid_running["value"]

    def fake_kill(pid, _signal):
        killed.append(pid)
        pid_running["value"] = False

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", fake_pid_is_running)
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

    assert url == "http://127.0.0.1:5413"
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
    # Stale daemon-state.json is cleared when the pid belongs to a different command
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == {}


@pytest.mark.skipif(
    os.name == "nt",
    reason="models POSIX ephemeral-process enumeration and signal retirement",
)
def test_ensure_guard_daemon_reaps_stale_ephemeral_processes_without_state_file(tmp_path, monkeypatch):
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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
        lambda _guard_home: {"pid": 55_555, "port": 4781, "guard_home": str(guard_home)},
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [],
    )

    def retire(pid: int, *, expected_guard_home: Path | None = None) -> bool:
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
        lambda _guard_home: {"pid": 55_555, "port": 4781, "guard_home": str(guard_home)},
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
        lambda _guard_home: {"pid": 55_555, "port": 4781, "guard_home": str(guard_home)},
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
    retire.assert_called_once_with(55_555, expected_guard_home=guard_home)


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


def test_guard_daemon_pid_matches_command_validates_guard_home_on_windows(tmp_path, monkeypatch):
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

    trusted_powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    captured_commands: list[list[str]] = []
    monkeypatch.setattr(daemon_manager_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(
        daemon_manager_module,
        "windows_command_line_to_argv",
        lambda raw_command: parsed_command if raw_command == command else None,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_trusted_windows_powershell_path",
        lambda: trusted_powershell,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_bounded_process_query_stdout",
        lambda invoked, **_kwargs: captured_commands.append(invoked) or command,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_home_from_command",
        lambda _command: expected_guard_home,
    )

    assert daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=expected_guard_home,
    )
    assert not daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=tmp_path / "other-home",
    )
    assert captured_commands
    assert all(invoked[0] == trusted_powershell for invoked in captured_commands)
    assert all("-NoProfile" in invoked and "-NonInteractive" in invoked for invoked in captured_commands)


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
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_lock", lambda _guard_home: nullcontext())
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

    def record_pending(_guard_home, *, process, port):
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
    state = {"pid": 62_222, "port": 5410, "guard_home": str(guard_home)}
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


def test_windows_daemon_inventory_is_bounded_strict_and_guard_home_scoped(tmp_path, monkeypatch) -> None:
    guard_home = tmp_path / "guard home"
    query_commands: list[list[str]] = []
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
    monkeypatch.setattr(daemon_manager_module, "_trusted_windows_powershell_path", lambda: "powershell.exe")
    monkeypatch.setattr(daemon_manager_module, "_split_process_command", lambda _command: daemon_parts)

    def bounded(command):
        query_commands.append(command)
        return json.dumps(
            [
                {"ProcessId": 0, "CommandLine": None},
                {"ProcessId": 63_333, "CommandLine": "native command line"},
            ]
        )

    monkeypatch.setattr(daemon_manager_module, "_bounded_process_query_stdout", bounded)

    assert daemon_manager_module._guard_daemon_process_inventory_for_guard_home(guard_home) == [(63_333, 5410)]
    assert "$ErrorActionPreference = 'Stop'" in query_commands[0][-1]
    assert "ConvertTo-Json" in query_commands[0][-1]


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

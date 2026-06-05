"""L314: No-dashboard approval URL wake tests.

Verifies that Guard starts the daemon and surfaces the approval URL even when
no browser dashboard is open (e.g., CLI-only or headless environments).
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


def _make_start_mock(guard_home: Path, port: int = 5700):
    """Return a Popen-compatible fake that writes a valid state file immediately."""

    import os

    state_dir = guard_home / ".guard"
    state_dir.mkdir(parents=True, exist_ok=True)

    class FakeProcess:
        pid = 12345
        returncode = None

        def poll(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    def _popen(*_args, **_kwargs):
        state = {
            "port": port,
            "pid": FakeProcess.pid,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": daemon_manager_module._current_guard_daemon_source_root(),
            "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        }
        state_path = state_dir / "daemon-state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        os.chmod(state_path, stat.S_IRUSR | stat.S_IWUSR)
        return FakeProcess()

    return _popen


class TestNoDashboardApprovalURLWake:
    """L314: daemon must start and expose the approval URL with no browser open."""

    def test_ensure_guard_daemon_returns_url_when_no_daemon_running(self, tmp_path, monkeypatch) -> None:
        """When no daemon is running and the dashboard is closed, ensure_guard_daemon
        starts the daemon and returns a usable approval URL."""
        guard_home = tmp_path / "guard-home"
        port = 5700

        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )

        url_iter = iter([None, None, f"http://127.0.0.1:{port}"])
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _gh: next(url_iter, f"http://127.0.0.1:{port}"),
        )

        monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _gh: None)
        monkeypatch.setattr(daemon_manager_module, "_running_guard_daemon_processes_for_guard_home", lambda _gh: [])
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _gh: False)
        monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _: None)
        monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", _make_start_mock(guard_home, port))
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_guard_daemon_url",
            lambda _gh, **_kw: f"http://127.0.0.1:{port}",
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url == f"http://127.0.0.1:{port}"
        assert url.startswith("http://127.0.0.1:")

    def test_ensure_guard_daemon_does_not_spawn_second_daemon_when_already_running(self, tmp_path, monkeypatch) -> None:
        """If the daemon state file is already present and healthy, ensure_guard_daemon
        must return the existing URL without spawning a new process."""
        guard_home = tmp_path / "guard-home"
        port = 5701
        spawn_calls: list[str] = []

        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _gh: f"http://127.0.0.1:{port}",
        )
        monkeypatch.setattr(daemon_manager_module, "_running_guard_daemon_processes_for_guard_home", lambda _gh: [])

        def _boom(*_args, **_kwargs):
            spawn_calls.append("spawn")
            raise AssertionError("daemon must not be spawned when already running")

        monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", _boom)

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url == f"http://127.0.0.1:{port}"
        assert spawn_calls == []

    def test_approval_url_has_expected_structure(self, tmp_path, monkeypatch) -> None:
        """The returned approval URL must be a valid localhost HTTP URL."""
        guard_home = tmp_path / "guard-home"
        port = 5702

        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _gh: f"http://127.0.0.1:{port}",
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url.startswith("http://"), "URL must be HTTP"
        assert "127.0.0.1" in url or "localhost" in url, "URL must be local"
        assert str(port) in url, "URL must include the daemon port"

    def test_approval_url_exposed_without_browser_open(self, tmp_path, monkeypatch) -> None:
        """Guard must provide an approval URL for CLI/headless consumers
        even when webbrowser.open is never called."""
        import webbrowser

        guard_home = tmp_path / "guard-home"
        port = 5703
        browser_opens: list[str] = []

        def _fake_browser_open(url: str, *_args, **_kwargs) -> None:
            browser_opens.append(url)

        monkeypatch.setattr(webbrowser, "open", _fake_browser_open)
        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _gh: f"http://127.0.0.1:{port}",
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url is not None
        assert len(browser_opens) == 0, "ensure_guard_daemon must not open a browser on its own"

    def test_daemon_wake_survives_stale_state_file(self, tmp_path, monkeypatch) -> None:
        """When the state file references a dead process, the daemon must be retired
        and a new daemon started to handle the approval URL."""
        guard_home = tmp_path / "guard-home"
        port = 5704

        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )

        stale_state = {
            "pid": 99999,
            "port": 4000,
            "compatibility_version": "0.0.0-stale",
            "source_root": "/tmp/old-install/guard",
            "runtime_fingerprint": "stale-fingerprint",
        }
        url_iter = iter([None, None, f"http://127.0.0.1:{port}"])
        monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _gh: stale_state)
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _gh: next(url_iter, f"http://127.0.0.1:{port}"),
        )
        retire_calls: list[dict] = []
        monkeypatch.setattr(
            daemon_manager_module,
            "_retire_guard_daemon_process",
            lambda state: retire_calls.append(state),
        )
        monkeypatch.setattr(daemon_manager_module, "_running_guard_daemon_processes_for_guard_home", lambda _gh: [])
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _gh: False)
        monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _: None)
        monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", _make_start_mock(guard_home, port))
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_guard_daemon_url",
            lambda _gh, **_kw: f"http://127.0.0.1:{port}",
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url == f"http://127.0.0.1:{port}"
        assert len(retire_calls) >= 1, "_retire_guard_daemon_process must be called to recover stale daemon state"

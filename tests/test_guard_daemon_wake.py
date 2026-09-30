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

        def wait(self, timeout=None):
            return 0

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
        even when the shared browser opener is never called."""
        from codex_plugin_scanner.guard import browser_opener

        guard_home = tmp_path / "guard-home"
        port = 5703
        browser_opens: list[str] = []

        def _fake_browser_open(url: str, *_args, **_kwargs) -> None:
            browser_opens.append(url)

        monkeypatch.setattr(browser_opener, "open_browser_url", _fake_browser_open)
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
            lambda state: retire_calls.append(state) or True,
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


class TestDaemonLifecycle:
    def test_daemon_shutdown_only_clears_own_state(self, tmp_path) -> None:
        """A retired duplicate daemon must not erase the active daemon state file."""
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        daemon_manager_module.write_guard_daemon_state(guard_home, 5705, "token-1", pid=111)

        cleared = daemon_manager_module.clear_guard_daemon_state_if_current(guard_home, pid=222, port=5706)
        state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))

        assert cleared is False
        assert state["pid"] == 111
        assert state["port"] == 5705

        assert daemon_manager_module.clear_guard_daemon_state_if_current(guard_home, pid=111, port=5705) is True
        assert json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8")) == {}

    def test_retiring_duplicate_daemons_rewrites_kept_state_after_old_exit(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        """Old duplicate daemons may clear daemon-state.json on exit; rewrite the kept daemon state."""
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        daemon_manager_module.write_guard_daemon_state(guard_home, 5707, "token-1", pid=111)
        killed: list[int] = []

        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [(111, 5707), (222, 5708)] if not (guard_home / "retired").exists() else [(111, 5707)],
        )

        def fake_retire(pid: int, *, expected_guard_home: Path | None = None) -> bool:
            del expected_guard_home
            killed.append(pid)
            daemon_manager_module.clear_guard_daemon_state(guard_home)
            (guard_home / "retired").write_text("1", encoding="utf-8")
            return True

        monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", fake_retire)
        monkeypatch.setattr(
            daemon_manager_module,
            "_daemon_healthz_details_payload",
            lambda _url, _auth_token: {"guard_home": str(guard_home), "pid": 111},
        )

        daemon_manager_module._retire_duplicate_guard_daemons(guard_home, keep_port=5707)
        state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))

        assert killed == [222]
        assert state["pid"] == 111
        assert state["port"] == 5707

    def test_retiring_duplicate_daemons_does_not_rewrite_when_retire_fails(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        """A duplicate that could not be retired must block kept-state recovery."""
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        daemon_manager_module.write_guard_daemon_state(guard_home, 5709, "token-1", pid=111)

        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [(111, 5709), (222, 5710)],
        )

        def fake_retire(_pid: int, *, expected_guard_home: Path | None = None) -> bool:
            del expected_guard_home
            daemon_manager_module.clear_guard_daemon_state(guard_home)
            return False

        monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", fake_retire)

        daemon_manager_module._retire_duplicate_guard_daemons(guard_home, keep_port=5709)

        assert json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8")) == {}

    def test_retiring_duplicate_daemons_requires_kept_daemon_auth(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        """Do not recover state with a token that cannot authenticate to the kept daemon."""
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        daemon_manager_module.write_guard_daemon_state(guard_home, 5711, "token-1", pid=111)

        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [(111, 5711), (222, 5712)] if not (guard_home / "retired").exists() else [(111, 5711)],
        )

        def fake_retire(_pid: int, *, expected_guard_home: Path | None = None) -> bool:
            del expected_guard_home
            daemon_manager_module.clear_guard_daemon_state(guard_home)
            (guard_home / "retired").write_text("1", encoding="utf-8")
            return True

        monkeypatch.setattr(daemon_manager_module, "_retire_guard_daemon_pid", fake_retire)
        monkeypatch.setattr(daemon_manager_module, "_daemon_healthz_details_payload", lambda _url, _auth_token: None)

        daemon_manager_module._retire_duplicate_guard_daemons(guard_home, keep_port=5711)

        assert json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8")) == {}


class _FakeSpawnedDaemonProcess:
    """Popen-compatible fake that records termination attempts."""

    def __init__(self, pid: int = 424242, returncode: int | None = None) -> None:
        self.pid = pid
        self.returncode = returncode
        self.stdin = None
        self.terminated = False
        self.killed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode if self.returncode is not None else 0


class TestSpawnedDaemonStartClassification:
    """A spawned daemon still starting at the deadline must not be killed."""

    def test_classify_spawned_daemon_dead_when_exited(self) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        process = _FakeSpawnedDaemonProcess(returncode=1)
        assert (
            start_classification.classify_spawned_daemon(
                process,
                pending_launch_present=True,
                lock_held_by_spawned_tree=True,
                journal_start_requested_after=True,
            )
            == "dead"
        )

    def test_classify_spawned_daemon_progressing_when_lock_held_by_spawned_tree(self) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        process = _FakeSpawnedDaemonProcess()
        assert (
            start_classification.classify_spawned_daemon(
                process,
                pending_launch_present=True,
                lock_held_by_spawned_tree=True,
                journal_start_requested_after=False,
            )
            == "progressing"
        )

    def test_classify_spawned_daemon_progressing_on_newer_start_requested(self) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        process = _FakeSpawnedDaemonProcess()
        assert (
            start_classification.classify_spawned_daemon(
                process,
                pending_launch_present=True,
                lock_held_by_spawned_tree=False,
                journal_start_requested_after=True,
            )
            == "progressing"
        )

    def test_classify_spawned_daemon_blocked_with_no_progress_signals(self) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        process = _FakeSpawnedDaemonProcess()
        assert (
            start_classification.classify_spawned_daemon(
                process,
                pending_launch_present=True,
                lock_held_by_spawned_tree=False,
                journal_start_requested_after=False,
            )
            == "blocked"
        )

    def test_classify_spawned_daemon_blocked_without_pending_launch(self) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        process = _FakeSpawnedDaemonProcess()
        assert (
            start_classification.classify_spawned_daemon(
                process,
                pending_launch_present=False,
                lock_held_by_spawned_tree=True,
                journal_start_requested_after=True,
            )
            == "blocked"
        )

    def test_owner_lock_signal_requires_spawned_tree_inventory(self, tmp_path, monkeypatch) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        guard_home = tmp_path / "guard-home"
        monkeypatch.setattr(start_classification, "daemon_owner_lock_is_held", lambda _gh: True)
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_process_inventory_for_guard_home",
            lambda _gh: [(424242, 5700)],
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_parent_pid",
            lambda pid: 424242 if pid == 555555 else None,
        )
        assert start_classification.spawned_daemon_owner_lock_held(guard_home, root_pid=424242) is True
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_process_inventory_for_guard_home",
            lambda _gh: [(424242, 5700), (777777, 5701)],
        )
        assert start_classification.spawned_daemon_owner_lock_held(guard_home, root_pid=424242) is False
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_process_inventory_for_guard_home",
            lambda _gh: [(555555, 5700)],
        )
        assert start_classification.spawned_daemon_owner_lock_held(guard_home, root_pid=424242) is True
        monkeypatch.setattr(start_classification, "daemon_owner_lock_is_held", lambda _gh: False)
        assert start_classification.spawned_daemon_owner_lock_held(guard_home, root_pid=424242) is False

    def test_start_requested_journal_requires_spawned_tree_pid(self, tmp_path, monkeypatch) -> None:
        import os

        from codex_plugin_scanner.guard.daemon import start_classification
        from codex_plugin_scanner.guard.daemon.lifecycle_journal import record_daemon_lifecycle_event

        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        own_pid = os.getpid()
        record_daemon_lifecycle_event(guard_home, event="start_requested", pid=own_pid)
        record_daemon_lifecycle_event(guard_home, event="start_requested", pid=999999)

        # 999999 is a grandchild of the spawned root: 999999 -> 555555 -> own_pid.
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_parent_pid",
            lambda pid: {999999: 555555, 555555: own_pid}.get(pid),
        )
        assert (
            start_classification.daemon_journal_records_start_requested_after(
                guard_home, root_pid=own_pid, since_ns=1
            )
            is True
        )
        assert (
            start_classification.daemon_journal_records_start_requested_after(
                guard_home, root_pid=own_pid, since_ns=2**62
            )
            is False
        )

        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_parent_pid", lambda pid: None)
        other_home = tmp_path / "other-home"
        other_home.mkdir()
        record_daemon_lifecycle_event(other_home, event="start_requested", pid=888888)
        assert (
            start_classification.daemon_journal_records_start_requested_after(
                other_home, root_pid=own_pid, since_ns=1
            )
            is False
        )
        assert (
            start_classification.daemon_journal_records_start_requested_after(
                tmp_path / "missing", root_pid=own_pid, since_ns=1
            )
            is False
        )

    def _patch_ensure_deadline(
        self,
        monkeypatch,
        guard_home: Path,
        process: _FakeSpawnedDaemonProcess,
        *,
        owner_lock_held: bool,
        journal_wait: object = None,
    ) -> None:
        from codex_plugin_scanner.guard.daemon import start_classification

        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(daemon_manager_module, "reap_orphaned_daemon_workers", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _gh: None)
        monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _gh: None)
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _gh: False)
        monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _: None)
        monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "posix:token")
        monkeypatch.setattr(
            start_classification,
            "daemon_owner_lock_is_held",
            lambda _gh: owner_lock_held,
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_process_inventory_for_guard_home",
            lambda _gh: [(process.pid, 5700)] if owner_lock_held else [],
        )

        def fake_wait(_gh, **kwargs):
            if callable(journal_wait):
                journal_wait()
            return None

        monkeypatch.setattr(daemon_manager_module, "_wait_for_guard_daemon_url", fake_wait)

    def test_progressing_spawn_is_not_terminated_or_cleared(self, tmp_path, monkeypatch) -> None:
        import pytest

        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        process = _FakeSpawnedDaemonProcess()
        self._patch_ensure_deadline(monkeypatch, guard_home, process, owner_lock_held=True)

        with pytest.raises(RuntimeError, match=r"^Guard daemon is still starting"):
            daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        assert process.terminated is False
        assert process.killed is False
        assert not (guard_home / "daemon-launch-pending.json").is_file()
        assert not (guard_home / ".guard" / "daemon-state.json").is_file()

    def test_progressing_spawn_detected_by_newer_start_requested(self, tmp_path, monkeypatch) -> None:
        import pytest

        from codex_plugin_scanner.guard.daemon.lifecycle_journal import record_daemon_lifecycle_event

        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        process = _FakeSpawnedDaemonProcess()
        self._patch_ensure_deadline(
            monkeypatch,
            guard_home,
            process,
            owner_lock_held=False,
            journal_wait=lambda: record_daemon_lifecycle_event(
                guard_home, event="start_requested", pid=process.pid
            ),
        )

        with pytest.raises(RuntimeError, match=r"^Guard daemon is still starting"):
            daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        assert process.terminated is False

    def test_blocked_spawn_keeps_existing_termination_behavior(self, tmp_path, monkeypatch) -> None:
        import pytest

        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        process = _FakeSpawnedDaemonProcess()
        self._patch_ensure_deadline(monkeypatch, guard_home, process, owner_lock_held=False)

        with pytest.raises(RuntimeError, match=r"^Guard approval center did not start"):
            daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        assert process.terminated is True

    def test_unrecordable_progressing_spawn_falls_back_to_terminate(self, tmp_path, monkeypatch) -> None:
        """A progressing daemon we cannot re-identify on retry must not stay alive."""

        import pytest

        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        process = _FakeSpawnedDaemonProcess()
        self._patch_ensure_deadline(monkeypatch, guard_home, process, owner_lock_held=True)
        monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: None)

        with pytest.raises(RuntimeError, match=r"^Guard approval center did not start"):
            # The patched readiness wait models expiry after the process spawns.
            daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        assert process.terminated is True
        assert not (guard_home / "daemon-start-progress.json").is_file()


class TestStillStartingAdoption:
    """The next ensure call adopts a recorded still-starting daemon."""

    def _patch_baseline(self, monkeypatch, guard_home: Path) -> dict[str, list]:
        calls: dict[str, list] = {"popen": [], "retire": []}
        monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_: None)
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _gh: None)
        monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _gh: None)
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_start_in_progress", lambda _gh: False)
        monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _: None)
        monkeypatch.setattr(
            daemon_manager_module.subprocess,
            "Popen",
            lambda *a, **k: calls["popen"].append(a[0]) or _FakeSpawnedDaemonProcess(),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "retire_all_guard_daemons_for_home",
            lambda _gh, **_kw: calls["retire"].append(1),
        )
        return calls

    def _record(self, pid: int = 424242, *, guard_home: Path | None = None) -> dict:
        return {
            "state_kind": "daemon_start_progress",
            "guard_home": str((guard_home or Path("/tmp/ignored")).resolve()),
            "pid": pid,
            "port": 5700,
            "process_start_token": "posix:token",
            "recorded_at_ns": 1,
            "spawned_at_ns": 1,
        }

    def test_retry_adopts_progressing_daemon_without_spawn(self, tmp_path, monkeypatch) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        calls = self._patch_baseline(monkeypatch, guard_home)
        cleared: list[int] = []
        monkeypatch.setattr(
            daemon_manager_module,
            "load_authenticated_guard_daemon_start_progress",
            lambda _gh: self._record(),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_start_progress_is_live",
            lambda _gh, _record: True,
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_clear_guard_daemon_start_progress",
            lambda _gh: cleared.append(1),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_guard_daemon_url",
            lambda _gh, **_kw: "http://127.0.0.1:5700",
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url == "http://127.0.0.1:5700"
        daemon_spawns = [cmd for cmd in calls["popen"] if "daemon" in str(cmd)]
        assert daemon_spawns == []
        assert calls["retire"] == []
        assert cleared == [1]

    def test_dead_record_is_cleared_and_spawn_proceeds(self, tmp_path, monkeypatch) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        calls = self._patch_baseline(monkeypatch, guard_home)
        cleared: list[int] = []
        monkeypatch.setattr(
            daemon_manager_module,
            "load_authenticated_guard_daemon_start_progress",
            lambda _gh: self._record(pid=424242),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_start_progress_is_live",
            lambda _gh, _record: False,
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_clear_guard_daemon_start_progress",
            lambda _gh: cleared.append(1),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_guard_daemon_url",
            lambda _gh, **_kw: "http://127.0.0.1:5700",
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        assert url == "http://127.0.0.1:5700"
        assert cleared == [1]
        daemon_spawns = [cmd for cmd in calls["popen"] if "daemon" in str(cmd)]
        assert len(daemon_spawns) == 1

    def test_still_progressing_pid_raises_again_without_kill(self, tmp_path, monkeypatch) -> None:
        import pytest

        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        calls = self._patch_baseline(monkeypatch, guard_home)
        monkeypatch.setattr(
            daemon_manager_module,
            "load_authenticated_guard_daemon_start_progress",
            lambda _gh: self._record(pid=424242),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_start_progress_is_live",
            lambda _gh, _record: True,
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_guard_daemon_url",
            lambda _gh, **_kw: None,
        )
        monkeypatch.setattr(
            daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "daemon_still_starting_evidence_present",
            lambda _gh, **_kw: True,
        )

        with pytest.raises(RuntimeError, match=r"^Guard daemon is still starting"):
            daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        daemon_spawns = [cmd for cmd in calls["popen"] if "daemon" in str(cmd)]
        assert daemon_spawns == []
        assert calls["retire"] == []

    def test_blocked_record_falls_back_to_retirement(self, tmp_path, monkeypatch) -> None:
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        calls = self._patch_baseline(monkeypatch, guard_home)
        monkeypatch.setattr(
            daemon_manager_module,
            "load_authenticated_guard_daemon_start_progress",
            lambda _gh: self._record(pid=424242),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_start_progress_is_live",
            lambda _gh, _record: True,
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_guard_daemon_url",
            lambda _gh, **_kw: None,
        )
        monkeypatch.setattr(
            daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: False
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_wait_for_started_guard_daemon_url",
            lambda _gh, **_kw: "http://127.0.0.1:5701",
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "guard_daemon_retirement_is_complete",
            lambda _gh: True,
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home, start_timeout=30.0, home_dir=tmp_path)

        assert url == "http://127.0.0.1:5701"
        assert calls["retire"] == [1]
        daemon_spawns = [cmd for cmd in calls["popen"] if "daemon" in str(cmd)]
        assert len(daemon_spawns) == 1

    def test_windows_pending_launch_retire_skips_live_start_progress(self, tmp_path, monkeypatch) -> None:
        """A live still-starting record exempts its pid from the previous-launch retire."""
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir()
        (guard_home / "daemon-launch-pending.json").write_text("{}", encoding="utf-8")
        pending_loads: list[int] = []
        monkeypatch.setattr(daemon_manager_module.os, "name", "nt")
        monkeypatch.setattr(
            daemon_manager_module,
            "load_authenticated_guard_daemon_pending_launch",
            lambda _gh: pending_loads.append(1) or {"pid": 424242},
        )

        assert (
            daemon_manager_module._windows_pending_launch_needs_retirement(
                guard_home, progress_is_live=True
            )
            is False
        )
        assert pending_loads == []
        assert (
            daemon_manager_module._windows_pending_launch_needs_retirement(
                guard_home, progress_is_live=False
            )
            is True
        )

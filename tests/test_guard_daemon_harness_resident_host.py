"""The test daemon's server view reads the hook worker that reviewed the daemon's hooks.

The native daemon hands each hook review to the resident library, which the
harness runs in the test process. The Gauntlet taps that worker's reviews and
reads its route metrics to prove which route answered, so a view that built a
second worker would see no hook at all and every live case would end unproven.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_observe_mode_liveness import _review_request


@pytest.mark.usefixtures("native_hook_force")
def test_the_view_reads_the_worker_that_reviewed_the_daemons_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    before_start = daemon._server.hook_worker
    seeded = daemon._server.request_capacity
    daemon.start()
    # Keep Oh My Pi hooks off the resident's direct lane so the daemon reviews them.
    monkeypatch.setenv("HOL_GUARD_PI_DIRECT_HOOK", "0")
    try:
        worker = daemon._server.hook_worker
        assert worker is not before_start
        # State a test seeds before the daemon runs stays the state it reads back.
        assert daemon._server.request_capacity is seeded
        reviewed: list[dict[str, Any]] = []
        original = worker.review_http_payload

        def tapped(**kwargs: Any) -> Any:
            reviewed.append(kwargs)
            return original(**kwargs)

        monkeypatch.setattr(worker, "review_http_payload", tapped)
        payload = _review_request(daemon, endpoint="omp", guard_home=guard_home, workspace=workspace)
        assert payload.get("decision") in {"allow", "deny"}
        assert len(reviewed) == 1
        assert worker.metrics.snapshot()["routes"].get("native_resident", 0) >= 1
        assert daemon._server.hook_worker is worker
    finally:
        daemon.stop()


class _Worker:
    def __init__(self, closes: bool) -> None:
        self.closes = closes
        self.deadline: float | None = None

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        self.deadline = deadline_monotonic
        return self.closes


class _Stoppable:
    def __init__(self) -> None:
        self.stopped = False

    def stop(self, timeout_seconds: float = 1.0) -> bool:
        self.stopped = True
        return True


class _Host:
    def __init__(self, worker: _Worker) -> None:
        self.hook_worker = worker
        self.runtime_resident_evidence_dispatch = _Stoppable()
        self.runtime_hook_evidence_writer = _Stoppable()
        self.closed = False

    def server_close(self) -> None:
        self.closed = True


def _daemon_with_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: _Host) -> GuardDaemonServer:
    from codex_plugin_scanner.guard.routes import hook_calls

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    other = _Host(_Worker(closes=True))
    monkeypatch.setattr(hook_calls, "_SERVERS", {str(guard_home): host, str(tmp_path / "other-home"): other})
    daemon = GuardDaemonServer.__new__(GuardDaemonServer)
    daemon.store = GuardStore(guard_home)

    class _Native:
        _process = None

        def stop(self) -> None:
            pass

    class _Library:
        def close(self) -> None:
            pass

    daemon._daemon = _Native()
    daemon._library = _Library()
    return daemon


def test_stop_retires_the_in_process_hook_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The host's policy publisher kept calling the resident after the daemon
    # stopped, restarting it while cleanup tried to stop it.
    from codex_plugin_scanner.guard.routes import hook_calls

    host = _Host(_Worker(closes=True))
    daemon = _daemon_with_host(tmp_path, monkeypatch, host)
    daemon.stop()
    assert host.hook_worker.deadline is not None
    assert host.runtime_resident_evidence_dispatch.stopped
    assert host.runtime_hook_evidence_writer.stopped
    assert host.closed
    assert list(hook_calls._SERVERS) == [str(tmp_path / "other-home")]
    assert daemon._finish_service() is True


def test_a_host_that_does_not_stop_fails_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = _daemon_with_host(tmp_path, monkeypatch, _Host(_Worker(closes=False)))
    daemon.stop()
    assert daemon._finish_service() is False

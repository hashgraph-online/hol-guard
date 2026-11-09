"""The daemon handler answers a raw request replayed through the Guard CLI."""

from __future__ import annotations

import json
import stat
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import request_replay, request_replay_state
from codex_plugin_scanner.guard.daemon.mcp_discovery_jobs import DiscoveryJobError
from codex_plugin_scanner.guard.daemon.request_replay import replay_request, wait_for_background_work
from codex_plugin_scanner.guard.daemon.request_replay_state import (
    _PersistedMapping,
    _ReplayDiscoveryJobs,
    _ReplayState,
    _SyncedLock,
)


def _status(response: bytes) -> int:
    return int(response.split(b"\r\n", 1)[0].split(b" ")[1])


def _body(response: bytes) -> dict[str, object]:
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def test_replay_answers_health(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    response = replay_request(
        guard_home, b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", port=5474, home_dir=tmp_path
    )
    assert _status(response) == 200
    assert _body(response).get("ok") is True


def test_replay_state_survives_between_processes(tmp_path: Path) -> None:
    mapping = _PersistedMapping(_ReplayState(tmp_path), "daemon_discovery_challenges")
    mapping["challenge"] = {"expires_at": 1}
    reread = _PersistedMapping(_ReplayState(tmp_path), "daemon_discovery_challenges")
    assert reread == {"challenge": {"expires_at": 1}}
    state_file = tmp_path / request_replay_state._STATE_FILENAME
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    reread.pop("challenge")
    assert _PersistedMapping(_ReplayState(tmp_path), "daemon_discovery_challenges") == {}


def test_replay_state_ignores_a_symlinked_file(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"daemon_discovery_challenges": {"x": 1}}))
    (tmp_path / request_replay_state._STATE_FILENAME).symlink_to(target)
    assert _ReplayState(tmp_path).get("daemon_discovery_challenges") is None


def test_a_consumed_nonce_is_gone_for_the_next_process(tmp_path: Path) -> None:
    first_state, second_state = _ReplayState(tmp_path), _ReplayState(tmp_path)
    first = _PersistedMapping(first_state, "package_firewall_session_nonces")
    second = _PersistedMapping(second_state, "package_firewall_session_nonces")
    first["nonce"] = 1.0
    with _SyncedLock(second_state, second):
        assert second.pop("nonce", None) == 1.0
    with _SyncedLock(first_state, first):
        assert first.pop("nonce", None) is None


def test_the_replay_lock_is_reentrant(tmp_path: Path) -> None:
    state = _ReplayState(tmp_path)
    mapping = _PersistedMapping(state, "daemon_discovery_challenges")
    with _SyncedLock(state, mapping):
        mapping["c"] = 1
        assert state.get("daemon_discovery_challenges") == {"c": 1}


def test_the_replay_lock_fails_closed_without_file_locking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(request_replay_state, "fcntl", None)
    state = _ReplayState(tmp_path)
    with pytest.raises(OSError):
        state.set("daemon_discovery_challenges", {"c": 1})
    assert not (tmp_path / request_replay_state._STATE_FILENAME).exists()


def test_a_planted_temporary_link_is_not_followed(tmp_path: Path) -> None:
    import os

    target = tmp_path / "elsewhere.json"
    target.write_text("keep")
    planted = tmp_path / f".{request_replay_state._STATE_FILENAME}.{os.getpid()}.{threading.get_ident()}"
    planted.symlink_to(target)
    _ReplayState(tmp_path).set("daemon_discovery_challenges", {"c": 1})
    assert target.read_text() == "keep"
    assert _ReplayState(tmp_path).get("daemon_discovery_challenges") == {"c": 1}


def test_a_connection_bound_challenge_is_unavailable(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    response = replay_request(
        guard_home,
        b"POST /v1/daemon/identity-challenge HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
        port=5474,
        home_dir=tmp_path,
    )
    assert _status(response) == 503
    assert _body(response) == {"error": "daemon_route_unavailable"}
    assert not (guard_home / request_replay_state._STATE_FILENAME).exists()


def test_discovery_jobs_are_read_and_cancelled_from_another_process(tmp_path: Path) -> None:
    started = threading.Event()

    def run(cancel: threading.Event) -> None:
        started.set()
        _ = cancel.wait(5)

    owner = _ReplayDiscoveryJobs(_ReplayState(tmp_path))
    job = owner.start("inventory:configured", run)
    assert started.wait(2)
    other = _ReplayDiscoveryJobs(_ReplayState(tmp_path))
    job_id = str(job["job_id"])
    assert other.read(job_id)["state"] == "running"
    assert other.start("inventory:configured", run)["job_id"] == job_id
    assert other.read(job_id, cancel=True)["state"] == "cancelling"
    deadline = time.monotonic() + 5
    while other.read(job_id)["state"] != "cancelled" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert other.read(job_id)["state"] == "cancelled"


def test_a_missing_discovery_job_is_unavailable(tmp_path: Path) -> None:
    jobs = _ReplayDiscoveryJobs(_ReplayState(tmp_path))
    with pytest.raises(DiscoveryJobError):
        _ = jobs.read("0" * 32)
    assert jobs.read("0" * 32, cancel=True)["state"] == "cancelled"
    assert jobs.start("x", lambda _cancel: None, requested_job_id="0" * 32)["state"] == "cancelled"


def test_a_job_whose_owner_died_reads_as_failed(tmp_path: Path) -> None:
    state = _ReplayState(tmp_path)
    state.set(
        "mcp_discovery_jobs",
        {"a" * 32: {"cli_id": "x", "state": "running", "started": time.time(), "owner": 2**22 + 12345}},
    )
    assert _ReplayDiscoveryJobs(state).read("a" * 32)["state"] == "failed"


def test_background_work_waits_for_a_connect_flow(tmp_path: Path) -> None:
    del tmp_path
    finished = threading.Event()

    def flow() -> None:
        time.sleep(0.2)
        finished.set()

    threading.Thread(target=flow, name="guard-cloud-connect", daemon=True).start()
    wait_for_background_work()
    assert finished.is_set()


def test_the_replay_server_names_the_edge_daemon(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    server = request_replay._replay_server_class()(GuardStore(guard_home), 5474, "127.0.0.1", tmp_path, "", 4242)
    try:
        assert server.daemon_pid() == 4242
    finally:
        server.server_close()

"""Real process exclusion at the native-review/local-reuse boundary."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_review_fence import native_review_fence
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock

from .test_guard_extension_control_authority import MemorySecretStore, _store
from .test_native_review_approval_coordination import _worker
from .test_native_review_policy_binding import _bound_edge, _resolve, _review


@pytest.mark.parametrize("outcome", ["reuse", "block", "unavailable", "exception"])
def test_worker_finalization_deadline_preserves_route_and_releases_lease(tmp_path, monkeypatch, outcome) -> None:
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    monkeypatch.setattr(
        worker,
        "_native_policy_snapshot",
        lambda *_args, **_kwargs: {"mode": "enforce", "command_extensions_bound": True},
    )
    routes = []
    monkeypatch.setattr(worker.metrics, "record_route", routes.append)
    try:
        _resolve(store, _review(worker, tmp_path))
        routes.clear()
        now = time.monotonic()
        deadline = now + 5
        clock = [now]
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.daemon.hook_worker_native.time", SimpleNamespace(monotonic=lambda: clock[0])
        )

        def evaluate(**_kwargs):
            clock[0] = deadline + 1
            if outcome == "exception":
                raise RuntimeError("injected edge failure")
            if outcome == "unavailable":
                return None
            if outcome == "block":
                edge["result"].update(minimum_action="block", policy_action="block", reason_code="native_core_block")
            return edge

        monkeypatch.setattr(worker, "_review_raw_hook_native", evaluate)
        arguments = {
            "payload": {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cat .env"},
            },
            "harness": "cursor",
            "event_name": "PreToolUse",
            "default_harness": "cursor",
            "home_dir": tmp_path / "home",
            "guard_home": store.guard_home,
            "workspace": tmp_path / "workspace",
            "deadline": deadline,
        }
        if outcome == "exception":
            with pytest.raises(RuntimeError, match="injected edge failure"):
                worker._review_native_edge(**arguments)
            assert routes == []
        else:
            response = worker._review_native_edge(**arguments)
            if outcome == "block":
                assert response["policy_action"] == "block"
                assert response["reason_code"] == "native_core_block"
                assert routes == ["native_resident"]
            else:
                assert response.get("approval_reuse_status") != "accepted"
                assert len(routes) == 1 and routes[0] in {"native_degraded", "native_fail_safe"}
        with hold_command_control_authority_lock(store.guard_home, timeout_seconds=0):
            pass
    finally:
        worker.close()


def _fence(home: Path, *, deadline: float | None = None, **changes):
    arguments = {
        "policy_snapshot": {"command_extensions_bound": True},
        "event_name": "PreToolUse",
        "recording_only": False,
        "guard_home": home,
        "deadline": deadline,
    }
    return native_review_fence(**(arguments | changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"policy_snapshot": None},
        {"policy_snapshot": {}},
        {"event_name": "PostToolUse"},
        {"recording_only": True},
    ],
)
def test_unbound_post_and_observe_paths_do_not_open_lock(tmp_path, changes) -> None:
    with _fence(tmp_path / "does-not-exist", **changes) as fenced:
        assert not fenced


def test_timeout_and_exception_release_review_lease(tmp_path) -> None:
    with pytest.raises(TimeoutError), _fence(tmp_path, deadline=time.monotonic() - 1):
        pytest.fail("expired review was admitted")
    with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
        pass
    with pytest.raises(RuntimeError), _fence(tmp_path, deadline=time.monotonic() + 5):
        raise RuntimeError("injected reuse failure")
    with hold_command_control_authority_lock(tmp_path, timeout_seconds=0):
        pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe selection; Windows native lock overlap is a CI gate")
def test_cross_process_stricter_commit_waits_for_paused_reuse(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    secrets = MemorySecretStore()
    owner = _store(tmp_path / "guard-home", secrets)
    worker, store = _worker(tmp_path, monkeypatch, _bound_edge(), publish_native_policy=False)
    monkeypatch.setattr(
        worker,
        "_native_policy_snapshot",
        lambda *_args, **_kwargs: {
            "mode": "enforce",
            "command_extensions_bound": True,
        },
    )
    entered, release = threading.Event(), threading.Event()
    outcome: list[object] = []
    process = None
    thread = None
    try:
        _resolve(store, _review(worker, tmp_path))
        import codex_plugin_scanner.guard.daemon.hook_native_review_approval as approval

        original = approval._native_review_matching_allow

        def paused(*args, **kwargs):
            entered.set()
            assert release.wait(10)
            return original(*args, **kwargs)

        monkeypatch.setattr(approval, "_native_review_matching_allow", paused)

        def review():
            try:
                outcome.append(_review(worker, tmp_path))
            except BaseException as error:
                outcome.append(error)

        script = """
import contextlib, json, pathlib, sys
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_extension_control_authority import MemorySecretStore, _commit
secrets = MemorySecretStore()
secrets.values = json.loads(sys.stdin.readline())
store = GuardStore(pathlib.Path(sys.argv[1]), prime_policy_integrity=False)
store._extension_control_authority_secret_store = secrets
original = store._extension_control_authority_lock
@contextlib.contextmanager
def observed(*args, **kwargs):
    print('waiting', flush=True)
    with original(*args, **kwargs):
        yield
store._extension_control_authority_lock = observed
print('ready', flush=True)
assert sys.stdin.readline().strip() == 'commit'
_commit(store)
print('committed', flush=True)
"""
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(owner.guard_home)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps(secrets.values) + "\n")
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 8)[0]
        assert process.stdout.readline() == "ready\n"
        # Store initialization may acquire the same authority fence. Finish it
        # before starting the timed review so this measures commit contention,
        # not child imports or an unobserved initialization lock.
        thread = threading.Thread(target=review)
        thread.start()
        assert entered.wait(5)
        process.stdin.write("commit\n")
        process.stdin.flush()
        assert select.select([process.stdout], [], [], 8)[0]
        assert process.stdout.readline() == "waiting\n"
        assert process.poll() is None
        with owner._connect() as connection:
            assert connection.execute("select revision from extension_control_authority_snapshot").fetchone()[0] == 0
        release.set()
        thread.join(5)
        assert not thread.is_alive()
        assert len(outcome) == 1 and isinstance(outcome[0], dict)
        assert outcome[0]["approval_reuse_status"] == "accepted"
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
        assert "committed" in stdout
        with owner._connect() as connection:
            assert connection.execute("select revision from extension_control_authority_snapshot").fetchone()[0] == 1
    finally:
        release.set()
        if thread is not None:
            thread.join(5)
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        worker.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX inherited-context boundary")
def test_fork_unwind_does_not_release_parent_review_lease(tmp_path) -> None:
    parent = os.getpid()
    try:
        with _fence(tmp_path):
            child = os.fork()
            if child == 0:
                return
            _, status = os.waitpid(child, 0)
            assert os.waitstatus_to_exitcode(status) == 0
            script = """
import fcntl, pathlib, sys
with (pathlib.Path(sys.argv[1]) / 'extension-control-authority.lock').open('r+b') as handle:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)
    sys.exit(2)
"""
            result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], timeout=5, check=False)
            assert result.returncode == 0
    finally:
        if os.getpid() != parent:
            os._exit(0)

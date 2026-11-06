"""Concurrent lifecycle callers must not discover or mutate the same files."""

import multiprocessing
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from threading import Event

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.codex_lifecycle_lock import (
    _account_home as real_account_home,
)
from codex_plugin_scanner.guard.adapters.codex_lifecycle_lock import (
    _lifecycle_lock_path,
    codex_configuration_lock,
    codex_lifecycle_locks,
)
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction


def test_core_publication_transaction_shares_configuration_exclusion(tmp_path, lifecycle_account_home):
    home = tmp_path / "home"
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "first-guard")
    other_guard = tmp_path / "second-guard"

    def competing_publication():
        with codex_install_transaction(
            other_guard,
            home / ".codex/config.toml",
            actor="competing-publication",
            deadline=time.monotonic() + 1,
        ):
            return "foreign transaction admitted"

    with codex_lifecycle_locks(context), ThreadPoolExecutor(max_workers=1) as executor:
        competing = executor.submit(competing_publication)
        with pytest.raises(TimeoutError, match="Codex lifecycle transaction deadline exceeded"):
            competing.result(timeout=5)
    assert not other_guard.exists(), "competing transaction must refuse before Guard-home writes"


def test_nested_core_configuration_ownership_preserves_the_first_io_error(tmp_path, lifecycle_account_home):
    home = tmp_path / "home"
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")
    injected = OSError("injected publication failure")
    with codex_lifecycle_locks(context):
        with (
            pytest.raises(OSError) as failure,
            codex_configuration_lock(home / ".codex/config.toml", deadline=time.monotonic() + 1),
        ):
            raise injected
        assert failure.value is injected


@pytest.fixture(autouse=True)
def lifecycle_account_home(tmp_path, monkeypatch):
    """Keep every lifecycle test's lock metadata outside the real account home."""
    import codex_plugin_scanner.guard.adapters.codex_lifecycle_lock as locks

    profile = tmp_path / "account-profile"
    profile.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "_account_home", lambda: profile)
    return profile


@pytest.mark.parametrize("competing_operation", ("install", "uninstall"))
def test_competing_lifecycle_call_is_rejected_before_discovery(tmp_path, monkeypatch, competing_operation):
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    entered = Event()
    release = Event()
    calls = []

    def paused_discovery(self, current_context):
        calls.append(current_context)
        entered.set()
        assert release.wait(5), "test owner was not released"
        raise RuntimeError("test_discovery_complete")

    monkeypatch.setattr(CodexHarnessAdapter, "detect", paused_discovery)
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(CodexHarnessAdapter().install, context)
        try:
            assert entered.wait(5), "test owner did not enter discovery"
            with pytest.raises(RuntimeError, match="codex_lifecycle_busy"):
                getattr(CodexHarnessAdapter(), competing_operation)(context)
            assert calls == [context]
        finally:
            release.set()
        with pytest.raises(RuntimeError, match="test_discovery_complete"):
            first.result(timeout=5)


def _hold_process_lock(home, guard_home, account_home, connection):
    import codex_plugin_scanner.guard.adapters.codex_lifecycle_lock as locks

    locks._account_home = lambda: Path(account_home)
    context = HarnessContext(home_dir=Path(home), workspace_dir=None, guard_home=Path(guard_home))
    with codex_lifecycle_locks(context):
        connection.send(True)
        connection.recv()


@pytest.mark.parametrize("owner_exit", ("normal", "interrupted"))
def test_separate_installation_owners_contend_and_process_exit_releases_lock(
    tmp_path, owner_exit, lifecycle_account_home
):
    spawn = multiprocessing.get_context("spawn")
    parent_connection, child_connection = spawn.Pipe()
    home = tmp_path / "home"
    child = spawn.Process(
        target=_hold_process_lock,
        args=(str(home), str(tmp_path / "first-guard"), str(lifecycle_account_home), child_connection),
    )
    child.start()
    child_connection.close()
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "second-guard")
    try:
        assert parent_connection.poll(5), "test owner did not acquire its lock"
        assert parent_connection.recv() is True
        with pytest.raises(RuntimeError, match="codex_lifecycle_busy"), codex_lifecycle_locks(context):
            pytest.fail("competing owner entered")
        if owner_exit == "normal":
            parent_connection.send("release")
        else:
            child.terminate()
        child.join(timeout=5)
        assert not child.is_alive()
        if owner_exit == "normal":
            assert child.exitcode == 0
        with codex_lifecycle_locks(context):
            pass
    finally:
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
        parent_connection.close()


def test_shared_workspace_contends_between_different_home_directories(tmp_path):
    workspace = tmp_path / "workspace"
    first = HarnessContext(home_dir=tmp_path / "one", workspace_dir=workspace, guard_home=tmp_path / "guard-one")
    second = HarnessContext(home_dir=tmp_path / "two", workspace_dir=workspace, guard_home=tmp_path / "guard-two")
    with (
        codex_lifecycle_locks(first),
        pytest.raises(RuntimeError, match="codex_lifecycle_busy"),
        codex_lifecycle_locks(second),
    ):
        pytest.fail("competing workspace owner entered")
    with codex_lifecycle_locks(second):
        pass


def test_lock_acquisition_does_not_create_codex_configuration_directories(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    context = HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=tmp_path / "guard")
    with codex_lifecycle_locks(context):
        assert not (home / ".codex").exists()
        assert not (workspace / ".codex").exists()


def test_read_only_workspace_does_not_block_global_lifecycle_lock(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original_mkdir = Path.mkdir

    def read_only_mkdir(path, *args, **kwargs):
        if path == workspace / ".codex":
            raise PermissionError("read-only workspace")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", read_only_mkdir)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=workspace, guard_home=tmp_path / "guard")
    with codex_lifecycle_locks(context):
        assert not (workspace / ".codex").exists()


def test_owner_environment_does_not_split_a_configuration_lock(tmp_path, monkeypatch):
    first_runtime = tmp_path / "first-runtime"
    second_runtime = tmp_path / "second-runtime"
    first_runtime.mkdir()
    second_runtime.mkdir()
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(first_runtime))
    with codex_lifecycle_locks(context):
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(second_runtime))
        with pytest.raises(RuntimeError, match="codex_lifecycle_busy"), codex_lifecycle_locks(context):
            pytest.fail("different owner environments bypassed configuration serialization")


def test_account_profile_discovery_ignores_owner_environment(tmp_path, monkeypatch):
    expected = real_account_home()
    for variable in ("HOME", "USERPROFILE", "TMPDIR", "TEMP", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(variable, str(tmp_path / variable))
    assert real_account_home() == expected


def test_configuration_directory_aliases_share_a_lock(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    first_home = tmp_path / "first"
    second_home = tmp_path / "second"
    first_home.mkdir()
    second_home.mkdir()
    (first_home / ".codex").symlink_to(actual, target_is_directory=True)
    (second_home / ".codex").symlink_to(actual, target_is_directory=True)
    first = HarnessContext(home_dir=first_home, workspace_dir=None, guard_home=tmp_path / "first-guard")
    second = HarnessContext(home_dir=second_home, workspace_dir=None, guard_home=tmp_path / "second-guard")
    with (
        codex_lifecycle_locks(first),
        pytest.raises(RuntimeError, match="codex_lifecycle_busy"),
        codex_lifecycle_locks(second),
    ):
        pytest.fail("configuration alias bypassed the lock")


def test_lock_permission_failure_has_a_lifecycle_reason(tmp_path, monkeypatch):
    import codex_plugin_scanner.guard.adapters.codex_lifecycle_lock as locks

    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    lock = _lifecycle_lock_path(context.home_dir / ".codex")
    original_open = locks.os.open

    def denied_open(path, *args, **kwargs):
        if path == lock:
            raise PermissionError(13, "lock denied", str(lock))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(locks.os, "open", denied_open)
    with (
        pytest.raises(RuntimeError, match=r"lock file is unavailable \(reason=EACCES\)"),
        codex_lifecycle_locks(context),
    ):
        pytest.fail("unavailable lock accepted")


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires kernel no-follow open")
def test_symlink_raced_before_open_preserves_target_and_reports_invalid_lock(tmp_path, monkeypatch):
    import codex_plugin_scanner.guard.adapters.codex_lifecycle_lock as locks

    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    lock = _lifecycle_lock_path(context.home_dir / ".codex")
    target = tmp_path / "user-file"
    target.write_bytes(b"preserved user content")
    original_open = locks.os.open

    def raced_open(path, *args, **kwargs):
        if path == lock:
            lock.symlink_to(target)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(locks.os, "open", raced_open)
    try:
        with (
            pytest.raises(RuntimeError, match="codex_lifecycle_lock_invalid: lifecycle lock file is unavailable"),
            codex_lifecycle_locks(context),
        ):
            pytest.fail("raced symlink accepted")
        assert target.read_bytes() == b"preserved user content"
    finally:
        lock.unlink(missing_ok=True)


@pytest.mark.parametrize("link_kind", ("symbolic", "hard"))
def test_lock_links_are_rejected_without_changing_the_target(tmp_path, link_kind):
    home = tmp_path / "home"
    lock = _lifecycle_lock_path(home / ".codex")
    lock.parent.mkdir(mode=0o700, exist_ok=True)
    target = lock.parent / "user-file"
    target.write_bytes(b"preserved user content")
    if link_kind == "symbolic":
        lock.symlink_to(target)
    else:
        lock.hardlink_to(target)
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")
    with pytest.raises(RuntimeError, match="codex_lifecycle_lock_invalid"), codex_lifecycle_locks(context):
        pytest.fail("linked lock accepted")
    assert target.read_bytes() == b"preserved user content"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork ownership")
def test_fork_during_target_acquisition_does_not_retain_crashed_parent_lock(tmp_path):
    root = tmp_path / "fork-owner"
    root.mkdir(mode=0o700)
    # Fork exactly after the kernel grants ownership, before the lock helper
    # returns. The owner exits without cleanup while its child remains alive.
    owner_script = r"""
import os, sys, time
from pathlib import Path
import codex_plugin_scanner.guard.adapters.codex_lifecycle_lock as locks
root = Path(sys.argv[1])
locks._account_home = lambda: root
original = locks.try_lock_daemon_file
def acquire(handle):
    assert original(handle)
    child = os.fork()
    if child == 0:
        (root / "child-ready").write_text("ready")
        deadline = time.monotonic() + 8
        while not (root / "release-child").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os._exit(0)
    deadline = time.monotonic() + 3
    while not (root / "child-ready").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert (root / "child-ready").exists()
    os._exit(0)
locks.try_lock_daemon_file = acquire
with locks.codex_configuration_lock(root / "config.toml"):
    raise AssertionError("owner must exit at the acquisition boundary")
"""
    probe_script = r"""
import sys, time
from pathlib import Path
import codex_plugin_scanner.guard.adapters.codex_lifecycle_lock as locks
root = Path(sys.argv[1])
locks._account_home = lambda: root
with locks.codex_configuration_lock(root / "config.toml", deadline=time.monotonic() + 0.3):
    print("acquired")
"""
    owner = subprocess.Popen(
        [sys.executable, "-c", owner_script, str(root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        # Pipes are deliberately inherited by the child; wait for the owner,
        # rather than waiting for pipe EOF from that still-live child.
        assert owner.wait(timeout=5) == 0
        assert (root / "child-ready").exists()
        probe = subprocess.run([sys.executable, "-c", probe_script, str(root)], capture_output=True, timeout=5)
        assert probe.returncode == 0, probe.stderr.decode(errors="replace")
        assert probe.stdout.strip() == b"acquired"
    finally:
        (root / "release-child").write_text("release")
        with suppress(ProcessLookupError):
            os.killpg(owner.pid, signal.SIGTERM)
        owner.communicate(timeout=5)

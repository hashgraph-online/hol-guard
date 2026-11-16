"""Concurrent lifecycle callers must not discover or mutate the same files."""

import multiprocessing
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_harness_lifecycle import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.codex_lifecycle_lock import (
    codex_configuration_lock,
    codex_lifecycle_locks,
)


def test_core_publication_transaction_shares_configuration_exclusion(tmp_path):
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


def test_nested_core_configuration_ownership_preserves_the_first_io_error(tmp_path):
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


@pytest.mark.parametrize("competing_operation", ("install", "uninstall"))
def test_competing_lifecycle_call_is_rejected_before_discovery(tmp_path, monkeypatch, competing_operation):
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    entered = Event()
    release = Event()
    calls = []

    def paused_discovery(self, current_context, **_kwargs):
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


def _hold_process_lock(home, guard_home, connection):
    context = HarnessContext(home_dir=Path(home), workspace_dir=None, guard_home=Path(guard_home))
    with codex_lifecycle_locks(context):
        connection.send(True)
        connection.recv()


@pytest.mark.parametrize("owner_exit", ("normal", "interrupted"))
def test_separate_installation_owners_contend_and_process_exit_releases_lock(tmp_path, owner_exit):
    spawn = multiprocessing.get_context("spawn")
    parent_connection, child_connection = spawn.Pipe()
    home = tmp_path / "home"
    child = spawn.Process(
        target=_hold_process_lock,
        args=(str(home), str(tmp_path / "first-guard"), child_connection),
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

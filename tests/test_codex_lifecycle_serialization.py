"""Concurrent lifecycle callers must not discover or mutate the same files."""

import multiprocessing
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_owned import (
    codex_configuration_lock,
    codex_install_transaction,
    codex_lifecycle_locks,
)
from tests import harness_ops_support as harness_support


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
def test_competing_lifecycle_call_is_rejected_before_discovery(tmp_path, competing_operation):
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")

    def competing():
        return getattr(harness_support, competing_operation)("codex", context)

    with (
        codex_lifecycle_locks(context),
        ThreadPoolExecutor(max_workers=1) as executor,
        pytest.raises(RuntimeError, match="codex_lifecycle_busy"),
    ):
        executor.submit(competing).result(timeout=5)
    assert not context.guard_home.exists(), "a refused lifecycle call must not write the Guard home"


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

"""The daemon's worker host admits the installed release before it publishes policy.

A runtime upgrade changes the command engine. The resident refuses any policy
snapshot bound to packs an older engine compiled, so if nothing migrates the
active packs, every hook fails closed. The Python daemon migrated at startup;
these tests hold the worker host that replaced it to the same order.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime_health import background_diagnostics
from codex_plugin_scanner.guard.runtime_health.diagnostics import background_log_sinks
from codex_plugin_scanner.guard.workers import host as worker_host


class _StopError(Exception):
    """Ends ``WorkerHost.start`` once the step under test has run."""


class _Store:
    def __init__(self, guard_home: Path, failures: int = 0) -> None:
        self.guard_home = guard_home
        self.failures = failures
        self.calls: list[str] = []

    def migrate_installed_command_pack_authority(self) -> None:
        self.calls.append("migrate")
        if self.failures:
            self.failures -= 1
            raise RuntimeError("native runtime did not answer")


def test_worker_host_migrates_installed_release_before_first_publication(tmp_path, monkeypatch):
    store = _Store(tmp_path)

    def publish(self):
        store.calls.append("publish")
        raise _StopError

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", publish)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    with pytest.raises(_StopError):
        host.start()

    assert store.calls == ["migrate", "publish"]


def test_worker_host_retries_a_failed_migration_until_it_lands(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime import approval_attention

    store = _Store(tmp_path, failures=2)
    loops: dict[str, object] = {}

    def attention(**_kwargs):
        raise _StopError

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.update({name: body}))
    monkeypatch.setattr(approval_attention, "ApprovalAttentionCoordinator", attention)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    with pytest.raises(_StopError):
        host.start()

    retry = loops["installed-authority"]
    assert callable(retry)
    retry()
    assert store.calls == ["migrate", "migrate"]
    retry()
    retry()
    # Once admitted the loop stops asking.
    assert store.calls == ["migrate", "migrate", "migrate"]


def test_worker_host_starts_no_retry_when_the_migration_landed(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime import approval_attention

    store = _Store(tmp_path)
    loops: list[str] = []

    def attention(**_kwargs):
        raise _StopError

    monkeypatch.setattr(worker_host.WorkerHost, "_start_policy_publication", lambda self: None)
    monkeypatch.setattr(worker_host.WorkerHost, "_loop", lambda self, name, body, interval: loops.append(name))
    monkeypatch.setattr(approval_attention, "ApprovalAttentionCoordinator", attention)
    host = worker_host.WorkerHost(store, home_dir=tmp_path)  # pyright: ignore[reportArgumentType]

    with pytest.raises(_StopError):
        host.start()

    assert "installed-authority" not in loops


def test_failed_migration_reaches_daemon_log_while_the_process_runs(tmp_path):
    from codex_plugin_scanner.guard.extension_control_host import migrate_installed_authority

    sink, notice = background_log_sinks(tmp_path)
    background_diagnostics.install_sink(sink, notice=notice)
    try:
        assert migrate_installed_authority(_Store(tmp_path, failures=1)) is False  # pyright: ignore[reportArgumentType]
        # Written at once, not queued until the process shuts down.
        lines = (tmp_path / "logs" / "daemon.log").read_text(encoding="utf-8").splitlines()
    finally:
        background_diagnostics.release_sink(sink)

    records = [json.loads(line) for line in lines]
    assert [record["event"] for record in records] == ["installed_authority_migration_failed"]
    assert records[0]["level"] == "error"
    assert "RuntimeError" in records[0]["detail"]

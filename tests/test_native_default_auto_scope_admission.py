"""The installed probe admits aliases before real scoped configuration capture."""

from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_native_default_auto as probe
from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError
from codex_plugin_scanner.guard.daemon.config_read_scope import HookConfigReadScope
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def _stub_store_and_command_fixture(monkeypatch):
    monkeypatch.setattr(probe, "GuardStore", lambda home: SimpleNamespace(guard_home=home))
    # Foundation predates main's command-authority fixture; neither is under test.
    if hasattr(probe, "_prepare_empty_command_authority"):
        monkeypatch.setattr(probe, "_prepare_empty_command_authority", lambda _store: {})
    monkeypatch.setattr(probe, "_ownership_routes", lambda: {})


def test_direct_probe_admits_alias_before_capture_and_keeps_that_generation(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("creating directory aliases requires runner support")
    _stub_store_and_command_fixture(monkeypatch)
    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: 10.0))
    events = []

    class EndOfScopedWitnessError(Exception):
        pass

    class Worker:
        def __init__(self, store):
            self.scope = HookConfigReadScope.for_guard_home(store.guard_home)
            self.policy_snapshot_publisher = NativePolicySnapshotPublisher(store=store, config_capture=self.scope)

        def prepare_workspace_policy(self, workspace, *, deadline):
            assert deadline == 10.0 + probe.MAX_READINESS_P95_MS / 1_000.0
            publisher = self.policy_snapshot_publisher
            assert publisher.config_capture is self.scope
            # Registering the same admitted path must retain one preparation.
            assert publisher.register_workspace(workspace) is False
            assert publisher._workspace_paths == {workspace}
            assert isinstance(publisher._compiled_effective_policy(), dict)
            events.append("scoped_capture_succeeded")
            # This is a capture-boundary witness, not a native ACK/IPC test.
            return {"fixture_scoped_capture": True}

    class Daemon:
        def __init__(self, store, **_kwargs):
            self._server = SimpleNamespace(hook_worker=Worker(store))

        def start(self):
            events.append("started")

        def stop(self):
            self._server.hook_worker.policy_snapshot_publisher.close()
            events.append("stopped")

    def route(daemon, _home, workspace, *_args):
        assert workspace == (real / "hook-workspace").resolve()
        publisher = daemon._server.hook_worker.policy_snapshot_publisher
        admitted = workspace
        admitted.rename(real / "original-workspace")
        replacement = real / "replacement-workspace"
        replacement.mkdir()
        (replacement / ".hol-guard.toml").write_text('sandbox_analysis = "off"\n', encoding="utf-8")
        admitted.symlink_to(replacement, target_is_directory=True)
        # No recanonicalization is permitted after the generation is admitted.
        publisher._acked = True
        with pytest.raises(GuardConfigSourceError, match="guard_config_scope_changed"):
            publisher._compiled_effective_policy()
        assert publisher._acked is False
        assert publisher.config_capture is daemon._server.hook_worker.scope
        events.append("retarget_rejected_and_ack_withdrawn")
        raise EndOfScopedWitnessError

    monkeypatch.setattr(probe, "GuardDaemonServer", Daemon)
    monkeypatch.setattr(probe, "_exercise_installed_routes", route)
    with pytest.raises(EndOfScopedWitnessError):
        probe._installed_hook_corpus(alias)
    assert events == ["started", "scoped_capture_succeeded", "retarget_rejected_and_ack_withdrawn", "stopped"]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("guardconfigsourceerror", "guardconfigsourceerror"),
        ("native_policy_snapshot_ack_mismatch", "native_policy_snapshot_ack_mismatch"),
        ("PRIVATE /path/content", "other"),
        ("native_policy_snapshot_" + "PRIVATE" * 100, "other"),
        ({"private": "PRIVATE"}, "other"),
        (None, None),
    ],
)
def test_readiness_failure_retains_only_fixed_error_codes_and_stops(tmp_path, monkeypatch, error, expected):
    _stub_store_and_command_fixture(monkeypatch)
    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: 10.0))
    stopped = []
    publisher = SimpleNamespace(last_error=error)

    def prepare(_workspace, *, deadline):
        assert deadline == 10.0 + probe.MAX_READINESS_P95_MS / 1_000.0
        return None

    class Daemon:
        def __init__(self, *_args, **_kwargs):
            self._server = SimpleNamespace(
                hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
            )

        def start(self):
            pass

        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(probe, "GuardDaemonServer", Daemon)
    monkeypatch.setattr(probe, "_exercise_installed_routes", lambda *_args: pytest.fail("unready corpus ran"))
    with pytest.raises(RuntimeError, match="native_default_auto_probe_failed") as caught:
        probe._installed_hook_corpus(tmp_path)
    detail = ast.literal_eval(str(caught.value).split(": ", 1)[1])
    assert detail == {"elapsed_ms": 0.0, "policy_ready": False, "publisher_last_error": expected}
    assert "PRIVATE" not in str(caught.value)
    assert stopped == [True]


def test_late_ready_snapshot_still_fails_original_deadline(tmp_path, monkeypatch):
    _stub_store_and_command_fixture(monkeypatch)
    budget = probe.MAX_READINESS_P95_MS / 1_000.0
    ticks = iter([10.0, 10.0 + budget + 1.0])
    monkeypatch.setattr(probe, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    stopped = []

    def prepare(_workspace, *, deadline):
        assert deadline == 10.0 + budget
        return {"fixture_ready": True}

    class Daemon:
        def __init__(self, *_args, **_kwargs):
            self._server = SimpleNamespace(
                hook_worker=SimpleNamespace(
                    policy_snapshot_publisher=SimpleNamespace(last_error=None), prepare_workspace_policy=prepare
                )
            )

        def start(self):
            pass

        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(probe, "GuardDaemonServer", Daemon)
    monkeypatch.setattr(probe, "_exercise_installed_routes", lambda *_args: pytest.fail("late corpus ran"))
    with pytest.raises(RuntimeError, match="native_default_auto_probe_failed") as caught:
        probe._installed_hook_corpus(tmp_path)
    detail = ast.literal_eval(str(caught.value).split(": ", 1)[1])
    assert detail == {
        "elapsed_ms": round((budget + 1.0) * 1_000, 2),
        "policy_ready": True,
        "publisher_last_error": None,
    }
    assert stopped == [True]

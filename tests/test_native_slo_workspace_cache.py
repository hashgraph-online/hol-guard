"""Real file/capture/cache controls, without any claim of installed native timing."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings
from scripts.native_slo_workloads import configuration_text
from scripts.native_slo_workspace_observer import PublicationObserver


@pytest.mark.parametrize("count", [1, 10, 100])
def test_observer_counts_real_initial_cached_and_stricter_scope_compilation(tmp_path, count):
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    atomic_write_settings(home / "config.toml", configuration_text("normal"))
    publisher = NativePolicySnapshotPublisher(store=SimpleNamespace(guard_home=home))
    workspaces = tuple(tmp_path / f"workspace-{index}" for index in range(count))
    for workspace in workspaces:
        workspace.mkdir(mode=0o700)
        assert publisher.register_workspace(workspace)
    try:
        with PublicationObserver(publisher, workspaces) as observer:
            original = publisher._compiled_effective_policy()
            initial = observer.rows()[-1]
            assert initial["config_loads"] == count + 1 and initial["cache_entries"] == count + 1
            assert initial["scope_loads"] == [1] * (count + 1)
            observer.phase(1)
            assert publisher._compiled_effective_policy() == original
            assert observer.rows()[-1]["config_loads"] == 0
            assert observer.rows()[-1]["scope_loads"] == [0] * (count + 1)
            observer.phase(2)
            atomic_write_settings(workspaces[0] / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')
            strict = publisher._compiled_effective_policy()
            assert strict["sandbox_analysis"] == "strict" and strict["mode"] == original["mode"]
            assert observer.rows()[-1]["config_loads"] == 1
            assert observer.rows()[-1]["scope_loads"] == [0, 1] + [0] * (count - 1)
            assert observer.rows()[-1]["cache_entries"] == count + 1
            assert len(publisher._workspace_paths) == count and publisher._max_workspaces == 1024
            assert observer.report()["complete"]
    finally:
        publisher.close()

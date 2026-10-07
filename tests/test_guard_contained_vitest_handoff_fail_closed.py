from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_node_execution
from codex_plugin_scanner.guard.runtime.package_intent_common import LocalPackageExecutionEvidence, PackageIntent


def _vitest_intent(workspace: Path) -> PackageIntent:
    execution = LocalPackageExecutionEvidence(
        manager_name="bunx",
        path_source="guard-shim",
        effective_cwd=str(workspace),
        cwd_source="request",
        manager_is_guard_shim=True,
        local_only_requested=True,
        context_hash="test-context",
        package_name="vitest",
        executable_name="vitest",
        declared_version="3.2.4",
        manager=None,
        local_executable=None,
    )
    return PackageIntent(
        package_manager="bunx",
        intent_kind="execute",
        command_tokens=("bunx", "vitest", "run", "tests/unit.test.ts"),
        redacted_command="bunx vitest run tests/unit.test.ts",
        targets=(),
        local_executions=(execution,),
    )


def test_installed_package_shim_stops_vitest_when_runner_evidence_is_missing(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    shim_directory = guard_home / "package-shims" / "bin"
    shim_directory.mkdir(parents=True)

    monkeypatch.setattr(
        contained_node_execution,
        "parse_package_intent",
        lambda *args, **kwargs: _vitest_intent(workspace),
    )
    monkeypatch.setattr(
        contained_node_execution,
        "build_local_node_runner_evidence",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(SystemExit, match="refused uncontained Vitest execution"):
        contained_node_execution.try_execute_contained_node_command(
            "bunx",
            ("vitest", "run", "tests/unit.test.ts"),
            workspace=workspace,
            guard_home=guard_home,
            shim_directory=shim_directory,
            environment={"PATH": "/usr/bin"},
        )


def test_non_shim_vitest_returns_to_review_when_runner_evidence_is_missing(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shim_directory = tmp_path / "bin"
    shim_directory.mkdir()

    monkeypatch.setattr(
        contained_node_execution,
        "parse_package_intent",
        lambda *args, **kwargs: _vitest_intent(workspace),
    )
    monkeypatch.setattr(
        contained_node_execution,
        "build_local_node_runner_evidence",
        lambda *args, **kwargs: None,
    )

    result = contained_node_execution.try_execute_contained_node_command(
        "bunx",
        ("vitest", "run", "tests/unit.test.ts"),
        workspace=workspace,
        guard_home=tmp_path / "guard-home",
        shim_directory=shim_directory,
        environment={"PATH": "/usr/bin"},
    )
    assert result is None

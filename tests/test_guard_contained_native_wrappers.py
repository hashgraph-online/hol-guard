"""Contained execution wrappers hand decisions to the resident and never decide in Python."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import (
    contained_node_execution,
    contained_package_script_execution,
    contained_typescript_execution,
    contained_workspace_write_execution,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import LocalPackageExecutionEvidence, PackageIntent

_SENTINEL = object()


def _intent(workspace: Path, manager: str, package: str) -> PackageIntent:
    execution = LocalPackageExecutionEvidence(
        manager_name=manager,
        path_source="guard-shim",
        effective_cwd=str(workspace),
        cwd_source="request",
        manager_is_guard_shim=True,
        local_only_requested=True,
        context_hash="test-context",
        package_name=package,
        executable_name=package,
        declared_version="1.0.0",
        manager=None,
        local_executable=None,
    )
    return PackageIntent(
        package_manager=manager,
        intent_kind="execute",
        command_tokens=(manager, package),
        redacted_command=f"{manager} {package}",
        targets=(),
        local_executions=(execution,),
    )


def _dirs(tmp_path: Path) -> tuple[Path, Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    shim = tmp_path / "bin"
    shim.mkdir()
    return workspace, guard_home, shim


def test_node_result_is_the_resident_answer_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home, shim = _dirs(tmp_path)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        contained_node_execution, "parse_package_intent", lambda *a, **k: _intent(workspace, "npx", "eslint")
    )

    def native(*args: object, **kwargs: Any) -> object:
        calls.append(kwargs)
        return _SENTINEL

    monkeypatch.setattr(contained_node_execution._native_execution, "contained_node_execute_native", native)
    result = contained_node_execution.try_execute_contained_node_command(
        "npx", ("eslint",), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
    )
    assert result is _SENTINEL
    assert calls[0]["evidence"]["package_name"] == "eslint"


def test_node_unavailable_resident_returns_to_review_without_python_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home, shim = _dirs(tmp_path)
    monkeypatch.setattr(
        contained_node_execution, "parse_package_intent", lambda *a, **k: _intent(workspace, "npx", "eslint")
    )
    monkeypatch.setattr(
        contained_node_execution._native_execution, "contained_node_execute_native", lambda *a, **k: None
    )
    assert (
        contained_node_execution.try_execute_contained_node_command(
            "npx", ("eslint",), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
        )
        is None
    )


@pytest.mark.parametrize("manager", ("pnpm", "yarn", ""))
def test_node_ignores_managers_it_does_not_own(tmp_path: Path, manager: str) -> None:
    workspace, guard_home, shim = _dirs(tmp_path)
    assert (
        contained_node_execution.try_execute_contained_node_command(
            manager, ("eslint",), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
        )
        is None
    )


def test_typescript_delegates_only_npx_to_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home, shim = _dirs(tmp_path)
    monkeypatch.setattr(
        contained_typescript_execution, "parse_package_intent", lambda *a, **k: _intent(workspace, "npx", "tsc")
    )
    monkeypatch.setattr(
        contained_typescript_execution._native_execution,
        "contained_typescript_execute_native",
        lambda *a, **k: _SENTINEL,
    )
    assert (
        contained_typescript_execution.try_execute_contained_typescript(
            "npx", ("tsc",), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
        )
        is _SENTINEL
    )
    assert (
        contained_typescript_execution.try_execute_contained_typescript(
            "bunx", ("tsc",), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
        )
        is None
    )


def test_package_script_delegates_only_bun_to_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home, shim = _dirs(tmp_path)
    seen: dict[str, Any] = {}

    def native(_workspace: Path, manager: str, argv: tuple[str, ...], **kwargs: Any) -> object:
        seen.update(manager=manager, argv=argv, **kwargs)
        return _SENTINEL

    monkeypatch.setattr(
        contained_package_script_execution._native_execution, "contained_package_script_execute_native", native
    )
    result = contained_package_script_execution.try_execute_contained_package_script(
        "bun", ("run", "build"), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
    )
    assert result is _SENTINEL
    assert seen["manager"] == "bun"
    assert seen["argv"] == ("run", "build")
    assert (
        contained_package_script_execution.try_execute_contained_package_script(
            "npm", ("run", "build"), workspace=workspace, guard_home=guard_home, shim_directory=shim, environment={}
        )
        is None
    )


def test_workspace_write_unavailable_workspace_or_resident_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home, _shim = _dirs(tmp_path)
    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution,
        "contained_workspace_write_execute_native",
        lambda *a, **k: None,
    )
    assert (
        contained_workspace_write_execution.try_execute_contained_workspace_write(
            "copy-generated", workspace=workspace, guard_home=guard_home, source="a.txt", target="b.txt"
        )
        is None
    )
    assert (
        contained_workspace_write_execution.try_execute_contained_workspace_write(
            "copy-generated",
            workspace=tmp_path / "missing",
            guard_home=guard_home,
            source="a.txt",
            target="b.txt",
        )
        is None
    )


def test_workspace_write_passes_canonical_workspace_and_scrubbed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home, _shim = _dirs(tmp_path)
    seen: dict[str, Any] = {}

    def native(canonical: Path, **kwargs: Any) -> object:
        seen["workspace"] = canonical
        seen.update(kwargs)
        return _SENTINEL

    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution, "contained_workspace_write_execute_native", native
    )
    result = contained_workspace_write_execution.try_execute_contained_workspace_write(
        "format-write",
        workspace=workspace,
        guard_home=guard_home,
        source="m.py",
        target="m.py",
        environment={"PATH": "/usr/bin", "GITHUB_TOKEN": "synthetic-secret"},
    )
    assert result is _SENTINEL
    assert seen["workspace"] == workspace.resolve()
    assert seen["operation"] == "format-write"
    assert "GITHUB_TOKEN" not in seen["environment"]

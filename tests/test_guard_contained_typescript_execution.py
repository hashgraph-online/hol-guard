from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_typescript_execution as execution_module
from codex_plugin_scanner.guard.contained_typescript_execution import try_execute_contained_typescript
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition

_TSC = ("--no-install", "tsc", "--noEmit", "src/example.ts")


@pytest.fixture
def native_home(package_intent_native: Path) -> Path:
    return package_intent_native


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")
    if executable:
        _ = path.chmod(0o755)


def _workspace(root: Path) -> Path:
    workspace = root / "workspace"
    _write(workspace / "package.json", '{"devDependencies":{"typescript":"^5.9.0"}}\n')
    _write(
        workspace / "package-lock.json",
        '{"packages":{"node_modules/typescript":{"version":"5.9.0","integrity":"sha512-reviewed"}}}\n',
    )
    _write(workspace / "src" / "example.ts", "export const value: number = 1;\n")
    compiler = workspace / "node_modules" / "typescript" / "bin" / "tsc"
    _write(compiler, "#!/usr/bin/env node\nrequire('../lib/tsc.js')\n", executable=True)
    _write(workspace / "node_modules" / "typescript" / "lib" / "tsc.js", "process.exit(0);\n")
    _write(
        workspace / "node_modules" / "typescript" / "package.json",
        '{"name":"typescript","version":"5.9.0","bin":{"tsc":"./bin/tsc"}}\n',
    )
    runner = workspace / "node_modules" / ".bin" / "tsc"
    runner.parent.mkdir(parents=True)
    runner.symlink_to(Path("..") / "typescript" / "bin" / "tsc")
    return workspace.resolve()


def _manager(root: Path) -> Path:
    directory = (root / "bin").resolve()
    _write(directory / "npx", "#!/bin/sh\nexit 99\n", executable=True)
    _write(directory / "node", "synthetic-node", executable=True)
    return directory


def test_native_request_carries_launch_evidence_environment_and_timeout(
    native_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path)
    shim = _manager(tmp_path)
    captured: dict[str, object] = {}

    def native(workspace_arg: Path, manager: str, argv: tuple[str, ...], **kwargs: object) -> None:
        captured.update(workspace=workspace_arg, manager=manager, argv=argv, **kwargs)

    monkeypatch.setattr(execution_module._native_execution, "contained_typescript_execute_native", native)
    environment = {"PATH": str(shim), "GITHUB_TOKEN": "left-to-the-resident"}
    result = try_execute_contained_typescript(
        "npx",
        _TSC,
        workspace=workspace,
        guard_home=native_home,
        shim_directory=shim,
        environment=environment,
        timeout_seconds=45.0,
    )

    assert result is None
    assert captured["workspace"] == workspace
    assert captured["manager"] == "npx"
    assert captured["argv"] == _TSC
    assert captured["shim_directory"] == shim
    assert captured["environment"] == environment
    assert captured["timeout_seconds"] == 45.0
    evidence = captured["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["executable_name"] == "tsc"


@pytest.mark.parametrize("manager", ("pnpm", "yarn", "bun", "bunx"))
def test_only_npx_reaches_the_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manager: str) -> None:
    def native(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("resident must only see npx")

    monkeypatch.setattr(execution_module._native_execution, "contained_typescript_execute_native", native)
    assert (
        try_execute_contained_typescript(
            manager,
            _TSC,
            workspace=tmp_path,
            guard_home=tmp_path,
            shim_directory=tmp_path,
            environment={},
        )
        is None
    )


def test_exact_local_typecheck_is_contained_by_the_resident_or_returns_to_review(
    native_home: Path, tmp_path: Path
) -> None:
    workspace = _workspace(tmp_path)
    shim = _manager(tmp_path)
    result = try_execute_contained_typescript(
        "npx",
        _TSC,
        workspace=workspace,
        guard_home=native_home,
        shim_directory=shim,
        environment={"PATH": str(shim), "GITHUB_TOKEN": "must-not-cross"},
    )

    # Hosts without an enforcing backend or an immutable node return to review.
    if result is None:
        return
    assert result.operation_id == "typecheck"
    assert result.proof.route is ProofRoute.CONTAINED
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert result.exit_code != 99, "the live package manager must never run"
    assert "must-not-cross" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "argv",
    (
        ("--no-install", "--package", "typescript", "tsc", "--noEmit", "src/example.ts"),
        ("tsc", "--noEmit", "src/example.ts"),
        ("--no-install", "tsc", "--project", "tsconfig.json", "--noEmit"),
        ("--no-install", "tsc", "--noEmit=false", "src/example.ts"),
    ),
)
def test_exploit_deltas_return_to_review_without_execution(
    native_home: Path, tmp_path: Path, argv: tuple[str, ...]
) -> None:
    workspace = _workspace(tmp_path)
    shim = _manager(tmp_path)
    assert (
        try_execute_contained_typescript(
            "npx",
            argv,
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


def test_package_tree_symlink_returns_to_review(native_home: Path, tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    shim = _manager(tmp_path)
    (workspace / "node_modules" / "typescript" / "lib" / "escape.js").symlink_to("/usr/bin/true")
    assert (
        try_execute_contained_typescript(
            "npx",
            _TSC,
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )

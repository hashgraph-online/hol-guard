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


def _capture_resident(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def resident(**kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(execution_module._native_execution, "_resident_request", resident)
    return calls


def test_native_request_carries_the_shims_launch_environment_and_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path)
    shim = _manager(tmp_path)
    calls = _capture_resident(monkeypatch)
    environment = {"PATH": str(shim), "GITHUB_TOKEN": "left-to-the-resident"}
    result = try_execute_contained_typescript(
        "npx",
        _TSC,
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment=environment,
        timeout_seconds=45.0,
    )

    assert result is None
    # One resident request: it parses the launch intent from the argv itself.
    assert len(calls) == 1
    assert calls[0]["operation"] == "contained_typescript_execute"
    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert request["schema"] == "guard-contained-typescript-execute-request.v2"
    assert request["workspace"] == str(workspace)
    assert request["manager"] == "npx"
    assert request["argv"] == list(_TSC)
    assert request["shim_directory"] == str(shim)
    assert request["environment"] == environment
    assert request["timeout_seconds"] == 45.0
    assert "evidence" not in request
    assert "command_text" not in request


@pytest.mark.parametrize("manager", ("pnpm", "yarn", "bun", "bunx"))
def test_only_npx_is_contained(native_home: Path, tmp_path: Path, manager: str) -> None:
    workspace = _workspace(tmp_path)
    shim = _manager(tmp_path)
    assert (
        try_execute_contained_typescript(
            manager,
            _TSC,
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
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

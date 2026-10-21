from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_node_execution as execution_module
from codex_plugin_scanner.guard.contained_node_execution import try_execute_contained_node_command
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition

_INTEGRITY = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")
    if executable:
        _ = path.chmod(0o755)


def _workspace(root: Path, runner: str) -> Path:
    workspace = (root / "workspace").resolve()
    version = "1.2.3"
    _write(workspace / "package.json", json.dumps({"devDependencies": {runner: version}}))
    _write(
        workspace / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    f"node_modules/{runner}": {
                        "version": version,
                        "resolved": f"https://registry.npmjs.org/{runner}/-/{runner}-{version}.tgz",
                        "integrity": _INTEGRITY,
                    }
                }
            }
        ),
    )
    target = workspace / "node_modules" / runner / "bin" / f"{runner}.mjs"
    _write(target, "process.exit(0);\n", executable=True)
    _write(
        workspace / "node_modules" / runner / "package.json",
        json.dumps({"name": runner, "version": version, "bin": {runner: f"bin/{runner}.mjs"}}),
    )
    link = workspace / "node_modules" / ".bin" / runner
    link.parent.mkdir(parents=True)
    link.symlink_to(Path("..") / runner / "bin" / f"{runner}.mjs")
    _write(workspace / "src" / "example.ts", "export const value = 1;\n")
    _write(workspace / "src" / "example.test.ts", "test('value', () => {});\n")
    _write(workspace / "vitest.config.ts", "export default {};\n")
    return workspace


def _manager(root: Path) -> Path:
    directory = (root / "bin").resolve()
    _write(directory / "npx", "#!/bin/sh\nexit 99\n", executable=True)
    _write(directory / "node", "synthetic-node", executable=True)
    return directory


@pytest.fixture
def native_home(package_intent_native: Path) -> Path:
    return package_intent_native


_VITEST = ("--no-install", "vitest", "run", "src/example.test.ts")
_ESLINT = ("--no-install", "eslint", "--no-cache", "src/example.ts")


def test_native_request_carries_launch_evidence_environment_and_timeout(
    native_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path, "vitest")
    shim = _manager(tmp_path)
    captured: dict[str, object] = {}

    def native(workspace_arg: Path, manager: str, argv: tuple[str, ...], **kwargs: object) -> None:
        captured.update(workspace=workspace_arg, manager=manager, argv=argv, **kwargs)

    monkeypatch.setattr(execution_module._native_execution, "contained_node_execute_native", native)
    environment = {"PATH": str(shim), "GITHUB_TOKEN": "left-to-the-resident"}
    result = try_execute_contained_node_command(
        "npx",
        _VITEST,
        workspace=workspace,
        guard_home=native_home,
        shim_directory=shim,
        environment=environment,
        timeout_seconds=45.0,
    )

    assert result is None
    assert captured["workspace"] == workspace
    assert captured["manager"] == "npx"
    assert captured["argv"] == _VITEST
    assert captured["shim_directory"] == shim
    assert captured["environment"] == environment
    assert captured["timeout_seconds"] == 45.0
    evidence = captured["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["manager_name"] == "npx"
    assert evidence["package_name"] == "vitest"
    assert evidence["local_only_requested"] is True


@pytest.mark.parametrize("manager", ("pnpm", "yarn", "bun"))
def test_unsupported_managers_never_reach_the_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manager: str
) -> None:
    def native(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("resident must not see an unsupported manager")

    monkeypatch.setattr(execution_module._native_execution, "contained_node_execute_native", native)
    assert (
        try_execute_contained_node_command(
            manager,
            _VITEST,
            workspace=tmp_path,
            guard_home=tmp_path,
            shim_directory=tmp_path,
            environment={},
        )
        is None
    )


def test_system_root_workspace_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def native(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a system-root workspace must return to review")

    monkeypatch.setattr(execution_module._native_execution, "contained_node_execute_native", native)
    assert (
        try_execute_contained_node_command(
            "npx",
            _VITEST,
            workspace=Path("/usr"),
            guard_home=Path("/usr"),
            shim_directory=Path("/usr"),
            environment={},
        )
        is None
    )


@pytest.mark.parametrize(
    ("runner", "argv", "operation"),
    (("vitest", _VITEST, "test"), ("eslint", _ESLINT, "lint")),
)
def test_exact_runner_is_contained_by_the_resident_or_returns_to_review(
    native_home: Path, tmp_path: Path, runner: str, argv: tuple[str, ...], operation: str
) -> None:
    workspace = _workspace(tmp_path, runner)
    shim = _manager(tmp_path)
    result = try_execute_contained_node_command(
        "npx",
        argv,
        workspace=workspace,
        guard_home=native_home,
        shim_directory=shim,
        environment={"PATH": str(shim), "GITHUB_TOKEN": "must-not-cross"},
    )

    # Hosts without an enforcing backend or an immutable node return to review.
    if result is None:
        return
    assert result.operation_id == operation
    assert result.proof.route is ProofRoute.CONTAINED
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert result.exit_code != 99, "the live package manager must never run"
    assert "must-not-cross" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "argv",
    (
        ("--no-install", "--package", "vitest", "vitest", "run", "src/example.test.ts"),
        ("--no-install", "--package=vitest", "vitest", "run", "src/example.test.ts"),
        ("--no-install", "vitest", "run", "--coverage", "src/example.test.ts"),
        ("--no-install", "vitest", "run"),
        ("--no-install", "vitest", "run", "src/example.ts"),
        ("--no-install", "vitest", "run", "../outside.test.ts"),
        ("--no-install", "vitest", "run", "src/../src/example.test.ts"),
        ("--no-install", "vitest", "run", "./src/example.test.ts"),
        ("--no-install", "vitest", "run", "src/example.test.ts", "src/example.test.ts"),
    ),
)
def test_exploit_deltas_return_to_review_without_execution(
    native_home: Path, tmp_path: Path, argv: tuple[str, ...]
) -> None:
    workspace = _workspace(tmp_path, "vitest")
    shim = _manager(tmp_path)
    assert (
        try_execute_contained_node_command(
            "npx",
            argv,
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


@pytest.mark.parametrize(
    ("relative", "content"),
    (
        ("package.json", '{"devDependencies":{"vitest":"9.9.9"}}'),
        ("package-lock.json", '{"packages":{"node_modules/vitest":{"version":"9.9.9"}}}'),
        (
            "node_modules/vitest/package.json",
            '{"name":"not-vitest","version":"9.9.9","bin":{"vitest":"bin/vitest.mjs"}}',
        ),
        (".env", "TOKEN=secret\n"),
    ),
)
def test_provenance_drift_or_secret_content_returns_to_review(
    native_home: Path, tmp_path: Path, relative: str, content: str
) -> None:
    workspace = _workspace(tmp_path, "vitest")
    shim = _manager(tmp_path)
    _write(workspace / relative, content)
    assert (
        try_execute_contained_node_command(
            "npx",
            _VITEST,
            workspace=workspace,
            guard_home=native_home,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )

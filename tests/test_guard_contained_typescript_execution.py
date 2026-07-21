from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_typescript_execution as execution_module
from codex_plugin_scanner.guard.contained_typescript_execution import try_execute_contained_typescript
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentAttestation,
    ContainmentBackend,
    ContainmentFailure,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import ContainmentExecutionResult, file_sha256
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
)
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition


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


def _manager(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    bin_directory = root / "bin"
    manager = bin_directory / "npx"
    _write(manager, "#!/bin/sh\nexit 99\n", executable=True)
    node = bin_directory / "node"
    _write(node, "synthetic-node", executable=True)
    monkeypatch.setenv("PATH", str(bin_directory))
    monkeypatch.setattr(execution_module, "_load_current_containment_health", _fake_health)
    return bin_directory.resolve(), node.resolve()


def _success(request: ContainmentRequest) -> ContainmentExecutionResult:
    return ContainmentExecutionResult(
        exit_code=0,
        stdout="typecheck-ok\n",
        stderr="",
        timed_out=False,
        attestation=ContainmentAttestation(
            backend=ContainmentBackend.LINUX_BWRAP,
            backend_digest=hashlib.sha256(b"backend").hexdigest(),
            request_digest=request.binding_digest,
            policy_digest=request.policy.digest,
            launch_digest=request.launch_digest,
            executable_digest=request.executable_digest,
            enforced=True,
            failure=None,
        ),
    )


def _health() -> tuple[ContainmentHealthEvidence, str]:
    fingerprint = hashlib.sha256(b"runtime").hexdigest()
    return (
        ContainmentHealthEvidence(
            backend=ContainmentBackend.LINUX_BWRAP,
            backend_digest=hashlib.sha256(b"backend").hexdigest(),
            policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
            daemon_fingerprint=fingerprint,
            runtime_fingerprint=fingerprint,
            probe_at=datetime.now(timezone.utc).isoformat(),
            probe_enforced=True,
        ),
        fingerprint,
    )


def _fake_health(_guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
    return _health()


def _node_resolver(node: Path) -> Callable[[str, Path], str]:
    def resolve(_path: str, _shim: Path) -> str:
        return str(node)

    return resolve


def test_exact_local_typecheck_routes_through_central_contained_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, node = _manager(tmp_path, monkeypatch)
    captured: list[ContainmentRequest] = []

    def fake_execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        assert timeout_seconds == 120.0
        captured.append(request)
        return _success(request)

    monkeypatch.setattr(execution_module, "execute_contained", fake_execute)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))

    result = try_execute_contained_typescript(
        "npx",
        ("--no-install", "tsc", "--noEmit", "src/example.ts"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim_directory,
        environment={"PATH": str(shim_directory), "GITHUB_TOKEN": "must-not-cross"},
    )

    assert result is not None
    assert result.exit_code == 0
    assert result.stdout == "typecheck-ok\n"
    assert result.proof.route is ProofRoute.CONTAINED
    assert result.proof.enforced is True
    assert result.decision.action == "allow"
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert len(captured) == 1
    request = captured[0]
    assert request.argv[0] == str(node)
    assert request.argv[1].endswith("node_modules/typescript/bin/tsc")
    assert request.policy.allowed_write_paths == ()
    assert "GITHUB_TOKEN" not in request.environment_dict()


def test_typecheck_snapshot_includes_imports_and_ambient_declarations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    _write(workspace / "src" / "example.ts", "import { value } from './util';\nexport { value };\n")
    _write(workspace / "src" / "util.ts", "export const value: number = 1;\n")
    _write(workspace / "node_modules" / "@types" / "example" / "index.d.ts", "declare const ambient: string;\n")
    _write(workspace / "node_modules" / "@types" / "example" / "package.json", '{"types":"index.d.ts"}\n')
    shim_directory, node = _manager(tmp_path, monkeypatch)
    captured: list[ContainmentRequest] = []

    def fake_execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        del timeout_seconds
        captured.append(request)
        return _success(request)

    monkeypatch.setattr(execution_module, "execute_contained", fake_execute)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))

    result = try_execute_contained_typescript(
        "npx",
        ("--no-install", "tsc", "--noEmit", "src/example.ts"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim_directory,
        environment={"PATH": str(shim_directory)},
    )

    assert result is not None
    snapshot_paths = {item.snapshot_path for item in captured[0].inputs}
    assert "src/example.ts" in snapshot_paths
    assert "src/util.ts" in snapshot_paths
    assert "node_modules/@types/example/index.d.ts" in snapshot_paths
    assert "node_modules/@types/example/package.json" in snapshot_paths


def test_typecheck_dependency_drift_changes_launch_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    dependency = workspace / "src" / "util.ts"
    _write(dependency, "export const value = 1;\n")
    shim_directory, node = _manager(tmp_path, monkeypatch)
    observed: list[str] = []

    def fake_execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        del timeout_seconds
        observed.append(request.launch_digest)
        return _success(request)

    monkeypatch.setattr(execution_module, "execute_contained", fake_execute)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))
    arguments = ("--no-install", "tsc", "--noEmit", "src/example.ts")

    assert (
        try_execute_contained_typescript(
            "npx",
            arguments,
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim_directory,
            environment={"PATH": str(shim_directory)},
        )
        is not None
    )
    _write(dependency, "export const value = 2;\n")
    assert (
        try_execute_contained_typescript(
            "npx",
            arguments,
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim_directory,
            environment={"PATH": str(shim_directory)},
        )
        is not None
    )

    assert len(observed) == 2
    assert observed[0] != observed[1]


def test_backend_failure_falls_back_to_guard_without_executing_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, node = _manager(tmp_path, monkeypatch)

    def failed_execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        del timeout_seconds
        return ContainmentExecutionResult(
            exit_code=None,
            stdout="",
            stderr="unsupported-platform",
            timed_out=False,
            attestation=ContainmentAttestation(
                backend=ContainmentBackend.UNSUPPORTED,
                backend_digest=hashlib.sha256(b"unavailable").hexdigest(),
                request_digest=request.binding_digest,
                policy_digest=request.policy.digest,
                launch_digest=request.launch_digest,
                executable_digest=request.executable_digest,
                enforced=False,
                failure=ContainmentFailure.UNSUPPORTED_PLATFORM,
            ),
        )

    monkeypatch.setattr(execution_module, "execute_contained", failed_execute)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))

    assert (
        try_execute_contained_typescript(
            "npx",
            ("--no-install", "tsc", "--noEmit", "src/example.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim_directory,
            environment={"PATH": str(shim_directory)},
        )
        is None
    )


def test_contained_typecheck_failure_returns_to_guard_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, node = _manager(tmp_path, monkeypatch)

    def failed_typecheck(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        del timeout_seconds
        return ContainmentExecutionResult(
            exit_code=2,
            stdout="",
            stderr="TS2307: dependency unavailable",
            timed_out=False,
            attestation=ContainmentAttestation(
                backend=ContainmentBackend.LINUX_BWRAP,
                backend_digest=hashlib.sha256(b"backend").hexdigest(),
                request_digest=request.binding_digest,
                policy_digest=request.policy.digest,
                launch_digest=request.launch_digest,
                executable_digest=request.executable_digest,
                enforced=True,
                failure=None,
            ),
        )

    monkeypatch.setattr(execution_module, "execute_contained", failed_typecheck)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))

    assert (
        try_execute_contained_typescript(
            "npx",
            ("--no-install", "tsc", "--noEmit", "src/example.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim_directory,
            environment={"PATH": str(shim_directory)},
        )
        is None
    )


def test_missing_authenticated_health_never_reaches_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, node = _manager(tmp_path, monkeypatch)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))

    def unavailable_health(_guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        raise RuntimeError("daemon unavailable")

    def unexpected_execute(
        request: ContainmentRequest,
        *,
        timeout_seconds: float,
    ) -> ContainmentExecutionResult:
        del request, timeout_seconds
        pytest.fail("missing daemon health reached containment executor")

    monkeypatch.setattr(execution_module, "_load_current_containment_health", unavailable_health)
    monkeypatch.setattr(execution_module, "execute_contained", unexpected_execute)

    result = try_execute_contained_typescript(
        "npx",
        ("--no-install", "tsc", "--noEmit", "src/example.ts"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim_directory,
        environment={"PATH": str(shim_directory)},
    )

    assert result is None


@pytest.mark.parametrize(
    "argv",
    (
        ("--no-install", "--package", "typescript", "tsc", "--noEmit", "src/example.ts"),
        ("tsc", "--noEmit", "src/example.ts"),
        ("--no-install", "tsc", "--project", "tsconfig.json", "--noEmit"),
        ("--no-install", "tsc", "--noEmit=false", "src/example.ts"),
    ),
)
def test_exploit_deltas_never_reach_containment_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: tuple[str, ...],
) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, _node = _manager(tmp_path, monkeypatch)

    def unexpected_execute(
        request: ContainmentRequest,
        *,
        timeout_seconds: float,
    ) -> ContainmentExecutionResult:
        del request, timeout_seconds
        pytest.fail("ineligible command reached containment executor")

    monkeypatch.setattr(execution_module, "execute_contained", unexpected_execute)

    assert (
        try_execute_contained_typescript(
            "npx",
            argv,
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim_directory,
            environment={"PATH": str(shim_directory)},
        )
        is None
    )


def test_package_tree_symlink_never_reaches_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, _node = _manager(tmp_path, monkeypatch)
    link = workspace / "node_modules" / "typescript" / "lib" / "escape.js"
    link.symlink_to("/usr/bin/true")

    def unexpected_execute(
        request: ContainmentRequest,
        *,
        timeout_seconds: float,
    ) -> ContainmentExecutionResult:
        del request, timeout_seconds
        pytest.fail("symlinked package tree reached containment executor")

    monkeypatch.setattr(execution_module, "execute_contained", unexpected_execute)

    assert (
        try_execute_contained_typescript(
            "npx",
            ("--no-install", "tsc", "--noEmit", "src/example.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim_directory,
            environment={"PATH": str(shim_directory)},
        )
        is None
    )


def test_node_digest_is_bound_into_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _workspace(tmp_path)
    shim_directory, node = _manager(tmp_path, monkeypatch)
    observed: list[str] = []

    def fake_execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        del timeout_seconds
        observed.append(request.executable_digest)
        return _success(request)

    monkeypatch.setattr(execution_module, "execute_contained", fake_execute)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))
    result = try_execute_contained_typescript(
        "npx",
        ("--no-install", "tsc", "--noEmit", "src/example.ts"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim_directory,
        environment={"PATH": str(shim_directory)},
    )

    assert result is not None
    assert observed == [file_sha256(str(node))]

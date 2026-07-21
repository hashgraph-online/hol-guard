from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_node_execution as execution_module
from codex_plugin_scanner.guard.contained_node_execution import try_execute_contained_node_command
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentAttestation,
    ContainmentBackend,
    ContainmentFailure,
    ContainmentInput,
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import (
    ContainmentExecutionResult,
    execute_contained,
    file_sha256,
)
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
)
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs import complete_workspace_snapshot

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


def _manager(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    directory = (root / "bin").resolve()
    _write(directory / "npx", "#!/bin/sh\nexit 99\n", executable=True)
    node = directory / "node"
    _write(node, "synthetic-node", executable=True)
    monkeypatch.setenv("PATH", str(directory))
    monkeypatch.setattr(execution_module, "_load_current_containment_health", _fake_health)
    monkeypatch.setattr(execution_module, "_resolve_node", _node_resolver(node))
    return directory, node


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


def _result(request: ContainmentRequest, exit_code: int = 0) -> ContainmentExecutionResult:
    return ContainmentExecutionResult(
        exit_code=exit_code,
        stdout="runner-output\n",
        stderr="" if exit_code == 0 else "runner-failed\n",
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


@pytest.mark.skipif(sys.platform not in {"darwin", "linux"}, reason="requires a supported containment platform")
def test_platform_backend_runs_path_pinned_node_or_fails_closed(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node executable unavailable")
    canonical_node = str(Path(node).resolve(strict=True))
    workspace = (tmp_path / "workspace").resolve()
    script = workspace / "runner.mjs"
    _write(script, "console.log('contained-node-ok');\n")
    script_digest = file_sha256(str(script))
    request = ContainmentRequest(
        argv=(canonical_node, "runner.mjs"),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), ()),
        inputs=(ContainmentInput(str(script), "runner.mjs", script_digest),),
        launch_digest=hashlib.sha256(b"contained-node-launch").hexdigest(),
        executable_digest=file_sha256(canonical_node),
        operation_id="test",
    )

    result = execute_contained(request)

    if sys.platform == "linux" and result.attestation.failure is ContainmentFailure.UNSUPPORTED_PLATFORM:
        assert result.enforced is False
        assert result.exit_code is None
        assert result.stderr == "unsupported-platform"
        return
    if sys.platform == "darwin" and not canonical_node.startswith(("/System/", "/usr/", "/bin/", "/sbin/")):
        assert result.enforced is False
        assert result.attestation.failure is ContainmentFailure.APPLY_FAILED
        assert "immutable system executable" in result.stderr
        return
    assert result.enforced is True
    assert result.exit_code == 0, result.stderr
    assert result.stdout == "contained-node-ok\n"


@pytest.mark.parametrize(
    ("runner", "argv", "operation"),
    (
        ("vitest", ("--no-install", "vitest", "run", "src/example.test.ts"), "test"),
        ("eslint", ("--no-install", "eslint", "--no-cache", "src/example.ts"), "lint"),
    ),
)
def test_exact_runner_routes_through_central_contained_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: str,
    argv: tuple[str, ...],
    operation: str,
) -> None:
    workspace = _workspace(tmp_path, runner)
    shim, node = _manager(tmp_path, monkeypatch)
    captured: list[ContainmentRequest] = []

    def execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        assert timeout_seconds == 120.0
        captured.append(request)
        return _result(request)

    monkeypatch.setattr(execution_module, "execute_contained", execute)
    result = try_execute_contained_node_command(
        "npx",
        argv,
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment={"PATH": str(shim), "GITHUB_TOKEN": "must-not-cross"},
    )

    assert result is not None
    assert result.operation_id == operation
    assert result.proof.route is ProofRoute.CONTAINED
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert len(captured) == 1
    request = captured[0]
    assert request.argv[0] == str(node)
    assert request.argv[1] == f"node_modules/{runner}/bin/{runner}.mjs"
    assert request.policy.allowed_write_paths == ()
    assert "GITHUB_TOKEN" not in request.environment_dict()
    paths = {item.snapshot_path for item in request.inputs}
    assert "vitest.config.ts" in paths
    assert f"node_modules/{runner}/package.json" in paths


def test_contained_nonzero_result_is_returned_without_manager_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "eslint")
    shim, _node = _manager(tmp_path, monkeypatch)

    def failed_result(
        request: ContainmentRequest,
        *,
        timeout_seconds: float,
    ) -> ContainmentExecutionResult:
        del timeout_seconds
        return _result(request, 1)

    monkeypatch.setattr(execution_module, "execute_contained", failed_result)

    result = try_execute_contained_node_command(
        "npx",
        ("--no-install", "eslint", "--no-cache", "src/example.ts"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment={"PATH": str(shim)},
    )

    assert result is not None
    assert result.exit_code == 1
    assert result.stderr == "runner-failed\n"


def test_missing_health_never_reaches_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _workspace(tmp_path, "vitest")
    shim, _node = _manager(tmp_path, monkeypatch)

    def unavailable(_guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        raise RuntimeError("daemon unavailable")

    def unexpected(_request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        raise AssertionError("missing health reached executor")

    monkeypatch.setattr(execution_module, "_load_current_containment_health", unavailable)
    monkeypatch.setattr(execution_module, "execute_contained", unexpected)

    assert (
        try_execute_contained_node_command(
            "npx",
            ("--no-install", "vitest", "run", "src/example.test.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


@pytest.mark.parametrize("failure", (ContainmentFailure.UNSUPPORTED_PLATFORM, ContainmentFailure.POLICY_MISMATCH))
def test_unenforced_backend_failure_returns_to_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: ContainmentFailure,
) -> None:
    workspace = _workspace(tmp_path, "eslint")
    shim, node = _manager(tmp_path, monkeypatch)

    def failed(request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        return ContainmentExecutionResult(
            exit_code=None,
            stdout="",
            stderr=failure.value,
            timed_out=False,
            attestation=ContainmentAttestation(
                backend=ContainmentBackend.UNSUPPORTED,
                backend_digest=hashlib.sha256(b"unavailable").hexdigest(),
                request_digest=request.binding_digest,
                policy_digest=request.policy.digest,
                launch_digest=request.launch_digest,
                executable_digest=file_sha256(str(node)),
                enforced=False,
                failure=failure,
            ),
        )

    monkeypatch.setattr(execution_module, "execute_contained", failed)

    assert (
        try_execute_contained_node_command(
            "npx",
            ("--no-install", "eslint", "--no-cache", "src/example.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


def test_workspace_or_executable_drift_never_reaches_or_survives_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "eslint")
    shim, _node = _manager(tmp_path, monkeypatch)
    executable = workspace / "node_modules" / "eslint" / "bin" / "eslint.mjs"

    def drifting_snapshot(path: Path):
        captured = complete_workspace_snapshot(path)
        _write(executable, "process.exit(2);\n", executable=True)
        return captured

    def unexpected(_request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        raise AssertionError("drifted executable reached executor")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.contained_node_execution.complete_workspace_snapshot",
        drifting_snapshot,
    )
    monkeypatch.setattr(execution_module, "execute_contained", unexpected)

    assert (
        try_execute_contained_node_command(
            "npx",
            ("--no-install", "eslint", "--no-cache", "src/example.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


@pytest.mark.parametrize(
    ("relative_path", "replacement"),
    (
        ("package.json", '{"devDependencies":{"eslint":"9.9.9"}}'),
        ("package-lock.json", '{"packages":{"node_modules/eslint":{"version":"9.9.9"}}}'),
        (
            "node_modules/eslint/package.json",
            '{"name":"not-eslint","version":"9.9.9","bin":{"eslint":"bin/eslint.mjs"}}',
        ),
    ),
)
def test_provenance_drift_before_snapshot_never_reaches_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
    replacement: str,
) -> None:
    workspace = _workspace(tmp_path, "eslint")
    shim, _node = _manager(tmp_path, monkeypatch)
    original_snapshot = complete_workspace_snapshot

    def drifting_snapshot(path: Path):
        _write(workspace / relative_path, replacement)
        return original_snapshot(path)

    def unexpected(_request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        raise AssertionError("drifted provenance reached executor")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.contained_node_execution.complete_workspace_snapshot",
        drifting_snapshot,
    )
    monkeypatch.setattr(execution_module, "execute_contained", unexpected)

    assert (
        try_execute_contained_node_command(
            "npx",
            ("--no-install", "eslint", "--no-cache", "src/example.ts"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


@pytest.mark.parametrize(
    "argv",
    (
        ("vitest", "run", "src/example.test.ts"),
        ("--no-install", "vitest", "run", "--coverage", "src/example.test.ts"),
        ("--no-install", "eslint", "--no-cache", "--fix", "src/example.ts"),
    ),
)
def test_exploit_deltas_never_reach_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: tuple[str, ...],
) -> None:
    runner = "eslint" if "eslint" in argv else "vitest"
    workspace = _workspace(tmp_path, runner)
    shim, _node = _manager(tmp_path, monkeypatch)

    def unexpected(_request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        raise AssertionError("ineligible command reached executor")

    monkeypatch.setattr(execution_module, "execute_contained", unexpected)

    assert (
        try_execute_contained_node_command(
            "npx",
            argv,
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )

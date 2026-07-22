from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import contained_package_script_execution as execution_module
from codex_plugin_scanner.guard.contained_package_script_execution import (
    try_execute_contained_package_script,
)
from codex_plugin_scanner.guard.package_shim_gate import package_shim_command_requires_guard
from codex_plugin_scanner.guard.runtime import local_package_script_evidence as evidence_module
from codex_plugin_scanner.guard.runtime.command_contained_routine_candidates import (
    contained_routine_candidate_operation,
)
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentAttestation,
    ContainmentBackend,
    ContainmentFailure,
    ContainmentInput,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import ContainmentExecutionResult, file_sha256
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
)
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRequirement, ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.local_package_script_evidence import (
    build_local_package_script_evidence,
)
from codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs import complete_workspace_snapshot
from tests.guard_command_corpus import iter_adversarial_corpus, iter_benign_corpus
from tests.guard_command_corpus_oracle import iter_adversarial_oracle, iter_benign_oracle

_INTEGRITY = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")
_OPERATIONS = {
    "test": ("vitest", "vitest", "vitest run src/example.test.ts"),
    "lint": ("eslint", "eslint", "eslint --no-cache src/example.ts"),
    "build": ("vite", "vite", "vite build"),
    "typecheck": ("typescript", "tsc", "tsc --noEmit --pretty"),
}


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")
    if executable:
        _ = path.chmod(0o755)


def _workspace(root: Path, operation: str) -> Path:
    workspace = (root / "workspace").resolve()
    package, runner, script = _OPERATIONS[operation]
    version = "1.2.3"
    _write(
        workspace / "package.json",
        json.dumps({"scripts": {operation: script}, "devDependencies": {package: version}}),
    )
    _write(
        workspace / "package-lock.json",
        json.dumps(
            {
                "packages": {
                    f"node_modules/{package}": {
                        "version": version,
                        "resolved": f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz",
                        "integrity": _INTEGRITY,
                    }
                }
            }
        ),
    )
    target = workspace / "node_modules" / package / "bin" / f"{runner}.mjs"
    _write(target, "process.exit(0);\n", executable=True)
    _write(
        workspace / "node_modules" / package / "package.json",
        json.dumps({"name": package, "version": version, "bin": {runner: f"bin/{runner}.mjs"}}),
    )
    _write(workspace / "src" / "example.ts", "export const value = 1;\n")
    _write(workspace / "src" / "example.test.ts", "test('value', () => {});\n")
    _write(workspace / "vite.config.ts", "export default {};\n")
    _write(workspace / "tsconfig.json", '{"compilerOptions":{"noEmit":true}}\n')
    return workspace


def _manager(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    shim = (root / "shim").resolve()
    shim.mkdir()
    real = (root / "real-bin").resolve()
    bun = real / "bun"
    _write(bun, "synthetic-bun", executable=True)
    monkeypatch.setattr(execution_module, "_resolve_bun", _bun_resolver(bun))
    monkeypatch.setattr(execution_module, "_load_current_containment_health", _fake_health)
    return shim, bun


def _bun_resolver(bun: Path) -> Callable[[str, Path], str]:
    def resolve(_path: str, _shim: Path) -> str:
        return str(bun)

    return resolve


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


def _result(request: ContainmentRequest, exit_code: int = 0) -> ContainmentExecutionResult:
    return ContainmentExecutionResult(
        exit_code=exit_code,
        stdout="routine-output\n",
        stderr="" if exit_code == 0 else "routine-failed\n",
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


def test_every_cdx_061_corpus_case_requires_owned_containment_proof() -> None:
    operations: set[str] = set()
    count = 0
    for case, oracle in zip(iter_benign_corpus(), iter_benign_oracle(), strict=True):
        evaluation = evaluate_command(case.command, cwd=Path("workspace"), home_dir=Path("home"))
        operation = contained_routine_candidate_operation(evaluation.command)
        if oracle.owner != "CDX-061":
            assert operation is None
            continue
        count += 1
        assert operation is not None
        operations.add(operation)
        assert evaluation.minimum_action == "review"
        assert evaluation.decision_plane.action == "review"
        assert evaluation.decision_plane.proof_routes == frozenset()
        assert any(
            reason.reason_code == "contained-routine-proof-required" for reason in evaluation.decision_plane.reasons
        )
    assert count == 275
    assert operations == {"test", "lint", "build", "typecheck", "compile-check", "dependency-tree", "workspace-check"}
    for case, oracle in zip(iter_adversarial_corpus(), iter_adversarial_oracle(), strict=True):
        assert oracle.owner != "CDX-061"
        evaluation = evaluate_command(case.command, cwd=Path("workspace"), home_dir=Path("home"))
        assert contained_routine_candidate_operation(evaluation.command) is None


@pytest.mark.parametrize("operation", tuple(_OPERATIONS))
def test_exact_bun_script_runs_through_central_contained_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    workspace = _workspace(tmp_path, operation)
    shim, bun = _manager(tmp_path, monkeypatch)
    captured: list[ContainmentRequest] = []

    def execute(request: ContainmentRequest, *, timeout_seconds: float) -> ContainmentExecutionResult:
        assert timeout_seconds == 120.0
        captured.append(request)
        return _result(request)

    monkeypatch.setattr(execution_module, "execute_contained", execute)
    result = try_execute_contained_package_script(
        "bun",
        ("run", operation),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment={"PATH": str(shim), "GITHUB_TOKEN": "must-not-cross"},
    )

    assert result is not None
    assert result.operation_id == operation
    assert result.proof.route is ProofRoute.CONTAINED
    assert ProofRequirement.DEPENDENCY_PROVENANCE not in result.proof.satisfied_requirements
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert len(captured) == 1
    request = captured[0]
    assert request.argv[0] == str(bun)
    assert request.argv[1].startswith("node_modules/")
    assert request.policy.allowed_write_paths == ()
    assert request.policy.network_allowed is False
    assert "GITHUB_TOKEN" not in request.environment_dict()
    assert {"package.json", "package-lock.json", "src/example.ts"} <= {item.snapshot_path for item in request.inputs}


def test_contained_nonzero_result_is_returned_without_live_manager_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "test")
    shim, _bun = _manager(tmp_path, monkeypatch)

    def failed_result(request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        return _result(request, 1)

    monkeypatch.setattr(execution_module, "execute_contained", failed_result)

    result = try_execute_contained_package_script(
        "bun",
        ("run", "test"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment={"PATH": str(shim)},
    )

    assert result is not None
    assert result.exit_code == 1
    assert result.stderr == "routine-failed\n"


@pytest.mark.parametrize(
    ("operation", "scripts", "reason"),
    (
        ("build", {"build": "vite build && cat /etc/passwd"}, "script_not_exact"),
        ("build", {"prebuild": "node prepare.js"}, "lifecycle_script_present"),
        (
            "typecheck",
            {"typecheck": "tsc --noEmit --project ../x"},
            "script_arguments_not_result_only",
        ),
        ("lint", {"lint": "eslint --fix src/example.ts"}, "script_arguments_not_result_only"),
        (
            "test",
            {"test": "vitest run --coverage src/example.test.ts"},
            "script_arguments_not_result_only",
        ),
    ),
)
def test_workspace_code_abuse_cannot_complete_launch_evidence(
    tmp_path: Path,
    operation: str,
    scripts: dict[str, str],
    reason: str,
) -> None:
    workspace = _workspace(tmp_path, operation)
    raw_manifest = cast(object, json.loads((workspace / "package.json").read_text(encoding="utf-8")))
    assert isinstance(raw_manifest, dict)
    manifest = cast(dict[str, object], raw_manifest)
    raw_scripts = manifest.get("scripts")
    assert isinstance(raw_scripts, dict)
    cast(dict[str, object], raw_scripts).update(scripts)
    _write(workspace / "package.json", json.dumps(manifest))

    evidence = build_local_package_script_evidence("bun", ("run", operation), workspace=workspace)

    assert evidence is not None
    assert evidence.status == "incomplete"
    assert reason in evidence.reasons


@pytest.mark.parametrize("name", ("bun.lock", "pnpm-lock.yaml", "yarn.lock"))
def test_ambiguous_lock_sources_fail_closed(tmp_path: Path, name: str) -> None:
    workspace = _workspace(tmp_path, "build")
    _write(workspace / name, "untrusted-lock")

    evidence = build_local_package_script_evidence("bun", ("run", "build"), workspace=workspace)

    assert evidence is not None
    assert evidence.status == "incomplete"
    assert "lock_source_ambiguous" in evidence.reasons


@pytest.mark.parametrize(
    ("specifier", "version", "expected"),
    (("^1.2.3", "1.9.0", True), ("^0.12.0", "0.12.3", True), ("^0.0.3", "0.0.4", False)),
)
def test_caret_version_matching_follows_semver(specifier: str, version: str, expected: bool) -> None:
    assert evidence_module._version_spec_matches(specifier, version) is expected  # pyright: ignore[reportPrivateUsage]


def test_scoped_registry_tarball_omits_scope_from_filename() -> None:
    resolved = "https://registry.npmjs.org/@scope/tool/-/tool-1.2.3.tgz"
    assert evidence_module._canonical_resolution("@scope/tool", "1.2.3", resolved)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("relative", (".env", "src/linked.ts"))
def test_protected_or_linked_workspace_never_reaches_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    workspace = _workspace(tmp_path, "build")
    if relative.endswith("linked.ts"):
        outside = tmp_path / "outside.ts"
        _write(outside, "private")
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(outside)
    else:
        _write(workspace / relative, "synthetic-secret")
    shim, _bun = _manager(tmp_path, monkeypatch)

    def unexpected(_request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        raise AssertionError("unsafe workspace reached executor")

    monkeypatch.setattr(execution_module, "execute_contained", unexpected)

    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", "build"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


def test_runner_drift_after_evidence_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "build")
    runner = workspace / "node_modules" / "vite" / "bin" / "vite.mjs"
    shim, _bun = _manager(tmp_path, monkeypatch)
    actual_snapshot = complete_workspace_snapshot

    def drifting_snapshot(path: Path) -> tuple[str, tuple[ContainmentInput, ...]]:
        captured = actual_snapshot(path)
        _write(runner, "process.exit(9);\n", executable=True)
        return captured

    monkeypatch.setattr(execution_module, "complete_workspace_snapshot", drifting_snapshot)

    def unexpected(_request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        raise AssertionError("drifted runner reached executor")

    monkeypatch.setattr(execution_module, "execute_contained", unexpected)

    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", "build"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


def test_untrusted_runner_is_contained_without_minting_dependency_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "build")
    runner = workspace / "node_modules" / "vite" / "bin" / "vite.mjs"
    _write(runner, "arbitraryWorkspaceCode();\n", executable=True)
    shim, _bun = _manager(tmp_path, monkeypatch)

    def execute(request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        assert request.policy.network_allowed is False
        assert request.policy.allowed_write_paths == ()
        assert "GITHUB_TOKEN" not in request.environment_dict()
        return _result(request)

    monkeypatch.setattr(execution_module, "execute_contained", execute)
    result = try_execute_contained_package_script(
        "bun",
        ("run", "build"),
        workspace=workspace,
        guard_home=tmp_path,
        shim_directory=shim,
        environment={"PATH": str(shim), "GITHUB_TOKEN": "must-not-cross"},
    )

    assert result is not None
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert ProofRequirement.DEPENDENCY_PROVENANCE not in result.proof.satisfied_requirements


def test_bun_alias_resolving_into_shim_directory_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "build")
    shim = tmp_path / "shim"
    alias = tmp_path / "alias"
    shim.mkdir()
    alias.mkdir()
    _write(shim / "bun", "shim", executable=True)
    (alias / "bun").symlink_to(shim / "bun")
    monkeypatch.setattr(execution_module, "_load_current_containment_health", _fake_health)

    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", "build"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(alias)},
        )
        is None
    )


def test_unenforced_backend_and_missing_health_return_to_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path, "build")
    shim, bun = _manager(tmp_path, monkeypatch)

    def failed(request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
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
                executable_digest=file_sha256(str(bun)),
                enforced=False,
                failure=ContainmentFailure.UNSUPPORTED_PLATFORM,
            ),
        )

    monkeypatch.setattr(execution_module, "execute_contained", failed)
    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", "build"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )

    def unavailable(_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        raise RuntimeError("unavailable")

    monkeypatch.setattr(execution_module, "_load_current_containment_health", unavailable)
    assert (
        try_execute_contained_package_script(
            "bun",
            ("run", "build"),
            workspace=workspace,
            guard_home=tmp_path,
            shim_directory=shim,
            environment={"PATH": str(shim)},
        )
        is None
    )


def test_all_bun_execution_enters_guard_but_only_exact_scripts_have_evidence(tmp_path: Path) -> None:
    for operation in _OPERATIONS:
        assert package_shim_command_requires_guard("bun", ("run", operation), workspace=tmp_path)
    for argv in (("run", "dev"), ("run", "build", "--watch"), ("script.ts",)):
        assert package_shim_command_requires_guard("bun", argv, workspace=tmp_path)
        assert build_local_package_script_evidence("bun", argv, workspace=tmp_path) is None
    assert not package_shim_command_requires_guard("bun", ("--version",), workspace=tmp_path)

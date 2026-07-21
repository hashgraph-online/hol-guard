from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentAttestation,
    ContainmentBackend,
    ContainmentFailure,
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import file_sha256
from codex_plugin_scanner.guard.runtime.containment_health import (
    CONTAINMENT_POLICY_CONTRACT_DIGEST,
    ContainmentHealthEvidence,
    contained_positive_proof,
)
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRequirement, ProofRoute


def _request(workspace: Path, *, executable: str = "/usr/bin/true") -> ContainmentRequest:
    output = workspace / "output"
    output.mkdir(exist_ok=True)
    return ContainmentRequest(
        argv=(executable,),
        cwd=str(workspace),
        environment=(("HOME", str(output)), ("PATH", "/usr/bin:/bin")),
        policy=ContainmentPolicy(str(workspace), (str(output),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256(executable),
        operation_id="typecheck",
    )


def _attestation(request: ContainmentRequest, *, enforced: bool = True) -> ContainmentAttestation:
    return ContainmentAttestation(
        backend=ContainmentBackend.MACOS_SANDBOX,
        backend_digest=hashlib.sha256(b"backend").hexdigest(),
        request_digest=request.binding_digest,
        policy_digest=request.policy.digest,
        launch_digest=request.launch_digest,
        executable_digest=request.executable_digest,
        enforced=enforced,
        failure=None if enforced else ContainmentFailure.APPLY_FAILED,
    )


def _health(attestation: ContainmentAttestation) -> ContainmentHealthEvidence:
    fingerprint = hashlib.sha256(b"runtime").hexdigest()
    return ContainmentHealthEvidence(
        backend=attestation.backend,
        backend_digest=attestation.backend_digest,
        policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
        daemon_fingerprint=fingerprint,
        runtime_fingerprint=fingerprint,
        probe_at="2026-07-19T15:00:00+00:00",
        probe_enforced=True,
    )


def test_contract_binds_paths_environment_policy_and_executable(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    request = _request(workspace)

    assert len(request.binding_digest) == 64
    assert len(request.policy.digest) == 64
    assert request.environment_dict() == {"HOME": str(workspace / "output"), "PATH": "/usr/bin:/bin"}
    assert request.argv[0] == "/usr/bin/true"


@pytest.mark.parametrize(
    ("key", "value"),
    (("GITHUB_TOKEN", "sentinel"), ("AWS_PROFILE", "prod"), ("PASSWORD", "sentinel")),
)
def test_contract_rejects_secret_bearing_environment(tmp_path: Path, key: str, value: str) -> None:
    workspace = tmp_path.resolve()
    output = workspace / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="secret-bearing"):
        _ = ContainmentRequest(
            argv=("/usr/bin/true",),
            cwd=str(workspace),
            environment=((key, value),),
            policy=ContainmentPolicy(str(workspace), (str(output),)),
            inputs=(),
            launch_digest=hashlib.sha256(b"launch").hexdigest(),
            executable_digest=file_sha256("/usr/bin/true"),
            operation_id="test",
        )


@pytest.mark.parametrize("relative", (".git", ".guard", ".env.local", "nested/credentials"))
def test_policy_rejects_protected_write_scope(tmp_path: Path, relative: str) -> None:
    workspace = tmp_path.resolve()
    target = workspace / relative
    target.mkdir(parents=True)
    with pytest.raises(ValueError, match="protected"):
        _ = ContainmentPolicy(str(workspace), (str(target),))


def test_contract_rejects_aliases_and_external_cwd(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    output = workspace / "output"
    output.mkdir()
    executable_link = workspace / "true"
    executable_link.symlink_to("/usr/bin/true")
    policy = ContainmentPolicy(str(workspace), (str(output),))
    with pytest.raises(ValueError, match="path-pinned"):
        _ = ContainmentRequest(
            argv=(str(executable_link),),
            cwd=str(workspace),
            environment=(),
            policy=policy,
            inputs=(),
            launch_digest=hashlib.sha256(b"launch").hexdigest(),
            executable_digest=file_sha256("/usr/bin/true"),
            operation_id="test",
        )
    with pytest.raises(ValueError, match="inside the workspace"):
        _ = ContainmentRequest(
            argv=("/usr/bin/true",),
            cwd=str(tmp_path),
            environment=(),
            policy=policy,
            inputs=(),
            launch_digest=hashlib.sha256(b"launch").hexdigest(),
            executable_digest=file_sha256("/usr/bin/true"),
            operation_id="test",
        )


def test_only_exact_successful_attestation_mints_contained_proof(tmp_path: Path) -> None:
    request = _request(tmp_path.resolve())
    attestation = _attestation(request)
    proof = contained_positive_proof(
        attestation,
        request,
        _health(attestation),
        requirements=(ProofRequirement.EXECUTABLE_IDENTITY, ProofRequirement.LAUNCH_CHAIN),
        now=datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc),
        runtime_fingerprint=hashlib.sha256(b"runtime").hexdigest(),
    )

    assert proof.route is ProofRoute.CONTAINED
    assert proof.enforced is True
    assert ProofRequirement.CONTAINMENT_IDENTITY in proof.satisfied_requirements

    failed = _attestation(request, enforced=False)
    with pytest.raises(ValueError, match="failed containment"):
        _ = contained_positive_proof(
            failed,
            request,
            _health(failed),
            requirements=(),
            now=datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc),
            runtime_fingerprint=hashlib.sha256(b"runtime").hexdigest(),
        )

    changed_output = request.policy.allowed_write_paths[0] + "-changed"
    os.mkdir(changed_output)
    changed = ContainmentRequest(
        argv=request.argv,
        cwd=request.cwd,
        environment=request.environment,
        policy=ContainmentPolicy(request.policy.workspace, (changed_output,)),
        inputs=request.inputs,
        launch_digest=request.launch_digest,
        executable_digest=request.executable_digest,
        operation_id=request.operation_id,
    )
    with pytest.raises(ValueError, match="request binding changed"):
        _ = contained_positive_proof(
            attestation,
            changed,
            _health(attestation),
            requirements=(),
            now=datetime(2026, 7, 19, 15, 0, tzinfo=timezone.utc),
            runtime_fingerprint=hashlib.sha256(b"runtime").hexdigest(),
        )


def test_attestation_rejects_enforcement_failure_contradictions(tmp_path: Path) -> None:
    request = _request(tmp_path.resolve())
    with pytest.raises(ValueError, match="cannot fail"):
        _ = ContainmentAttestation(
            backend=ContainmentBackend.MACOS_SANDBOX,
            backend_digest=hashlib.sha256(b"backend").hexdigest(),
            request_digest=request.binding_digest,
            policy_digest=request.policy.digest,
            launch_digest=request.launch_digest,
            executable_digest=request.executable_digest,
            enforced=True,
            failure=ContainmentFailure.APPLY_FAILED,
        )
    with pytest.raises(ValueError, match="cannot claim enforcement"):
        _ = ContainmentAttestation(
            backend=ContainmentBackend.MACOS_SANDBOX,
            backend_digest=hashlib.sha256(b"backend").hexdigest(),
            request_digest=request.binding_digest,
            policy_digest=request.policy.digest,
            launch_digest=request.launch_digest,
            executable_digest=request.executable_digest,
            enforced=False,
            failure=None,
        )

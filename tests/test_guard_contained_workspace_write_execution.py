from __future__ import annotations

import hashlib
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_workspace_write_execution as write_module
from codex_plugin_scanner.guard.contained_workspace_write_execution import (
    ContainedWriteOperation,
    try_execute_contained_workspace_write,
)
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentAttestation,
    ContainmentBackend,
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
from codex_plugin_scanner.guard.runtime.containment_outputs import ContainmentCapturedOutput
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRequirement, ProofRoute
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition


def _write(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")
    if executable:
        _ = path.chmod(0o700)


write_contained_test_file = _write


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


def _macos_health() -> tuple[ContainmentHealthEvidence, str]:
    fingerprint = hashlib.sha256(b"runtime").hexdigest()
    return (
        ContainmentHealthEvidence(
            backend=ContainmentBackend.MACOS_SANDBOX,
            backend_digest=file_sha256("/usr/bin/sandbox-exec"),
            policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
            daemon_fingerprint=fingerprint,
            runtime_fingerprint=fingerprint,
            probe_at=datetime.now(timezone.utc).isoformat(),
            probe_enforced=True,
        ),
        fingerprint,
    )


def _attestation(request: ContainmentRequest) -> ContainmentAttestation:
    return ContainmentAttestation(
        backend=ContainmentBackend.LINUX_BWRAP,
        backend_digest=hashlib.sha256(b"backend").hexdigest(),
        request_digest=request.binding_digest,
        policy_digest=request.policy.digest,
        launch_digest=request.launch_digest,
        executable_digest=request.executable_digest,
        enforced=True,
        failure=None,
    )


def _contained_result(
    content: bytes | None,
    *,
    mutate: Callable[[], None] | None = None,
) -> Callable[..., ContainmentExecutionResult]:
    def execute(request: ContainmentRequest, **_kwargs: object) -> ContainmentExecutionResult:
        if mutate is not None:
            mutate()
        outputs = ()
        if content is not None:
            outputs = (
                ContainmentCapturedOutput(
                    request.declared_outputs[0],
                    content,
                    hashlib.sha256(content).hexdigest(),
                ),
            )
        return ContainmentExecutionResult(0, "", "", False, _attestation(request), outputs)

    return execute


def _prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes | None,
    *,
    mutate: Callable[[], None] | None = None,
) -> tuple[Path, Path]:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    executable = (tmp_path / "runner").resolve()
    _write(executable, "runner\n", executable=True)
    guard_home = (tmp_path / "guard-home-state").resolve()
    guard_home.mkdir()

    def resolve_executable(_name: str, _environment: dict[str, str]) -> str:
        return str(executable)

    def load_health(_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        return _health()

    monkeypatch.setattr(write_module, "_resolve_executable", resolve_executable)
    monkeypatch.setattr(write_module, "_load_current_containment_health", load_health)
    monkeypatch.setattr(write_module, "execute_contained", _contained_result(content, mutate=mutate))
    return workspace, guard_home


prepare_contained_write_test = _prepare


def test_copy_promotes_one_exact_output_atomically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, b'{"new":true}\n')
    _write(workspace / "build" / "schema.json", '{"new":true}\n')
    _write(workspace / "generated" / "schema.json", '{"old":true}\n')
    _ = (workspace / "generated" / "schema.json").chmod(0o640)

    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="build/schema.json",
        target="generated/schema.json",
    )

    assert result is not None
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert result.proof.route is ProofRoute.CONTAINED
    assert ProofRequirement.SHELL_DATA_FLOW in result.proof.satisfied_requirements
    assert result.output_digest == hashlib.sha256(b'{"new":true}\n').hexdigest()
    assert (workspace / "generated" / "schema.json").read_bytes() == b'{"new":true}\n'
    assert (workspace / "generated" / "schema.json").stat().st_mode & 0o777 == 0o640
    assert not tuple((workspace / "generated").glob(".guard-output-*"))


def test_atomic_promotion_rejects_zero_length_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, b"new\n")
    _write(workspace / "build" / "schema.json", "new\n")
    _write(workspace / "generated" / "schema.json", "old\n")

    def zero_length_write(_descriptor: int, _content: bytes) -> int:
        return 0

    monkeypatch.setattr(os, "write", zero_length_write)
    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="build/schema.json",
        target="generated/schema.json",
    )
    assert result is None
    assert (workspace / "generated" / "schema.json").read_bytes() == b"old\n"
    assert not tuple(workspace.glob("generated/.guard-output-*"))


@pytest.mark.parametrize(
    ("operation", "source", "target", "output"),
    (
        ("patch-apply", "change.patch", "src/module.py", b"value = 2\n"),
        ("format-write", "src/module.py", "src/module.py", b"value = 1\n"),
    ),
)
def test_patch_and_format_promote_only_the_declared_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: ContainedWriteOperation,
    source: str,
    target: str,
    output: bytes,
) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, output)
    _write(workspace / "change.patch", "synthetic patch\n")
    _write(workspace / "src" / "module.py", "value=1\n")

    result = try_execute_contained_workspace_write(
        operation,
        workspace=workspace,
        guard_home=guard_home,
        source=source,
        target=target,
    )

    assert result is not None
    assert (workspace / target).read_bytes() == output


def test_patch_check_never_promotes_workspace_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, None)
    _write(workspace / "change.patch", "synthetic patch\n")

    result = try_execute_contained_workspace_write(
        "patch-check",
        workspace=workspace,
        guard_home=guard_home,
        source="change.patch",
    )

    assert result is not None
    assert result.output_digest is None
    assert tuple(workspace.rglob("*")) == (workspace / "change.patch",)


def test_workspace_drift_prevents_promotion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = (tmp_path / "workspace").resolve()

    def mutate() -> None:
        _write(workspace / "unrelated.txt", "changed\n")

    workspace, guard_home = _prepare(tmp_path, monkeypatch, b"new\n", mutate=mutate)
    _write(workspace / "source.txt", "new\n")
    _write(workspace / "output.txt", "old\n")

    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="source.txt",
        target="output.txt",
    )

    assert result is None
    assert (workspace / "output.txt").read_text(encoding="utf-8") == "old\n"


def test_expired_proof_does_not_promote_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, b"new\n")
    _write(workspace / "source.txt", "new\n")
    _write(workspace / "output.txt", "old\n")
    fingerprint = hashlib.sha256(b"runtime").hexdigest()

    def expired_health(_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        return (
            ContainmentHealthEvidence(
                backend=ContainmentBackend.LINUX_BWRAP,
                backend_digest=hashlib.sha256(b"backend").hexdigest(),
                policy_contract_digest=CONTAINMENT_POLICY_CONTRACT_DIGEST,
                daemon_fingerprint=fingerprint,
                runtime_fingerprint=fingerprint,
                probe_at="2000-01-01T00:00:00+00:00",
                probe_enforced=True,
            ),
            fingerprint,
        )

    monkeypatch.setattr(write_module, "_load_current_containment_health", expired_health)
    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="source.txt",
        target="output.txt",
    )

    assert result is None
    assert (workspace / "output.txt").read_text(encoding="utf-8") == "old\n"


def test_post_commit_directory_fsync_failure_returns_committed_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, b"new\n")
    _write(workspace / "source.txt", "new\n")
    _write(workspace / "output.txt", "old\n")
    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic post-commit durability failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="source.txt",
        target="output.txt",
    )

    assert calls == 2
    assert result is not None
    assert (workspace / "output.txt").read_text(encoding="utf-8") == "new\n"


@pytest.mark.parametrize(
    ("source", "target"),
    (
        (".env", "output.txt"),
        ("source.txt", ".guard/policy.json"),
        ("source.txt", "../outside.txt"),
        ("source.txt", "/tmp/outside.txt"),
    ),
)
def test_protected_secret_and_escape_paths_fail_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    target: str,
) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, b"new\n")
    _write(workspace / "source.txt", "new\n")
    _write(workspace / ".env", "synthetic-secret\n")
    (workspace / ".guard").mkdir(exist_ok=True)

    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source=source,
        target=target,
    )

    assert result is None


def test_symlink_and_hardlink_inputs_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, guard_home = _prepare(tmp_path, monkeypatch, b"new\n")
    _write(workspace / "real.txt", "new\n")
    (workspace / "link.txt").symlink_to(workspace / "real.txt")
    os.link(workspace / "real.txt", workspace / "hard.txt")

    for source in ("link.txt", "hard.txt"):
        assert (
            try_execute_contained_workspace_write(
                "copy-generated",
                workspace=workspace,
                guard_home=guard_home,
                source=source,
                target="output.txt",
            )
            is None
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_captures_declared_output_without_live_write(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    output = workspace / "output"
    output.mkdir(parents=True)
    request = ContainmentRequest(
        argv=("/bin/sh", "-c", "printf captured > output/result.txt"),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), (str(output),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256("/bin/sh"),
        operation_id="copy-generated",
        declared_outputs=("output/result.txt",),
    )

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code == 0, result.stderr
    assert len(result.outputs) == 1
    assert result.outputs[0].content == b"captured"
    assert not (output / "result.txt").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_rejects_undeclared_snapshot_mutation(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    output = workspace / "output"
    output.mkdir(parents=True)
    request = ContainmentRequest(
        argv=("/bin/sh", "-c", "printf captured > output/result.txt; printf rogue > rogue.txt"),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), (str(output),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"launch").hexdigest(),
        executable_digest=file_sha256("/bin/sh"),
        operation_id="copy-generated",
        declared_outputs=("output/result.txt",),
    )

    result = execute_contained(request)

    assert result.enforced is False
    assert result.attestation.failure is not None
    assert result.attestation.failure.value == "output-boundary-violation"
    assert not (output / "result.txt").exists()
    assert not (workspace / "rogue.txt").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_copy_runs_contained_and_promotes_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    guard_home = (tmp_path / "guard-home-state").resolve()
    guard_home.mkdir()
    _write(workspace / "build" / "schema.json", '{"contained":true}\n')
    _write(workspace / "generated" / "schema.json", '{"contained":false}\n')

    def load_health(_home: Path) -> tuple[ContainmentHealthEvidence, str]:
        return _macos_health()

    monkeypatch.setattr(write_module, "_load_current_containment_health", load_health)
    result = try_execute_contained_workspace_write(
        "copy-generated",
        workspace=workspace,
        guard_home=guard_home,
        source="build/schema.json",
        target="generated/schema.json",
        environment={"PATH": "/usr/bin:/bin"},
    )

    assert result is not None
    assert result.decision.disposition is FinalDisposition.SILENT_CONTAINED
    assert (workspace / "generated" / "schema.json").read_text(encoding="utf-8") == '{"contained":true}\n'

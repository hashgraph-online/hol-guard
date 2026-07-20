"""OS-enforced execution for Guard containment requests."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .containment_contract import (
    ContainmentAttestation,
    ContainmentBackend,
    ContainmentFailure,
    ContainmentRequest,
)
from .containment_outputs import ContainmentCapturedOutput, OutputBoundaryError, capture_declared_outputs

_OUTPUT_LIMIT: Final = 64 * 1024
_MAX_EXECUTABLE_BYTES: Final = 256 * 1024 * 1024
_MAX_INPUT_BYTES: Final = 256 * 1024 * 1024
_MAX_INPUT_FILES: Final = 20_000


@dataclass(frozen=True, slots=True)
class ContainmentExecutionResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    attestation: ContainmentAttestation
    outputs: tuple[ContainmentCapturedOutput, ...] = ()

    @property
    def enforced(self) -> bool:
        return self.attestation.enforced


@dataclass(frozen=True, slots=True)
class _BackendIdentity:
    kind: ContainmentBackend
    path: str
    digest: str


def file_sha256(path: str) -> str:
    """Hash one non-symlinked regular file without following a replacement link."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_EXECUTABLE_BYTES:
            raise ValueError("executable must be a bounded regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def execute_contained(
    request: ContainmentRequest,
    *,
    timeout_seconds: float = 60.0,
    platform: str | None = None,
) -> ContainmentExecutionResult:
    """Execute exactly once under a verified platform backend or fail closed."""

    if not 0.1 <= float(timeout_seconds) <= 600:
        raise ValueError("timeout_seconds must be between 0.1 and 600")
    selected_platform = platform or sys.platform
    backend = _select_backend(selected_platform)
    if backend is None:
        return _failure_result(request, ContainmentFailure.UNSUPPORTED_PLATFORM)
    try:
        actual_backend_digest = file_sha256(backend.path)
    except (OSError, ValueError):
        return _failure_result(request, ContainmentFailure.BACKEND_UNAVAILABLE, backend=backend.kind)
    if actual_backend_digest != backend.digest:
        return _failure_result(
            request,
            ContainmentFailure.BACKEND_IDENTITY_MISMATCH,
            backend=backend.kind,
            backend_digest=actual_backend_digest,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="guard-contained-") as temp_root:
            root = Path(temp_root).resolve(strict=True)
            snapshot = _snapshot_inputs(request, root)
            if backend.kind is ContainmentBackend.MACOS_SANDBOX:
                pinned_executable = _pin_executable(request, root, backend=backend.kind)
                argv = _macos_argv(backend.path, request, pinned_executable, root)
                cwd = str(snapshot)
                home = str(root / "home")
                temporary = str(root / "tmp")
            else:
                _ = _pin_executable(request, root, backend=backend.kind)
                argv = _linux_argv(backend.path, request, root)
                cwd = str(root)
                home = "/guard/home"
                temporary = "/guard/tmp"
            exit_code, stdout, stderr, timed_out = _run_process(
                argv,
                cwd=cwd,
                environment={
                    **request.environment_dict(),
                    "HOME": home,
                    "TMPDIR": temporary,
                },
                timeout_seconds=float(timeout_seconds),
                temp_root=root,
            )
            outputs = (
                capture_declared_outputs(request, root / "workspace")
                if exit_code == 0 and request.declared_outputs
                else ()
            )
    except OutputBoundaryError as exc:
        return ContainmentExecutionResult(
            exit_code=None,
            stdout="",
            stderr=_bounded_text(str(exc)),
            timed_out=False,
            attestation=_failed_attestation(
                request,
                backend.kind,
                backend.digest,
                ContainmentFailure.OUTPUT_BOUNDARY_VIOLATION,
            ),
        )
    except (OSError, ValueError) as exc:
        return ContainmentExecutionResult(
            exit_code=None,
            stdout="",
            stderr=_bounded_text(str(exc)),
            timed_out=False,
            attestation=_failed_attestation(request, backend.kind, backend.digest, ContainmentFailure.APPLY_FAILED),
        )
    return ContainmentExecutionResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        attestation=_success_attestation(request, backend),
        outputs=outputs,
    )


def _select_backend(platform: str) -> _BackendIdentity | None:
    if platform == "darwin":
        return _backend_at(ContainmentBackend.MACOS_SANDBOX, "/usr/bin/sandbox-exec")
    if platform.startswith("linux"):
        for path in ("/usr/bin/bwrap", "/bin/bwrap"):
            backend = _backend_at(ContainmentBackend.LINUX_BWRAP, path)
            if backend is not None:
                return backend
    return None


def _backend_at(kind: ContainmentBackend, path: str) -> _BackendIdentity | None:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    try:
        digest = file_sha256(path)
    except (OSError, ValueError):
        return None
    return _BackendIdentity(kind, path, digest)


def _pin_executable(
    request: ContainmentRequest,
    temp_root: Path,
    *,
    backend: ContainmentBackend,
) -> str:
    source = request.argv[0]
    if file_sha256(source) != request.executable_digest:
        raise ValueError("executable identity changed before contained execution")
    if backend is ContainmentBackend.MACOS_SANDBOX:
        metadata = os.stat(source, follow_symlinks=False)
        immutable_prefix = source.startswith(("/System/", "/usr/", "/bin/", "/sbin/"))
        if not immutable_prefix or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("macOS containment requires an immutable system executable")
        return source
    destination = temp_root / "guard-exec"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_EXECUTABLE_BYTES:
            raise ValueError("executable must remain a bounded regular file")
        with destination.open("xb") as target, os.fdopen(os.dup(descriptor), "rb") as source_file:
            shutil.copyfileobj(source_file, target, length=1024 * 1024)
    finally:
        os.close(descriptor)
    destination.chmod(0o500)
    if file_sha256(str(destination)) != request.executable_digest:
        raise ValueError("pinned executable copy failed identity verification")
    return str(destination)


def _snapshot_inputs(request: ContainmentRequest, temp_root: Path) -> Path:
    snapshot = temp_root / "workspace"
    snapshot.mkdir(mode=0o700)
    (temp_root / "home").mkdir(mode=0o700)
    (temp_root / "tmp").mkdir(mode=0o700)
    if len(request.inputs) > _MAX_INPUT_FILES:
        raise ValueError("containment input file budget exceeded")
    total_bytes = 0
    for item in request.inputs:
        destination = snapshot.joinpath(*item.snapshot_path.split("/"))
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        copied_bytes, copied_digest = _copy_verified_input(item.source_path, destination)
        total_bytes += copied_bytes
        if total_bytes > _MAX_INPUT_BYTES:
            raise ValueError("containment input byte budget exceeded")
        if copied_digest != item.content_digest:
            raise ValueError("containment input identity changed before snapshot")
    relative_cwd = Path(request.cwd).relative_to(request.policy.workspace)
    snapshot_cwd = snapshot / relative_cwd
    snapshot_cwd.mkdir(mode=0o700, parents=True, exist_ok=True)
    for write_path in request.policy.allowed_write_paths:
        relative = Path(write_path).relative_to(request.policy.workspace)
        (snapshot / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for output_path in request.declared_outputs:
        output = snapshot.joinpath(*output_path.split("/"))
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if output.exists():
            metadata = output.stat(follow_symlinks=False)
            if output.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("declared containment output must be a singly linked regular file")
            output.chmod(0o600)
    return snapshot_cwd


def _copy_verified_input(source: str, destination: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    digest = hashlib.sha256()
    copied = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_INPUT_BYTES:
            raise ValueError("containment input must remain a bounded regular file")
        with destination.open("xb") as target:
            while chunk := os.read(descriptor, 1024 * 1024):
                copied += len(chunk)
                if copied > _MAX_INPUT_BYTES:
                    raise ValueError("containment input byte budget exceeded")
                digest.update(chunk)
                _ = target.write(chunk)
    finally:
        os.close(descriptor)
    destination.chmod(0o400)
    return copied, digest.hexdigest()


def _run_process(
    argv: list[str],
    *,
    cwd: str,
    environment: dict[str, str],
    timeout_seconds: float,
    temp_root: Path,
) -> tuple[int | None, str, str, bool]:
    stdout_path = temp_root / "stdout"
    stderr_path = temp_root / "stderr"
    with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
        timed_out = False
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(process.pid)
            _ = process.wait(timeout=5)
            exit_code = None
        else:
            _kill_process_group(process.pid)
    return (
        exit_code,
        _read_bounded(stdout_path),
        _read_bounded(stderr_path),
        timed_out,
    )


def _macos_argv(
    backend_path: str,
    request: ContainmentRequest,
    pinned_executable: str,
    temp_root: Path,
) -> list[str]:
    profile = [
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
        "(allow process*)",
        "(deny process-fork)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow ipc-posix*)",
        "(allow file-read-metadata)",
        f'(allow file-map-executable (literal "{_profile_escape(pinned_executable)}"))',
    ]
    for path in ("/System", "/usr", "/bin", "/sbin", str(temp_root)):
        profile.append(f'(allow file-read* (subpath "{_profile_escape(path)}"))')
    profile.append(f'(allow file-write* (subpath "{_profile_escape(str(temp_root))}"))')
    profile.append("(deny network*)")
    profile.append('(deny file-write* (subpath "/cores"))')
    return [backend_path, "-p", "\n".join(profile), pinned_executable, *request.argv[1:]]


def _linux_argv(
    backend_path: str,
    request: ContainmentRequest,
    temp_root: Path,
) -> list[str]:
    argv = [
        backend_path,
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--tmpfs",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--bind",
        str(temp_root),
        "/guard",
    ]
    for path in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
        if Path(path).exists():
            argv.extend(("--ro-bind", path, path))
    relative_cwd = Path(request.cwd).relative_to(request.policy.workspace)
    sandbox_cwd = Path("/guard/workspace") / relative_cwd
    argv.extend(("--chdir", str(sandbox_cwd), "--clearenv"))
    for key, value in request.environment:
        argv.extend(("--setenv", key, value))
    argv.extend(("--setenv", "HOME", "/guard/home", "--setenv", "TMPDIR", "/guard/tmp"))
    sandbox_executable = "/guard/guard-exec"
    argv.extend(("--", sandbox_executable, *request.argv[1:]))
    return argv


def _kill_process_group(process_group_id: int) -> None:
    try:
        _ = os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        return


def _success_attestation(request: ContainmentRequest, backend: _BackendIdentity) -> ContainmentAttestation:
    return ContainmentAttestation(
        backend=backend.kind,
        backend_digest=backend.digest,
        request_digest=request.binding_digest,
        policy_digest=request.policy.digest,
        launch_digest=request.launch_digest,
        executable_digest=request.executable_digest,
        enforced=True,
        failure=None,
    )


def _failed_attestation(
    request: ContainmentRequest,
    backend: ContainmentBackend,
    backend_digest: str,
    failure: ContainmentFailure,
) -> ContainmentAttestation:
    return ContainmentAttestation(
        backend=backend,
        backend_digest=backend_digest,
        request_digest=request.binding_digest,
        policy_digest=request.policy.digest,
        launch_digest=request.launch_digest,
        executable_digest=request.executable_digest,
        enforced=False,
        failure=failure,
    )


def _failure_result(
    request: ContainmentRequest,
    failure: ContainmentFailure,
    *,
    backend: ContainmentBackend = ContainmentBackend.UNSUPPORTED,
    backend_digest: str | None = None,
) -> ContainmentExecutionResult:
    digest = backend_digest or hashlib.sha256(f"unavailable:{backend.value}".encode()).hexdigest()
    return ContainmentExecutionResult(
        exit_code=None,
        stdout="",
        stderr=failure.value,
        timed_out=False,
        attestation=_failed_attestation(request, backend, digest, failure),
    )


def _profile_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _bounded_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")[:_OUTPUT_LIMIT]
    return str(value)[:_OUTPUT_LIMIT]


def _read_bounded(path: Path) -> str:
    with path.open("rb") as stream:
        return stream.read(_OUTPUT_LIMIT).decode("utf-8", errors="replace")


__all__ = (
    "ContainmentExecutionResult",
    "execute_contained",
    "file_sha256",
)

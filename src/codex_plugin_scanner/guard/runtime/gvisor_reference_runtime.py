"""Pinned gVisor ``runsc`` reference runtime for Guard-owned OCI bundles.

The runner does not inspect or activate workspace content. It accepts only bundles
materialized below a Guard-owned root, verifies the configured runtime binary by
digest before every attempt, disables networking, bounds captured output, and
forces container deletion on every terminal path.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, final

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import framed_digest
from codex_plugin_scanner.guard.runtime.isolation_provider import ProviderPlanError

_CONTAINER_ID: Final = re.compile(r"\Aguard-[a-z0-9][a-z0-9-]{0,62}\Z")
_MAX_CAPTURE_BYTES: Final = 1_048_576


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _limit_output_files() -> None:
    """Hard-limit each inherited output file before executing runsc."""
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_CAPTURE_BYTES, _MAX_CAPTURE_BYTES))


@dataclass(frozen=True, slots=True)
class GVisorRunResult:
    """Privacy-preserving terminal result from one fenced runsc attempt."""

    execution_instance: str
    exit_code: int
    stdout_digest: str
    stderr_digest: str
    stdout_bytes: int
    stderr_bytes: int
    duration_milliseconds: int
    timed_out: bool
    cleanup_complete: bool


@final
class GVisorReferenceRuntime:
    """Execute pre-materialized, Guard-owned OCI bundles with pinned runsc."""

    def __init__(
        self,
        *,
        runsc_path: str,
        runsc_digest: str,
        bundle_root: str,
        state_root: str,
        platform: str = "systrap",
    ) -> None:
        self._runsc_path = self._validate_owned_absolute_path(runsc_path, "runsc_path")
        self._bundle_root = self._validate_owned_absolute_path(bundle_root, "bundle_root")
        self._state_root = self._validate_owned_absolute_path(state_root, "state_root")
        if len(runsc_digest) != 64 or not all(char in "0123456789abcdef" for char in runsc_digest):
            raise ValueError("runsc_digest must be 64 lowercase hexadecimal characters")
        if platform not in {"systrap", "kvm"}:
            raise ValueError("platform must be systrap or kvm")
        self._runsc_digest = runsc_digest
        self._platform = platform

    @staticmethod
    def _validate_owned_absolute_path(raw: str, label: str) -> Path:
        path = Path(raw)
        if not path.is_absolute():
            raise ValueError(f"{label} must be absolute")
        resolved = path.resolve(strict=False)
        if not (
            resolved.is_relative_to("/usr/libexec/hol-guard")
            or resolved.is_relative_to("/var/lib/hol-guard")
            or resolved.is_relative_to("/tmp/hol-guard-test")
            or resolved.is_relative_to("/private/tmp/hol-guard-test")
        ):
            raise ValueError(f"{label} must be below a Guard-owned root")
        return resolved

    def verify_binary(self) -> str:
        """Verify the exact runsc executable bytes configured by the administrator."""
        try:
            observed = _sha256_file(self._runsc_path)
        except OSError as exc:
            raise ProviderPlanError("configured runsc binary is unavailable") from exc
        if observed != self._runsc_digest:
            raise ProviderPlanError("configured runsc binary digest mismatch")
        mode = self._runsc_path.stat().st_mode
        if not os.access(self._runsc_path, os.X_OK) or mode & 0o005 != 0o005:
            raise ProviderPlanError("configured runsc binary is not executable by its sandbox process")
        if mode & 0o022:
            raise ProviderPlanError("configured runsc binary is writable outside its owner")
        return observed

    def _bundle_path(self, bundle_name: str) -> Path:
        if not _CONTAINER_ID.fullmatch(bundle_name):
            raise ProviderPlanError("invalid Guard execution instance")
        try:
            candidate = (self._bundle_root / bundle_name).resolve(strict=True)
        except OSError as exc:
            raise ProviderPlanError("bundle has no OCI config.json") from exc
        if not candidate.is_relative_to(self._bundle_root):
            raise ProviderPlanError("bundle escapes the Guard-owned root")
        if not (candidate / "config.json").is_file():
            raise ProviderPlanError("bundle has no OCI config.json")
        return candidate

    def _base_command(self) -> tuple[str, ...]:
        return (
            str(self._runsc_path),
            "--root",
            str(self._state_root),
            "--network",
            "none",
            "--platform",
            self._platform,
        )

    def run(self, execution_instance: str, *, timeout_seconds: int = 30) -> GVisorRunResult:
        """Run one bundle and always force-delete its runtime state afterward."""
        if timeout_seconds < 1 or timeout_seconds > 300:
            raise ValueError("timeout_seconds must be between 1 and 300")
        _ = self.verify_binary()
        bundle = self._bundle_path(execution_instance)
        self._state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        command = (
            *self._base_command(),
            "run",
            "--bundle",
            str(bundle),
            execution_instance,
        )
        started = time.monotonic_ns()
        timed_out = False
        stdout = b""
        stderr = b""
        exit_code = 125
        cleanup_complete = False
        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                try:
                    completed = subprocess.run(
                        command,
                        check=False,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        timeout=timeout_seconds,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                        preexec_fn=_limit_output_files,
                    )
                    exit_code = completed.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    exit_code = 124
                _ = stdout_file.seek(0)
                _ = stderr_file.seek(0)
                stdout = stdout_file.read(_MAX_CAPTURE_BYTES)
                stderr = stderr_file.read(_MAX_CAPTURE_BYTES)
        finally:
            try:
                cleanup = subprocess.run(
                    (*self._base_command(), "delete", "--force", execution_instance),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                )
                cleanup_complete = cleanup.returncode in {0, 128}
            except subprocess.TimeoutExpired:
                cleanup_complete = False

        duration_ms = (time.monotonic_ns() - started) // 1_000_000
        return GVisorRunResult(
            execution_instance=execution_instance,
            exit_code=exit_code,
            stdout_digest=framed_digest("guard.runsc-stdout.v1", {"bytes": stdout.hex()}),
            stderr_digest=framed_digest("guard.runsc-stderr.v1", {"bytes": stderr.hex()}),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            duration_milliseconds=duration_ms,
            timed_out=timed_out,
            cleanup_complete=cleanup_complete,
        )

    def cancel(self, execution_instance: str) -> bool:
        """Idempotently signal and delete one Guard-owned execution instance."""
        if not _CONTAINER_ID.fullmatch(execution_instance):
            raise ProviderPlanError("invalid Guard execution instance")
        _ = self.verify_binary()
        try:
            kill = subprocess.run(
                (*self._base_command(), "kill", execution_instance, "KILL"),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except subprocess.TimeoutExpired:
            kill = None
        try:
            delete = subprocess.run(
                (*self._base_command(), "delete", "--force", execution_instance),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except subprocess.TimeoutExpired:
            delete = None
        return kill is not None and delete is not None and kill.returncode in {0, 128} and delete.returncode in {0, 128}


__all__ = ["GVisorReferenceRuntime", "GVisorRunResult"]

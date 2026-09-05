"""Attest the isolated Guard CLI command embedded in managed hooks."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from ...version import __version__
from ..stable_guard_cli import resolve_frozen_guard_cli
from .base import HarnessContext
from .hook_python import (
    HookPythonAttestation,
    HookPythonExecutableIdentity,
    HookPythonFileMetadata,
    _executable_identity,
    attest_guard_hook_python,
)


@dataclass(frozen=True, slots=True)
class GuardCliAttestation:
    """One isolated CLI command bound to the active Guard distribution."""

    command: tuple[str, ...]
    python: HookPythonAttestation | None
    frozen_identity: HookPythonExecutableIdentity | None = None

    @property
    def frozen(self) -> bool:
        return self.frozen_identity is not None

    def manifest_payload(self) -> dict[str, object]:
        """Return the complete identity persisted by managed harnesses."""

        identity = self.frozen_identity or (self.python.identity if self.python is not None else None)
        if identity is None:
            raise RuntimeError("guard_cli_identity_unavailable")
        if self.python is None:
            return {
                "schema": 1,
                "runtime": "frozen-core",
                "command": list(self.command),
                "entry_point": "hol-guard",
                "guard_version": __version__,
                "package_file": None,
                "package_root": None,
                "hol_distribution_root": None,
                "interpreter": _executable_identity_payload(identity),
            }
        return {
            "schema": 1,
            "command": list(self.command),
            "entry_point": self.python.entry_point,
            "guard_version": self.python.version,
            "package_file": str(self.python.package_file),
            "package_root": str(self.python.package_root),
            "hol_distribution_root": (
                str(self.python.hol_distribution_root) if self.python.hol_distribution_root is not None else None
            ),
            "interpreter": _executable_identity_payload(identity),
        }


def _executable_identity_payload(identity: HookPythonExecutableIdentity) -> dict[str, object]:
    return {
        "invocation_path": str(identity.invocation_path),
        "invocation_type": identity.invocation_type,
        "invocation_link_target": identity.invocation_link_target,
        "invocation_stat": _file_metadata_payload(identity.invocation_stat),
        "target_path": str(identity.target_path),
        "target_stat": _file_metadata_payload(identity.target_stat),
        "target_sha256": identity.target_sha256,
    }


def _file_metadata_payload(value: HookPythonFileMetadata) -> dict[str, int]:
    return {
        "device": value.device,
        "inode": value.inode,
        "mode": value.mode,
        "size": value.size,
        "mtime_ns": value.mtime_ns,
    }


def _frozen_guard_cli_attestation() -> GuardCliAttestation:
    launcher = Path(resolve_frozen_guard_cli()).expanduser().absolute()
    identity = _executable_identity(launcher)
    return GuardCliAttestation(
        command=(str(identity.invocation_path),),
        python=None,
        frozen_identity=identity,
    )


def resolve_attested_guard_cli(context: HarnessContext) -> GuardCliAttestation:
    """Resolve Guard's CLI without consulting PATH or the caller's import cwd."""

    if bool(getattr(sys, "frozen", False)):
        return _frozen_guard_cli_attestation()
    try:
        python = attest_guard_hook_python(context)
    except RuntimeError as error:
        message = (
            "Guard could not attest its CLI runtime. Reinstall hol-guard with pipx or uv, "
            "then re-run the harness installation."
        )
        raise RuntimeError(message) from error
    command = (
        str(python.executable),
        "-I",
        "-s",
        "-m",
        "codex_plugin_scanner.cli",
    )
    return GuardCliAttestation(command=command, python=python)


def guard_hook_command(attestation: GuardCliAttestation, *, harness: str) -> list[str]:
    """Return the canonical Guard hook command for either packaged runtime."""

    prefix = [*attestation.command]
    if not attestation.frozen:
        prefix.append("guard")
    return [*prefix, "hook", "--harness", harness, "--json"]


__all__ = ["GuardCliAttestation", "guard_hook_command", "resolve_attested_guard_cli"]

"""Attest the isolated Guard CLI command embedded in managed hooks."""

from __future__ import annotations

from dataclasses import dataclass

from .base import HarnessContext
from .hook_python import HookPythonAttestation, HookPythonFileMetadata, attest_guard_hook_python


@dataclass(frozen=True, slots=True)
class GuardCliAttestation:
    """One isolated CLI command bound to the active Guard distribution."""

    command: tuple[str, ...]
    python: HookPythonAttestation

    def manifest_payload(self) -> dict[str, object]:
        """Return the complete identity persisted by managed harnesses."""

        identity = self.python.identity
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
            "interpreter": {
                "invocation_path": str(identity.invocation_path),
                "invocation_type": identity.invocation_type,
                "invocation_link_target": identity.invocation_link_target,
                "invocation_stat": _file_metadata_payload(identity.invocation_stat),
                "target_path": str(identity.target_path),
                "target_stat": _file_metadata_payload(identity.target_stat),
                "target_sha256": identity.target_sha256,
            },
        }


def _file_metadata_payload(value: HookPythonFileMetadata) -> dict[str, int]:
    return {
        "device": value.device,
        "inode": value.inode,
        "mode": value.mode,
        "size": value.size,
        "mtime_ns": value.mtime_ns,
    }


def resolve_attested_guard_cli(context: HarnessContext) -> GuardCliAttestation:
    """Resolve Guard's CLI without consulting PATH or the caller's import cwd."""

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


__all__ = ["GuardCliAttestation", "resolve_attested_guard_cli"]

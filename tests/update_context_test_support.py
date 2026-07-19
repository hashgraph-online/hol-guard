"""Legacy updater test seam; security behavior is covered in dedicated isolation tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.update_subprocess import InstalledDistribution
from codex_plugin_scanner.guard.shims import _trusted_import_root, _trusted_python_flags


@dataclass(frozen=True, slots=True)
class _Identity:
    canonical_path: Path
    sha256: str = "0" * 64


@dataclass(frozen=True, slots=True)
class _Source:
    public_name: str
    fingerprint: str = "1" * 64


@dataclass(frozen=True, slots=True)
class _Distribution:
    version: str
    direct_url: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class _Result:
    returncode: int
    stdout: str
    stderr: str
    output_limited: bool = False


@dataclass(frozen=True, slots=True)
class LegacyWheelArtifact:
    staged_path: Path
    version: str
    sha256: str = "2" * 64

    def revalidate(self) -> None:
        return None

    def cleanup(self) -> None:
        return None


@dataclass(frozen=True, slots=True)
class LegacyUpdateContext:
    python: _Identity
    installer: _Identity | None
    installer_kind: str
    source: _Source
    neutral_cwd: Path
    environment: Mapping[str, str]
    installer_interpreters: tuple[_Identity, ...] = ()

    def build_installer_command(self, display_command: list[str]) -> list[str]:
        return list(display_command)

    def python_command(self, script: str, *args: str) -> list[str]:
        return [sys.executable, *_trusted_python_flags(), "-c", script, *args]

    def run(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
        output_limit_bytes: int | None = None,
        allow_windows_job_breakaway: bool = False,
    ) -> _Result:
        del output_limit_bytes, allow_windows_job_breakaway
        if update_commands._HARNESS_REPAIR_SCRIPT in command:
            from codex_plugin_scanner.guard.adapters.base import HarnessContext
            from codex_plugin_scanner.guard.store import GuardStore

            assert input_text is not None
            payload = json.loads(input_text)
            workspace_value = payload.get("workspace_dir")
            repair_context = HarnessContext(
                home_dir=Path(payload["home_dir"]),
                workspace_dir=Path(workspace_value) if isinstance(workspace_value, str) else None,
                guard_home=Path(payload["guard_home"]),
            )
            managed_installs, notes = update_commands._repair_supported_harnesses_in_process(
                context=repair_context,
                store=GuardStore(repair_context.guard_home),
                workspace=workspace_value,
                now=str(payload["now"]),
                dry_run=False,
            )
            return _Result(
                returncode=0,
                stdout=json.dumps({"managed_installs": managed_installs, "notes": notes}, sort_keys=True),
                stderr="",
            )
        kwargs: dict[str, object] = {
            "capture_output": True,
            "check": False,
            "text": True,
        }
        if input_text is not None:
            kwargs["input"] = input_text
            kwargs["cwd"] = str(_trusted_import_root())
            refresh_env = dict(os.environ)
            refresh_env.pop("PYTHONPATH", None)
            kwargs["env"] = refresh_env
        if timeout_seconds is not None:
            kwargs["timeout"] = timeout_seconds
        result = subprocess.run(command, **kwargs)
        return _Result(
            returncode=result.returncode,
            stdout=str(result.stdout or ""),
            stderr=str(result.stderr or ""),
        )

    def query_distribution(self) -> _Distribution:
        return _Distribution(
            version=update_commands._current_version(),
            direct_url=update_commands._direct_url_payload(),
        )


def build_legacy_update_context(**kwargs: object) -> LegacyUpdateContext:
    installer_kind = str(kwargs.get("installer_kind") or "pip")
    guard_home_value = kwargs.get("guard_home")
    guard_home = Path(guard_home_value) if isinstance(guard_home_value, (str, Path)) else Path.cwd()
    python = _Identity(Path(sys.executable))
    installer = None if installer_kind == "pip" else _Identity(Path(installer_kind))
    source_kind = str(kwargs.get("source_kind") or "pypi")
    return LegacyUpdateContext(
        python=python,
        installer=installer,
        installer_kind=installer_kind,
        source=_Source(source_kind),
        neutral_cwd=guard_home / "update-runtime",
        environment=MappingProxyType({}),
    )


def stage_legacy_wheel(source: Path, **_kwargs: object) -> LegacyWheelArtifact:
    parts = source.name.removesuffix(".whl").split("-")
    version = parts[1] if len(parts) >= 2 else "unknown"
    return LegacyWheelArtifact(staged_path=source, version=version)


def build_legacy_status_distribution(**_kwargs: object) -> InstalledDistribution:
    return InstalledDistribution(
        name="hol-guard",
        version=update_commands._current_version(),
        root=Path(sys.prefix).resolve(),
        direct_url=update_commands._direct_url_payload(),
    )


__all__ = ["build_legacy_status_distribution", "build_legacy_update_context", "stage_legacy_wheel"]

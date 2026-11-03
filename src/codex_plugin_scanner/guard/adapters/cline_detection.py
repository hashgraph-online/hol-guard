"""Cline host discovery: the CLI lookup here, the editor installs and settings natively."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..aibom_detection import native_adapter_detection_with_warnings
from ..models import GuardArtifact
from .base import HarnessContext, _resolve_command, _run_command_probe, detection_request

_VERSION_PATTERN = re.compile(r"(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)")


@dataclass(frozen=True, slots=True)
class ClineHostDetection:
    cli_executable: str | None
    cli_version: str | None
    vscode_versions: tuple[str, ...]
    jetbrains_paths: tuple[str, ...]

    @property
    def hosts(self) -> tuple[str, ...]:
        hosts: list[str] = []
        if self.cli_executable:
            hosts.append("cli")
        if self.vscode_versions:
            hosts.append("vscode")
        if self.jetbrains_paths:
            hosts.append("jetbrains")
        return tuple(hosts)


def resolve_cline_cli(context: HarnessContext) -> tuple[str | None, str | None]:
    """The Cline CLI executable and its probed version; neither reads the editor installs."""

    executable = _resolve_command(
        "cline",
        (
            context.home_dir / ".local" / "bin" / "cline",
            context.home_dir / ".bun" / "bin" / "cline",
            context.home_dir / ".npm-global" / "bin" / "cline",
        ),
    )
    version: str | None = None
    if executable:
        probe = _run_command_probe([executable, "--version"], timeout_seconds=3)
        text = f"{probe.get('stdout', '')}\n{probe.get('stderr', '')}"
        match = _VERSION_PATTERN.search(text)
        if match:
            version = match.group("version")
    return executable, version


def native_cline_inventory(
    context: HarnessContext, settings: Iterable[Path]
) -> tuple[tuple[GuardArtifact, ...], tuple[str, ...], tuple[str, ...]]:
    """The VS Code and JetBrains hosts, the MCP servers of ``settings`` and the hook and plugin
    directories, as artifacts, found paths and warnings."""

    request = {**detection_request("cline", context), "mcp_settings": [str(path) for path in settings]}
    return native_adapter_detection_with_warnings("cline_detect", request)


def cline_hosts(executable: str | None, version: str | None, artifacts: Iterable[GuardArtifact]) -> ClineHostDetection:
    """The hosts the native inventory named, with the CLI Python resolved."""

    hosts = [artifact for artifact in artifacts if artifact.artifact_type == "harness_host"]
    return ClineHostDetection(
        cli_executable=executable,
        cli_version=version,
        vscode_versions=tuple(str(host.metadata["version"]) for host in hosts if host.metadata["surface"] == "vscode"),
        jetbrains_paths=tuple(host.config_path for host in hosts if host.metadata["surface"] == "jetbrains"),
    )


def detect_cline_hosts(context: HarnessContext) -> ClineHostDetection:
    executable, version = resolve_cline_cli(context)
    artifacts, _found_paths, _warnings = native_cline_inventory(context, ())
    return cline_hosts(executable, version, artifacts)


__all__ = [
    "ClineHostDetection",
    "cline_hosts",
    "detect_cline_hosts",
    "native_cline_inventory",
    "resolve_cline_cli",
]

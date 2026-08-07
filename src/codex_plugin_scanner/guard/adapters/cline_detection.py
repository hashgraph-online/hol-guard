"""Side-effect-free Cline host and version discovery."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .base import HarnessContext, _resolve_command, _run_command_probe

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


def _package_version(path: Path) -> str | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    version = payload.get("version") if isinstance(payload, dict) else None
    return version.strip() if isinstance(version, str) and version.strip() else None


def _vscode_extension_versions(home_dir: Path) -> tuple[str, ...]:
    versions: list[str] = []
    roots = (
        home_dir / ".vscode" / "extensions",
        home_dir / ".vscode-insiders" / "extensions",
        home_dir / ".cursor" / "extensions",
    )
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in sorted(root.glob("saoudrizwan.claude-dev-*")):
            version = _package_version(candidate / "package.json")
            if version:
                versions.append(version)
    return tuple(dict.fromkeys(versions))


def _jetbrains_paths(home_dir: Path) -> tuple[str, ...]:
    candidates: list[Path] = []
    roots = (
        home_dir / ".local" / "share" / "JetBrains",
        home_dir / "Library" / "Application Support" / "JetBrains",
        home_dir / ".config" / "JetBrains",
    )
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.glob("*/plugins/*"):
            if "cline" in path.name.lower() and path.exists():
                candidates.append(path)
    return tuple(str(path) for path in candidates)


def detect_cline_hosts(context: HarnessContext) -> ClineHostDetection:
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
    return ClineHostDetection(
        cli_executable=executable,
        cli_version=version,
        vscode_versions=_vscode_extension_versions(context.home_dir),
        jetbrains_paths=_jetbrains_paths(context.home_dir),
    )


__all__ = ["ClineHostDetection", "detect_cline_hosts"]

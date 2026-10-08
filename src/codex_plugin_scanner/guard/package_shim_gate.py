"""Guard/no-guard routing for generated package-manager shims."""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import Path

_PACKAGE_SHIM_PARSER_MANAGERS = frozenset(
    {
        "brew",
        "bun",
        "bunx",
        "bundle",
        "cargo",
        "composer",
        "go",
        "gradle",
        "mvn",
        "npm",
        "npx",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "pnpm",
        "poetry",
        "uv",
        "uvx",
        "yarn",
    }
)


def package_shim_command_requires_guard(
    manager: str,
    argv: Sequence[str],
    *,
    workspace: Path | None = None,
    guard_home: Path | None = None,
) -> bool:
    """Return whether a shimmed package-manager command should enter Guard protect."""

    normalized_manager = manager.strip().lower()
    if not normalized_manager:
        return False
    if normalized_manager not in _PACKAGE_SHIM_PARSER_MANAGERS:
        return True
    normalized_argv = tuple(str(argument) for argument in argv)
    if normalized_manager == "bun":
        return normalized_argv not in {
            ("--help",),
            ("--version",),
            ("-v",),
            ("help",),
        }
    command = [normalized_manager, *normalized_argv]
    intent = _parse_shim_package_intent(shlex.join(command), workspace=workspace, guard_home=guard_home)
    return intent is not None


def package_shim_command_requires_external_archive_binding(
    manager: str,
    argv: Sequence[str],
    *,
    workspace: Path | None = None,
    guard_home: Path | None = None,
) -> bool:
    """Return whether Guard itself must launch a digest-bound archive command."""

    normalized_manager = manager.strip().lower()
    if normalized_manager not in _PACKAGE_SHIM_PARSER_MANAGERS:
        return False
    command = [normalized_manager, *[str(argument) for argument in argv]]
    from codex_plugin_scanner.guard.runtime.restricted_archive_download import is_external_https_archive_source

    intent = _parse_shim_package_intent(shlex.join(command), workspace=workspace, guard_home=guard_home)
    return bool(
        intent is not None
        and any(
            target.ecosystem in {"npm", "pypi"}
            and target.source_url is not None
            and is_external_https_archive_source(target.source_url)
            for target in intent.targets
        )
    )


def _parse_shim_package_intent(raw_command: str, *, workspace: Path | None = None, guard_home: Path | None = None):
    """Route shim package-intent parsing through the resident native authority.

    ``parse_package_intent`` is resident-sole-authority, so this helper only
    binds the selected guard home and returns its result.
    """
    from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent

    return parse_package_intent(raw_command, workspace=workspace, guard_home=guard_home)

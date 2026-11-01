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
        # Bun runs files and scripts, so the install parser's "no intent" is
        # not a pass. Help and version still print and exit. Install help is
        # the same exit: `bun add --help` never installs.
        return normalized_argv not in {
            ("--help",),
            ("--version",),
            ("-v",),
            ("help",),
            ("add", "--help"),
            ("add", "-h"),
            ("install", "--help"),
            ("install", "-h"),
            ("i", "--help"),
            ("i", "-h"),
        }
    command = [normalized_manager, *normalized_argv]
    intent = _parse_shim_package_intent(shlex.join(command), workspace=workspace, guard_home=guard_home)
    return intent is not None


def package_shim_command_is_routine_local_runner(
    manager: str,
    argv: Sequence[str],
    *,
    workspace: Path | None = None,
    guard_home: Path | None = None,
) -> bool:
    """Return whether the command runs a runner this project already pins locally.

    The native parser reaches that verdict from the manifest, the installed
    package's own manifest and every lockfile: the runner is the lint, test or
    TypeScript entry point this project declared, resolved under this
    workspace's ``node_modules``. Nothing is fetched, so the shim has no
    install to ask about. It is not a reason to skip contained execution, so
    the shim consults this only once containment has declined the command.
    """

    normalized_manager = manager.strip().lower()
    if normalized_manager not in {"bunx", "npx"}:
        return False
    command = [normalized_manager, *[str(argument) for argument in argv]]
    intent = _parse_shim_package_intent(shlex.join(command), workspace=workspace, guard_home=guard_home)
    return bool(intent is not None and intent.routine_local_runner)


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

"""Identify user scripts sourced or launched inside compound shell commands."""

from __future__ import annotations

import shlex
from pathlib import Path

from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .command_model import CommandSegment, parse_shell_command
from .command_tokens import executable_name
from .local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli

_SOURCE_BUILTINS = frozenset({".", "source"})
_INLINE_FLAGS = frozenset({"-c", "-lc"})
_SHELL_INTERPRETERS = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})
_SHELL_SCRIPT_SUFFIXES = frozenset({".bash", ".ksh", ".rc", ".sh", ".zsh"})


def identify_unlisted_cli_identities(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> tuple[UnlistedCliIdentity, ...]:
    """Return unlisted CLI identities from a single invocation or compound shell."""

    found: dict[str, UnlistedCliIdentity] = {}

    def add(identity: UnlistedCliIdentity | None) -> None:
        if identity is None:
            return
        found.setdefault(identity.cli_id, identity)

    add(identify_unlisted_cli(command_text, cwd=cwd, home_dir=home_dir, registry=registry))
    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return tuple(found.values())
    relative_ok = True
    for segment in model.segments:
        if executable_name(segment.executable) == "cd":
            relative_ok = False
        add(
            _identity_from_segment(
                segment,
                cwd=cwd,
                home_dir=home_dir,
                registry=registry,
                allow_relative=relative_ok,
            )
        )
    return tuple(found.values())


def _identity_from_segment(
    segment: CommandSegment,
    *,
    cwd: Path,
    home_dir: Path | None,
    registry: CommandSafetyExtensionRegistry,
    allow_relative: bool,
) -> UnlistedCliIdentity | None:
    if segment.path_overridden or segment.wrapper_chain:
        return None
    exe = executable_name(segment.executable)
    if exe is None:
        return None
    if exe in _SOURCE_BUILTINS and segment.arguments:
        script = _resolve_existing_file(
            segment.arguments[0],
            cwd=cwd,
            home_dir=home_dir,
            allow_relative=allow_relative,
        )
        if script is None:
            return None
        return identify_unlisted_cli(
            f"bash {shlex.quote(str(script))}",
            cwd=cwd,
            home_dir=home_dir,
            registry=registry,
        )
    if exe in _SHELL_INTERPRETERS:
        if any(argument in _INLINE_FLAGS for argument in segment.arguments):
            return None
        for argument in segment.arguments:
            if argument.startswith("-"):
                continue
            script = _resolve_existing_file(
                argument,
                cwd=cwd,
                home_dir=home_dir,
                allow_relative=allow_relative,
            )
            if script is None or script.suffix.lower() not in _SHELL_SCRIPT_SUFFIXES:
                return None
            return identify_unlisted_cli(
                f"{exe} {shlex.quote(str(script))}",
                cwd=cwd,
                home_dir=home_dir,
                registry=registry,
            )
    if segment.executable is None:
        return None
    script = _resolve_existing_file(
        segment.executable,
        cwd=cwd,
        home_dir=home_dir,
        allow_relative=allow_relative,
    )
    if script is None:
        return None
    return identify_unlisted_cli(shlex.quote(str(script)), cwd=cwd, home_dir=home_dir, registry=registry)


def _resolve_existing_file(
    value: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    allow_relative: bool,
) -> Path | None:
    expanded = value.strip()
    if not expanded:
        return None
    try:
        home = (home_dir or Path.home()).expanduser()
        if expanded.startswith("~/"):
            expanded = str(home / expanded[2:])
        path = Path(expanded)
        if not path.is_absolute():
            if not allow_relative:
                return None
            path = cwd / path
        resolved = path.expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    return resolved

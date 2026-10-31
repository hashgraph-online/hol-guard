"""Python command-id resolution for a custom extension invocation, kept for tests.

The resident owns this in Rust (``hook_direct_local_cli_block.rs`` and
``local_cli_hook_op.rs``); these tests keep the composed Python answer that
recorded its parity vectors.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from codex_plugin_scanner.guard.native_local_cli_identity import (
    record_local_cli_identity_failure,
    track_local_cli_identity_failures,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    _COMMAND_NAME,
    _MAX_DEPTH,
    OTHER_COMMAND_ID,
    ROOT_COMMAND_ID,
    LocalCliCommand,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.package_json_scripts import _native_package_scripts

# Only these options may precede a runner target. Package selectors such as
# ``--package``/``-p`` or ``--call``/``-c`` make the runner execute something
# other than the named bin, so any other pre-target option is not unwrapped.
_PRETARGET_OPTIONS = frozenset({"-y", "--yes"})
_EXEC_SUBCOMMANDS = frozenset({"exec", "x"})
_EXEC_SUBCOMMAND_RUNNERS = frozenset({"npm", "pnpm", "yarn"})


def _runner_inner_arguments(runner: str, arguments: list[str] | tuple[str, ...]) -> list[str] | None:
    """Return the arguments passed through to the runner's target CLI."""

    exec_subcommand_allowed = runner in _EXEC_SUBCOMMAND_RUNNERS
    for index, argument in enumerate(arguments):
        if argument == "--" or argument in _PRETARGET_OPTIONS:
            continue
        if argument.startswith("-"):
            return None
        if exec_subcommand_allowed and argument in _EXEC_SUBCOMMANDS:
            exec_subcommand_allowed = False
            continue
        return list(arguments[index + 1 :])
    return None


class LocalCliIdentityUnavailableError(RuntimeError):
    """The resident could not derive an identity the command may need."""


def package_script_command_tokens(command_text: str, *, cwd: Path, home_dir: Path | None) -> tuple[str, ...] | None:
    """Return colon-nested tokens for one package script name.

    ``None`` means the command is not a package script. A failed or malformed
    native answer raises ``LocalCliIdentityUnavailableError`` instead, so a
    grant decision is never made against generic argv tokens.
    """

    with track_local_cli_identity_failures() as failures:
        found = _native_package_scripts(command_text, cwd=cwd, home_dir=home_dir or cwd)
    if failures:
        record_local_cli_identity_failure(failures[0])
        raise LocalCliIdentityUnavailableError(failures[0])
    return None if found is None else found.command_tokens


def command_tokens_for_invocation(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    identity: UnlistedCliIdentity,
) -> tuple[str, ...]:
    package_tokens = package_script_command_tokens(command_text, cwd=cwd, home_dir=home_dir)
    if package_tokens is not None:
        return package_tokens
    model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    if not model.segments:
        return ()
    arguments = list(model.segments[0].arguments)
    if identity.runner is not None:
        split = _runner_inner_arguments(identity.runner, arguments)
        if split is None:
            return ()
        arguments = split
    elif identity.kind == "script" and arguments:
        first_name = Path(arguments[0]).name
        if first_name == identity.name:
            arguments = arguments[1:]
    tokens: list[str] = []
    for argument in arguments:
        if argument.startswith("-") or not _COMMAND_NAME.fullmatch(argument):
            break
        tokens.append(argument)
        if len(tokens) >= _MAX_DEPTH:
            break
    return tuple(tokens)


def match_command_id(
    tokens: Sequence[str],
    commands: Sequence[LocalCliCommand],
) -> str:
    if not tokens:
        return ROOT_COMMAND_ID
    known = {command.command_id for command in commands}
    for length in range(min(len(tokens), _MAX_DEPTH), 0, -1):
        candidate = ".".join(tokens[:length])
        if candidate in known:
            return candidate
    return OTHER_COMMAND_ID


def resolve_command_id_for_text(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    identity: UnlistedCliIdentity,
    commands: Sequence[LocalCliCommand],
) -> str:
    tokens = command_tokens_for_invocation(
        command_text,
        cwd=cwd,
        home_dir=home_dir,
        identity=identity,
    )
    return match_command_id(tokens, commands)

"""Split package-runner invocations such as ``npx wrangler`` into bin and arguments.

The resident's ``local_cli_identify`` kind owns runner unwrapping for grant
identity. These helpers only name the runner's target for display and help
probing.
"""

from __future__ import annotations

from pathlib import Path

LOCAL_BIN_RUNNERS = frozenset({"npx", "bunx", "pnpm", "pnpx", "yarn", "npm"})
# Only these options may precede a runner target. Package selectors such as
# ``--package``/``-p`` or ``--call``/``-c`` make the runner execute something
# other than the named bin, so any other pre-target option is not unwrapped.
RUNNER_PRETARGET_OPTIONS = frozenset({"-y", "--yes"})
RUNNER_EXEC_SUBCOMMANDS = frozenset({"exec", "x"})
_EXEC_SUBCOMMAND_RUNNERS = frozenset({"npm", "pnpm", "yarn"})


def runner_name(executable: str | None) -> str | None:
    if not executable:
        return None
    base = Path(executable.replace("\\", "/")).name.lower()
    if base.endswith((".cmd", ".exe")):
        base = base.rsplit(".", 1)[0]
    return base if base in LOCAL_BIN_RUNNERS else None


def runner_target(runner: str, arguments: list[str] | tuple[str, ...]) -> str | None:
    """Return the bin a runner launches, or ``None`` for any selector form."""

    split = _split_runner_arguments(runner, arguments)
    return split[0] if split is not None else None


def runner_inner_arguments(runner: str, arguments: list[str] | tuple[str, ...]) -> list[str] | None:
    """Return the arguments passed through to the runner's target CLI."""

    split = _split_runner_arguments(runner, arguments)
    return split[1] if split is not None else None


def _split_runner_arguments(
    runner: str,
    arguments: list[str] | tuple[str, ...],
) -> tuple[str, list[str]] | None:
    exec_subcommand_allowed = runner in _EXEC_SUBCOMMAND_RUNNERS
    for index, argument in enumerate(arguments):
        if argument == "--" or argument in RUNNER_PRETARGET_OPTIONS:
            continue
        if argument.startswith("-"):
            return None
        if exec_subcommand_allowed and argument in RUNNER_EXEC_SUBCOMMANDS:
            exec_subcommand_allowed = False
            continue
        return argument, list(arguments[index + 1 :])
    return None


__all__ = [
    "LOCAL_BIN_RUNNERS",
    "runner_inner_arguments",
    "runner_name",
    "runner_target",
]

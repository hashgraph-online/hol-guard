"""Origin-shaped Git fetch recognition for extension ownership."""

from __future__ import annotations

import re
from typing import Final

from .secret_file_request_services.shell_tokenization import _shell_segment_primary_command

_ORIGIN_REFRESH_FLAGS: Final = frozenset({"-q", "--quiet", "--no-tags", "--prune", "-p"})
_ORIGIN_REF: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")
_GIT_GLOBAL_FLAG_OPTIONS: Final = frozenset(
    {
        "--bare",
        "--literal-pathspecs",
        "--no-advice",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "--no-pager",
        "--no-replace-objects",
        "--paginate",
        "-P",
        "-p",
    }
)
_GIT_GLOBAL_VALUE_OPTIONS: Final = frozenset({"-C", "--git-dir", "--namespace", "--super-prefix", "--work-tree"})
_GIT_EXECUTION_VALUE_OPTIONS: Final = frozenset({"-c", "--config-env", "--exec-path"})


def origin_shaped_git_fetch_args(args: tuple[str, ...]) -> bool:
    """Return whether fetch operands are a named-origin refresh, not a URL or --all."""

    if not args or len(args) > 16:
        return False
    remote: str | None = None
    refs: list[str] = []
    for arg in args:
        if arg in _ORIGIN_REFRESH_FLAGS:
            continue
        if arg.startswith("-") or (remote is None and arg != "origin"):
            return False
        if remote is None:
            remote = arg
            continue
        if _ORIGIN_REF.fullmatch(arg) is None:
            return False
        refs.append(arg)
    return remote == "origin" and len(refs) <= 12


def git_fetch_operands(tokens: tuple[str, ...]) -> tuple[str, ...] | None:
    """Return arguments after a git fetch subcommand, if the segment is a fetch."""

    command_name, command_index = _shell_segment_primary_command(list(tokens))
    if command_name != "git" or command_index is None:
        return None
    args = tokens[command_index + 1 :]
    index = 0
    while index < len(args):
        token = args[index]
        option_name = token.partition("=")[0]
        if token in _GIT_GLOBAL_FLAG_OPTIONS:
            index += 1
            continue
        if option_name in _GIT_EXECUTION_VALUE_OPTIONS:
            return None
        if option_name in _GIT_GLOBAL_VALUE_OPTIONS:
            if "=" in token:
                if not token.partition("=")[2]:
                    return None
                index += 1
                continue
            if index + 1 >= len(args):
                return None
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if token != "fetch":
            return None
        return args[index + 1 :]
    return None


def command_is_origin_shaped_git_fetch(segments: tuple[tuple[str, ...], ...]) -> bool:
    """Return whether every fetch segment is a named-origin refresh."""

    saw_fetch = False
    for tokens in segments:
        operands = git_fetch_operands(tokens)
        if operands is None:
            continue
        saw_fetch = True
        if not origin_shaped_git_fetch_args(operands):
            return False
    return saw_fetch

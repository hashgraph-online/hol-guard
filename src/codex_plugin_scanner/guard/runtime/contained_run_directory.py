"""The directory an Oh My Pi `bash` call asks to run in.

Oh My Pi's `bash` tool takes an optional `cwd` argument and runs the command
there. Native authority resolves it the same way the host does before judging
the command, so the contained run must start in that directory too. The sink
turns the argument into the explicit `cd '<directory>' && <command>` form,
which the wrapper peel already resolves, rebases onto a sibling repository
and authorizes again.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from .restricted_pytest import RestrictedPytestError

_OTHER_INPUT_KEYS = ("toolInput", "arguments")


def _reject() -> RestrictedPytestError:
    return RestrictedPytestError(
        "contained_run_authorization_failed", "Guard could not resolve the directory this command runs in."
    )


def requested_directory(value: object, *, workspace: Path, home: Path | None) -> Path | None:
    """The canonical directory `value` names, or None for the session directory.

    An empty value or a root of only slashes keeps the session directory, as
    on the host. `~` and `~/x` expand to home and any other text is joined to
    the session directory. Forms the host rewrites before resolving (`@` and
    `:` prefixes, `file:` and other URLs, non-ASCII text, backslashes) are
    rejected, as native authority sends them to review.
    """
    if not isinstance(value, str):
        raise _reject()
    if not value or set(value) == {"/"}:
        return None
    if (
        not value.isascii()
        or any(character < " " or character in "\x7f\\" for character in value)
        or value.startswith(("@", ":", "file:"))
        or "://" in value
    ):
        raise _reject()
    if value == "~" or value.startswith("~/"):
        if home is None:
            raise _reject()
        path = home / value[1:].lstrip("/")
    elif value.startswith("~"):
        raise _reject()
    else:
        path = workspace / value
    try:
        directory = path.resolve(strict=True)
        root = workspace.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise _reject() from error
    if not directory.is_dir():
        raise _reject()
    return None if directory == root else directory


def _split_directory(
    payload: dict[str, object], *, workspace: Path, home: Path | None
) -> tuple[Path | None, dict[str, object]]:
    tool_input = payload.get("tool_input")
    if (
        not isinstance(tool_input, dict)
        or not isinstance(tool_input.get("command"), str)
        or any(key in payload for key in _OTHER_INPUT_KEYS)
    ):
        raise _reject()
    directory = requested_directory(tool_input.get("cwd"), workspace=workspace, home=home)
    return directory, {key: value for key, value in tool_input.items() if key != "cwd"}


def as_directory_change(payload: dict[str, object], *, workspace: Path, home: Path | None) -> dict[str, object]:
    """`payload` with its `cwd` argument written as a leading `cd`."""
    directory, rest = _split_directory(payload, workspace=workspace, home=home)
    if directory is not None:
        rest["command"] = f"cd {shlex.quote(str(directory))} && {rest['command']}"
    return {**payload, "tool_input": rest}


def as_run_root(payload: dict[str, object], *, workspace: Path, home: Path | None) -> tuple[Path, dict[str, object]]:
    """The directory `payload`'s `cwd` argument names, and the call judged from it.

    Native authority judges an Oh My Pi `bash` call inside its `cwd`
    argument, and may root the workspace sandbox there. The returned payload
    asks the same question with that directory as the session folder, so the
    sandbox root comes from a native verdict rather than from this sink.
    """
    directory, rest = _split_directory(payload, workspace=workspace, home=home)
    root = directory if directory is not None else workspace.resolve(strict=True)
    return root, {**payload, "cwd": str(root), "tool_input": rest}

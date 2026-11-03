"""The files Guard reads, but never runs, to learn what a script takes.

A script's own source says what it takes and whether it answers --help
before anything runs it. The native ``local_cli_script_source`` kind finds
and reads the files: the verified script itself, and the few local modules it
imports from inside its own folder. Without the native runtime nothing is
read and no path is safe to probe, so nothing is run on its word.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .local_cli_identity import UnlistedCliIdentity


def script_source_path(identity: UnlistedCliIdentity, argv: Sequence[str]) -> tuple[str, bool] | None:
    """The script a --help argv would run, and whether it needs a ``#!`` line.

    A script launched through its interpreter has ``argv`` of
    ``(interpreter, script, "--help")``. One run directly has ``(script,
    "--help")`` and counts only when the file starts with a ``#!`` line, so a
    compiled program is never read as text. ``read_script_source`` checks the
    path before it reads anything.
    """

    if identity.kind == "script" and len(argv) == 3:
        return str(argv[1]), False
    if identity.kind == "executable" and len(argv) == 2:
        return str(argv[0]), True
    return None


def read_script_source(path: str, *, shebang_only: bool, guard_home: Path | None = None) -> str | None:
    """The start of a script's text, or None when it is not a readable script."""

    text = _ask("read", guard_home, path=path, shebang_only=shebang_only).get("text")
    return text if isinstance(text, str) else None


def read_local_module(module: str, script: str, *, guard_home: Path | None = None) -> str | None:
    """A module's text, read only when the file opened is the one inside the script's folder."""

    text = _ask("module", guard_home, module=module, script=script).get("text")
    return text if isinstance(text, str) else None


def local_import_paths(script: str, imports: Sequence[str], *, guard_home: Path | None = None) -> tuple[str, ...]:
    """The imported modules worth reading: regular script files inside the script's folder."""

    paths = _ask("imports", guard_home, script=script, imports=[str(entry) for entry in imports]).get("paths")
    if not isinstance(paths, list):
        return ()
    return tuple(path for path in paths if isinstance(path, str))


def safe_probe_path(path_text: str, *, guard_home: Path | None = None) -> bool:
    """Whether ``path_text`` names a regular file Guard may probe."""

    return _ask("probe", guard_home, path=path_text).get("safe") is True


def _ask(op: str, guard_home: Path | None, **fields: Any) -> dict[str, Any]:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("local_cli_script_source", {"op": op, **fields}, guard_home)
    except NativeRunnerAuthorityError:
        return {}

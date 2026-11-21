"""The files Guard reads, but never runs, to learn what a script takes.

A script's own source says what it takes and whether it answers --help
before anything runs it. The native ``local_cli_script_source`` kind finds
and reads the files: the verified script itself, and the few local modules it
imports from inside its own folder, and says whether those files, or the
installed package an entry-point wrapper runs, show an MCP server. Without the
native runtime nothing is read and no path is safe to probe, so nothing is run
on its word: a read the
runtime cannot answer raises ``ScriptSourceUnavailableError`` rather than looking
like a file that is not a script.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any


class ScriptSourceUnavailableError(RuntimeError):
    """The native runtime could not answer a script-source read."""


def read_script_source(path: str, *, shebang_only: bool, guard_home: Path | None = None) -> str | None:
    """The start of a script's text, or None when it is not a readable script.

    Raises ``ScriptSourceUnavailableError`` when the runtime cannot answer.
    """

    text = _ask("read", guard_home, path=path, shebang_only=shebang_only).get("text")
    return text if isinstance(text, str) else None


def script_serves_mcp(script: str, invocation: Sequence[str], *, guard_home: Path | None = None) -> bool:
    """Whether a script's source, a local module it imports, or the installed
    package its entry-point wrapper runs shows an MCP server.

    Raises ``ScriptSourceUnavailableError`` when the runtime cannot answer.
    """

    fields = {"script": script, "invocation": [str(part) for part in invocation]}
    return _ask("mcp_evidence", guard_home, **fields).get("serves") is True


def safe_probe_path(path_text: str, *, guard_home: Path | None = None) -> bool:
    """Whether ``path_text`` names a regular file Guard may probe; never when the runtime cannot answer."""

    try:
        return _ask("probe", guard_home, path=path_text).get("safe") is True
    except ScriptSourceUnavailableError:
        return False


def _ask(op: str, guard_home: Path | None, **fields: Any) -> dict[str, Any]:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("local_cli_script_source", {"op": op, **fields}, guard_home)
    except NativeRunnerAuthorityError as exc:
        raise ScriptSourceUnavailableError("the native runtime could not read the script source") from exc

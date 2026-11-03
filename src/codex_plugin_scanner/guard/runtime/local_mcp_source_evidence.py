"""Whether a pasted script's own source says it is an MCP server.

Recognizing a pasted command as MCP launches it with its real arguments, so a
script that is not a server would do its normal work. For a readable script
the resident reads the source first, without running it, and only a script
that imports an MCP server library or answers ``tools/list`` is launched. For
the wrapper pip or uv writes for an installed command, that evidence must come
from the installed package the wrapper runs. The native
``local_cli_script_source`` kind reads the files and decides.
"""

from __future__ import annotations

from pathlib import Path

from .approval_context import build_runtime_launch_identity
from .command_model import parse_shell_command
from .local_cli_identity import identify_unlisted_cli
from .local_cli_script_source import (
    ScriptSourceUnavailableError,
    read_script_source,
    safe_probe_path,
    script_serves_mcp,
)


def script_may_serve_mcp(command: str, *, cwd: Path, home_dir: Path | None, guard_home: Path) -> bool:
    """Whether Guard may launch ``command`` to ask it for MCP tools.

    True for a compiled program and a project bin run through a package
    launcher. A script is launched only when its source, or a local module it
    imports, shows an MCP server; for an installed command's entry-point
    wrapper, the installed package it runs must show one. A lookup that fails,
    a script whose source cannot be read, or a resident that cannot be asked
    never launches; an older resident that cannot read MCP evidence keeps the
    launch.
    """

    identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return False
    if identity.runner is not None:
        return True
    launched = _launched_script(command, cwd=cwd, home_dir=home_dir, guard_home=guard_home)
    if launched is None:
        return False
    if launched == "":
        return True
    reads_evidence = _resident_reads_mcp_evidence()
    if reads_evidence is None:
        return False
    try:
        if not reads_evidence:
            return read_script_source(launched, shebang_only=False, guard_home=guard_home) is not None
        return script_serves_mcp(launched, (identity.name,), guard_home=guard_home)
    except ScriptSourceUnavailableError:
        return False


def _launched_script(command: str, *, cwd: Path, home_dir: Path | None, guard_home: Path) -> str | None:
    """The script ``command`` runs, ``""`` for a compiled program, or None when unknown.

    The launch identity says which: an interpreter's script argument, a file
    run through its ``#!`` line, or a program that is not a script at all.
    """

    try:
        model = parse_shell_command(command, cwd=cwd, home_dir=home_dir)
        if not model.segments:
            return None
        segment = model.segments[0]
        launch = build_runtime_launch_identity(
            segment.executable, args=segment.arguments, structured_command=True, cwd=cwd, home_dir=home_dir
        )
    except Exception:
        return None
    executable = launch.get("executable")
    entrypoint = launch.get("entrypoint")
    if not isinstance(executable, dict) or not isinstance(entrypoint, dict):
        return None
    kind = entrypoint.get("kind")
    if kind == "direct-executable" and executable.get("shebang_status") == "not_script":
        return ""
    if entrypoint.get("status") != "verified" or not isinstance(kind, str) or not kind.endswith("-script"):
        return None
    path = executable.get("path") if kind == "direct-script" else entrypoint.get("path")
    return path if isinstance(path, str) and safe_probe_path(path, guard_home=guard_home) else None


def _resident_reads_mcp_evidence() -> bool | None:
    from ..native_local_cli_help_parse import resident_reads_mcp_evidence

    try:
        return resident_reads_mcp_evidence()
    except Exception:
        return None

"""Whether a pasted script's own source says it is an MCP server.

Recognizing a pasted command as MCP launches it with its real arguments, so a
script that is not a server would do its normal work. For a readable script
the resident reads the source first, without running it, and only a script
that imports an MCP server library or answers ``tools/list`` is launched.
"""

from __future__ import annotations

from pathlib import Path

from .approval_context import build_runtime_launch_identity
from .command_model import parse_shell_command
from .local_cli_identity import identify_unlisted_cli
from .local_cli_script_source import (
    local_import_paths,
    read_local_module,
    read_script_source,
    safe_probe_path,
)


def script_may_serve_mcp(command: str, *, cwd: Path, home_dir: Path | None, guard_home: Path) -> bool:
    """Whether Guard may launch ``command`` to ask it for MCP tools.

    True for a compiled program and a project bin run through a package
    launcher. A script is launched only when its source, or a local module it
    imports, shows an MCP server. A lookup that fails, a script whose source
    cannot be read, or a resident that cannot be asked never launches; an
    older resident that cannot read MCP evidence keeps the launch.
    """

    identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return False
    if identity.runner is not None:
        return True
    launched = _launched_script(command, cwd=cwd, home_dir=home_dir)
    if launched is None:
        return False
    if launched == "":
        return True
    text = read_script_source(launched, shebang_only=False)
    if text is None:
        return False
    reads_evidence = _resident_reads_mcp_evidence()
    if reads_evidence is None:
        return False
    if not reads_evidence:
        return True
    invocation = (identity.name,)
    read = _source_read(text, invocation, guard_home)
    if read is None:
        return False
    if read.mcp_server:
        return True
    for module in local_import_paths(launched, read.imports):
        module_text = read_local_module(module, launched)
        if module_text is None:
            continue
        imported = _source_read(module_text, invocation, guard_home)
        if imported is not None and imported.mcp_server:
            return True
    return False


def _launched_script(command: str, *, cwd: Path, home_dir: Path | None) -> str | None:
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
    return path if isinstance(path, str) and safe_probe_path(path) else None


def _resident_reads_mcp_evidence() -> bool | None:
    from ..native_local_cli_help_parse import resident_reads_mcp_evidence

    try:
        return resident_reads_mcp_evidence()
    except Exception:
        return None


def _source_read(text: str, invocation: tuple[str, ...], guard_home: Path):
    from ..native_local_cli_help_parse import native_local_cli_source_read

    try:
        return native_local_cli_source_read(guard_home=guard_home, text=text, invocation=invocation, mcp_evidence=True)
    except Exception:
        return None

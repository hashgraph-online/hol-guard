"""Whether a pasted script's own source says it is an MCP server.

Recognizing a pasted command as MCP launches it with its real arguments, so a
script that is not a server would do its normal work. For a readable script
the resident reads the source first, without running it, and only a script
that imports an MCP server library or answers ``tools/list`` is launched.
"""

from __future__ import annotations

from pathlib import Path

from .local_cli_help import help_invocation_for_command
from .local_cli_script_source import (
    local_import_paths,
    read_local_module,
    read_script_source,
    script_source_path,
)


def script_may_serve_mcp(command: str, *, cwd: Path, home_dir: Path | None, guard_home: Path) -> bool:
    """Whether Guard may launch ``command`` to ask it for MCP tools.

    True for what is not a readable script: a compiled program, a package bin
    run through a launcher, or a command Guard cannot place. A script whose
    source cannot be read, or whose resident cannot be asked, is not run.
    An older resident that cannot read MCP evidence keeps the launch.
    """

    resolved = help_invocation_for_command(command, cwd=cwd, home_dir=home_dir)
    if resolved is None:
        return True
    identity, argv = resolved
    source = script_source_path(identity, argv)
    if identity.runner is not None or source is None:
        return True
    script, shebang_only = source
    text = read_script_source(script, shebang_only=shebang_only)
    if text is None:
        # A program run directly without a #! line is compiled, not a script.
        return shebang_only
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
    for module in local_import_paths(script, read.imports):
        module_text = read_local_module(module, script)
        if module_text is None:
            continue
        imported = _source_read(module_text, invocation, guard_home)
        if imported is not None and imported.mcp_server:
            return True
    return False


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

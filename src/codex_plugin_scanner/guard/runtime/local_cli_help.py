"""Find the commands a verified local CLI takes, for custom extension discovery.

``help_invocation_for_command`` matches a command to the CLI the operator
approved and builds the only ``--help`` argv Guard may run for it. Everything
after that is the native ``local-cli-discover`` command
(``rust/crates/guard-runtime/src/local_cli_discover.rs``): it reads a script's
source before anything runs, runs ``--help`` only as far as that source
allows, in a private folder with a fixed ``PATH``, and parses what comes back.
Help text is whatever a third-party program printed, so nothing here parses
it.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from .approval_context import build_runtime_launch_identity
from .command_model import parse_shell_command
from .local_cli_commands import LocalCliCommand, merge_discovered_commands
from .local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from .local_cli_script_source import safe_probe_path as _safe_probe_path

HelpStatus = Literal["ok", "empty", "failed"]

LOCAL_CLI_DISCOVER_COMMAND = "local-cli-discover"
LOCAL_CLI_DISCOVER_FEATURE = "local-cli-discover-v1"
# One top-level --help and up to eight nested ones, 2.5 seconds each, with room
# for the runtime to start and read the script's source.
_TIMEOUT_SECONDS = 45.0
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_FIELDS = ("command_id", "name", "usage", "description")


def help_invocation_for_command(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    guard_home: Path | None = None,
) -> tuple[UnlistedCliIdentity, tuple[str, ...]] | None:
    """Return the verified identity and argv Guard may use for --help."""

    identity = identify_unlisted_cli(command_text, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return None
    if identity.runner is not None:
        # Probe the proven project bin directly; registry fetches are never run.
        bin_path = identity.source_path
        if identity.is_registry_package or bin_path is None or not _safe_probe_path(bin_path, guard_home=guard_home):
            return None
        return identity, (bin_path, "--help")
    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    if not model.segments:
        return None
    segment = model.segments[0]
    launch = build_runtime_launch_identity(
        segment.executable,
        args=segment.arguments,
        structured_command=True,
        cwd=cwd,
        home_dir=home_dir,
    )
    executable = launch.get("executable")
    entrypoint = launch.get("entrypoint")
    if not isinstance(executable, dict) or not isinstance(entrypoint, dict):
        return None
    exe_path = executable.get("path")
    if not isinstance(exe_path, str) or not _safe_probe_path(exe_path, guard_home=guard_home):
        return None
    if identity.kind == "script":
        script_path = entrypoint.get("path")
        if not isinstance(script_path, str) or not _safe_probe_path(script_path, guard_home=guard_home):
            return None
        return identity, (exe_path, script_path, "--help")
    return identity, (exe_path, "--help")


def discover_local_cli_commands(
    identity: UnlistedCliIdentity,
    argv: Sequence[str],
    *,
    cancel: threading.Event | None = None,
) -> tuple[tuple[LocalCliCommand, ...], HelpStatus]:
    """Ask the native runtime for ``identity``'s commands and merge them onto the default catalog.

    ``argv`` is the verified --help argv from ``help_invocation_for_command``.
    Setting ``cancel`` stops the runtime and every --help it started; once it
    is set nothing starts. A runtime that cannot answer leaves the CLI on its
    default commands with a ``failed`` status, so the operator is told Guard
    could not read --help rather than that the CLI named nothing.
    """

    discovered = _native_discover(identity, argv, cancel)
    if discovered is None:
        return merge_discovered_commands(identity.name, ()), "failed"
    commands, status = discovered
    return merge_discovered_commands(identity.name, commands), status


def _native_discover(
    identity: UnlistedCliIdentity,
    argv: Sequence[str],
    cancel: threading.Event | None,
) -> tuple[tuple[LocalCliCommand, ...], HelpStatus] | None:
    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    if cancel is not None and cancel.is_set():
        return None
    try:
        status = native_runtime_status()
    except Exception:
        return None
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or LOCAL_CLI_DISCOVER_FEATURE not in status.capabilities.features
    ):
        return None
    runtime = status.identity.path
    request = {"name": identity.name, "kind": identity.kind, "argv": [str(part) for part in argv]}
    completed = run_isolated_hook_process(
        (str(runtime), LOCAL_CLI_DISCOVER_COMMAND, "--stdin"),
        input_text=json.dumps(request, separators=(",", ":")),
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
        stop_event=cancel,
    )
    if completed.returncode != 0 or completed.timed_out or completed.output_limit_exceeded:
        return None
    if completed.containment_failed:
        return None
    try:
        answer = json.loads(completed.stdout)
    except (TypeError, ValueError):
        return None
    return _read_answer(answer)


def _read_answer(answer: object) -> tuple[tuple[LocalCliCommand, ...], HelpStatus] | None:
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        return None
    result = answer.get("result")
    if not isinstance(result, dict):
        return None
    status = result.get("status")
    rows = result.get("commands")
    if status not in ("ok", "empty", "failed") or not isinstance(rows, list):
        return None
    commands: list[LocalCliCommand] = []
    for row in rows:
        if not isinstance(row, dict) or any(not isinstance(row.get(field), str) for field in _FIELDS):
            return None
        parent_id = row.get("parent_id")
        if parent_id is not None and not isinstance(parent_id, str):
            return None
        commands.append(
            LocalCliCommand(
                command_id=row["command_id"],
                name=row["name"],
                usage=row["usage"],
                description=row["description"],
                parent_id=parent_id,
            )
        )
    return tuple(commands), status

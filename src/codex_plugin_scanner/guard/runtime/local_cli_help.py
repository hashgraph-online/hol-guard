"""Bounded --help probing for custom extension command discovery."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal

from .approval_context import build_runtime_launch_identity
from .command_model import parse_shell_command
from .local_cli_commands import LocalCliCommand, merge_discovered_commands
from .local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli

HelpStatus = Literal["ok", "empty", "failed"]

_COMMAND_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")
_HELP_TIMEOUT_SECONDS = 2.5
_HELP_OUTPUT_LIMIT = 8192
_MAX_NESTED_PROBES = 8
_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"


def parse_cli_help_text(
    text: str,
    *,
    parent_id: str | None = None,
    invocation: Sequence[str] = (),
    guard_home: Path | None = None,
) -> tuple[LocalCliCommand, ...] | None:
    """Extract first-level commands from typical CLI --help output.

    ``invocation`` is the program and parent command path (for example
    ``("wrangler", "d1")``). Yargs-style help repeats it at the start of every
    indented row and groups commands under uppercase headings such as
    ``ACCOUNT``. Under those headings only invocation-prefixed rows count;
    prose, examples, options and positionals never do.

    The reading itself is the resident's, in ``rust/.../local_cli_help.rs``.
    Help text is whatever a third-party program printed, so nothing here parses
    it.

    Returns the commands the resident read, or ``None`` when it could not
    answer. The two are not the same thing and the caller reports them
    differently: a CLI whose help names no subcommands really did name none,
    while a resident that never answered has read nothing at all, and telling
    the operator the CLI listed no subcommands would be a guess.
    """

    from ..config import resolve_guard_home
    from ..native_local_cli_help_parse import native_local_cli_help_commands

    home = guard_home if guard_home is not None else resolve_guard_home()
    try:
        rows = native_local_cli_help_commands(
            guard_home=home,
            text=text,
            parent_id=parent_id,
            invocation=tuple(invocation),
        )
    except Exception:
        return None
    if rows is None:
        return None
    return tuple(
        LocalCliCommand(
            command_id=str(row["command_id"]),
            name=str(row["name"]),
            usage=str(row["usage"]),
            description=str(row["description"]),
            parent_id=None if row["parent_id"] is None else str(row["parent_id"]),
        )
        for row in rows
    )


def help_invocation_for_command(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> tuple[UnlistedCliIdentity, tuple[str, ...]] | None:
    """Return the verified identity and argv Guard may use for --help."""

    identity = identify_unlisted_cli(command_text, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return None
    if identity.runner is not None:
        # Probe the proven project bin directly; registry fetches are never run.
        bin_path = identity.source_path
        if identity.is_registry_package or bin_path is None or not _safe_probe_path(bin_path):
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
    if not isinstance(exe_path, str) or not _safe_probe_path(exe_path):
        return None
    if identity.kind == "script":
        script_path = entrypoint.get("path")
        if not isinstance(script_path, str) or not _safe_probe_path(script_path):
            return None
        return identity, (exe_path, script_path, "--help")
    return identity, (exe_path, "--help")


def discover_local_cli_commands(
    identity: UnlistedCliIdentity,
    argv: Sequence[str],
    *,
    runner: Callable[[Sequence[str]], str] | None = None,
    guard_home: Path | None = None,
) -> tuple[tuple[LocalCliCommand, ...], HelpStatus]:
    """Run --help and merge discovered commands onto the default catalog.

    ``guard_home`` is the home whose resident reads the help text. A daemon
    serving a non-default home must pass its own, or the parse goes to a
    resident it does not own.
    """

    probe: Callable[[Sequence[str]], str] = runner if runner is not None else run_cli_help
    output = str(probe(tuple(argv)))
    empty: tuple[LocalCliCommand, ...] = ()
    if output.strip() == "":
        # The probe printed nothing, so there is nothing to send anywhere.
        return merge_discovered_commands(identity.name, empty), "failed"
    discovered = parse_cli_help_text(output, invocation=(identity.name,), guard_home=guard_home)
    if discovered is None:
        return merge_discovered_commands(identity.name, empty), "failed"
    if not discovered:
        return merge_discovered_commands(identity.name, empty), "empty"
    if len(discovered) <= _MAX_NESTED_PROBES:
        discovered = _with_nested_commands(tuple(argv), discovered, probe, program=identity.name, guard_home=guard_home)
    return merge_discovered_commands(identity.name, discovered), "ok"


def run_cli_help(argv: Sequence[str]) -> str:
    """Run a verified --help argv in an isolated temp directory."""

    if len(argv) < 2 or argv[-1] != "--help":
        return ""
    if any(not isinstance(part, str) or not part or "\x00" in part for part in argv):
        return ""
    if not _safe_probe_path(argv[0]):
        return ""
    if (
        len(argv) >= 3
        and not _safe_probe_path(argv[1])
        and argv[1] != "--help"
        and not _COMMAND_NAME.fullmatch(str(argv[1]))
    ):
        return ""
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-cli-help-") as tmp:
            return _read_help_output(list(argv), tmp)
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _read_help_output(argv: list[str], tmp: str) -> str:
    process = subprocess.Popen(
        argv,
        cwd=tmp,
        env=_help_env(tmp),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    chunks: list[str] = []
    captured = 0

    def _drain() -> None:
        nonlocal captured
        stdout = process.stdout
        if stdout is None:
            return
        while captured < _HELP_OUTPUT_LIMIT:
            piece = stdout.read(min(4096, _HELP_OUTPUT_LIMIT - captured))
            if piece == "":
                return
            chunks.append(piece)
            captured += len(piece)
        process.kill()

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    reader.join(_HELP_TIMEOUT_SECONDS)
    if reader.is_alive() or process.poll() is None:
        process.kill()
        reader.join(1)
        if process.poll() is None:
            process.wait(timeout=1)
    return "".join(chunks)[:_HELP_OUTPUT_LIMIT]


def _with_nested_commands(
    argv: Sequence[str],
    discovered: Sequence[LocalCliCommand],
    probe: Callable[[Sequence[str]], str],
    *,
    program: str,
    guard_home: Path | None = None,
) -> tuple[LocalCliCommand, ...]:
    nested: list[LocalCliCommand] = list(discovered)
    seen = {command.command_id for command in nested}
    prefix = tuple(argv[:-1])
    for command in discovered:
        if command.parent_id is not None:
            continue
        child_output = probe((*prefix, command.name, "--help"))
        if child_output.strip() == "":
            continue
        children = parse_cli_help_text(child_output, invocation=(program, command.name), guard_home=guard_home)
        if children is None:
            # The resident stopped answering. Every remaining child would wait
            # out its own timeout for the same silence, so stop probing and
            # keep what the top-level parse already found.
            break
        for child in children:
            child_id = f"{command.command_id}.{child.command_id}"
            if child_id in seen or not _COMMAND_NAME.fullmatch(child.command_id):
                continue
            seen.add(child_id)
            nested.append(
                LocalCliCommand(
                    command_id=child_id,
                    name=f"{command.name} {child.name}",
                    usage=f"{command.name} {child.usage or child.name}",
                    description=child.description,
                    parent_id=command.command_id,
                )
            )
    return tuple(nested)


def _help_env(tmp: str) -> dict[str, str]:
    env = {
        "PATH": _SAFE_PATH,
        "HOME": tmp,
        "TMPDIR": tmp,
        "LANG": "C",
        "LC_ALL": "C",
        "TERM": "dumb",
    }
    if os.name == "nt":
        env["PATH"] = os.environ.get("PATH", env["PATH"])
        system_root = os.environ.get("SYSTEMROOT")
        if system_root:
            env["SYSTEMROOT"] = system_root
    return env


def _safe_probe_path(path_text: str) -> bool:
    path = Path(path_text)
    if not path.is_absolute():
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return False
    if not resolved.is_file():
        return False
    parts = [part.lower() for part in resolved.parts]
    return not (len(parts) > 1 and parts[0] == "/" and parts[1] in {"proc", "dev", "sys"})

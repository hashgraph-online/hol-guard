"""Bounded --help probing for custom extension command discovery."""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import tempfile
import threading
from collections.abc import Callable, Iterable, Sequence
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
_SCRIPT_SOURCE_LIMIT = 32 * 1024
_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"


def parse_cli_help_text(
    text: str,
    *,
    parent_id: str | None = None,
    invocation: Sequence[str] = (),
    guard_home: Path | None = None,
    script_source: bool = False,
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

    ``script_source`` sends a script's own source instead of help output, for
    a script whose ``--help`` printed nothing useful.
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
            script_source=script_source,
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
    # The probe printed nothing, so there is no help to send anywhere.
    discovered = (
        parse_cli_help_text(output, invocation=(identity.name,), guard_home=guard_home) if output.strip() else None
    )
    # A resident that could not read the help would not read the source either.
    resident_failed = discovered is None and bool(output.strip())
    if not discovered and not resident_failed:
        # Many scripts reject --help or print only an error. Their usage
        # comment and argument loop still name what they take.
        from_source = _script_source_commands(identity, argv, guard_home=guard_home)
        if from_source:
            return merge_discovered_commands(identity.name, from_source), "ok"
    if discovered is None:
        return merge_discovered_commands(identity.name, empty), "failed"
    if not discovered:
        return merge_discovered_commands(identity.name, empty), "empty"
    if len(discovered) <= _MAX_NESTED_PROBES:
        discovered = _with_nested_commands(
            tuple(argv), discovered, probe, program=identity.name, parent_help=output, guard_home=guard_home
        )
    return merge_discovered_commands(identity.name, discovered), "ok"


def _script_source_commands(
    identity: UnlistedCliIdentity,
    argv: Sequence[str],
    *,
    guard_home: Path | None,
) -> tuple[LocalCliCommand, ...] | None:
    """What a script's own source names, read from the verified script path.

    A script launched through its interpreter has ``argv`` of
    ``(interpreter, script, "--help")``. One run directly has ``(script,
    "--help")`` and counts only when the file starts with a ``#!`` line, so a
    compiled program is never read as text. Either path already passed the
    probe's checks. Nothing in the file is run.
    """

    if identity.kind == "script" and len(argv) == 3:
        path, shebang_only = str(argv[1]), False
    elif identity.kind == "executable" and len(argv) == 2:
        path, shebang_only = str(argv[0]), True
    else:
        return None
    if not _safe_probe_path(path):
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_SCRIPT_SOURCE_LIMIT)
    except OSError:
        return None
    if shebang_only and not raw.startswith(b"#!"):
        return None
    source = raw.decode("utf-8", errors="replace")
    if not source.strip():
        return None
    return parse_cli_help_text(source, invocation=(identity.name,), guard_home=guard_home, script_source=True)


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
        # Its own process group, so a timeout also stops whatever the
        # program started.
        start_new_session=os.name != "nt",
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
        _stop_probe(process)

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    reader.join(_HELP_TIMEOUT_SECONDS)
    try:
        if reader.is_alive() or process.poll() is None:
            _stop_probe(process)
            reader.join(1)
            if process.poll() is None:
                process.wait(timeout=1)
    finally:
        # A child that let go of the output can outlive a program that exited
        # on its own; nothing a help run started keeps running after it.
        _stop_group(process)
    return "".join(chunks)[:_HELP_OUTPUT_LIMIT]


def _stop_probe(process: subprocess.Popen[str]) -> None:
    """Kill a help probe and, off Windows, every process in its group.

    A program that ignores --help can start children that keep its output
    open or keep working after it exits; killing only the direct child would
    leave them running.
    """

    _stop_group(process)
    process.kill()


def _stop_group(process: subprocess.Popen[str]) -> None:
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)


def _with_nested_commands(
    argv: Sequence[str],
    discovered: Sequence[LocalCliCommand],
    probe: Callable[[Sequence[str]], str],
    *,
    program: str,
    parent_help: str,
    guard_home: Path | None = None,
) -> tuple[LocalCliCommand, ...]:
    nested: list[LocalCliCommand] = list(discovered)
    seen = {command.command_id for command in nested}
    prefix = tuple(argv[:-1])
    top_level_help = _help_words(parent_help)
    top_level_entries = _listed_entries(command for command in discovered if command.parent_id is None)
    for command in discovered:
        # An option has no help of its own to probe.
        if command.parent_id is not None or not _COMMAND_NAME.fullmatch(command.name):
            continue
        child_output = probe((*prefix, command.name, "--help"))
        # A script that reads only --help prints its own help again for every
        # command. That lists the top-level commands, not this command's, and
        # would add each one again under every other, such as "push push".
        if child_output.strip() == "" or _help_words(child_output) == top_level_help:
            continue
        children = parse_cli_help_text(child_output, invocation=(program, command.name), guard_home=guard_home)
        if children is None:
            # The resident stopped answering. Every remaining child would wait
            # out its own timeout for the same silence, so stop probing and
            # keep what the top-level parse already found.
            break
        # The same help under another heading lists the same commands with the
        # same descriptions. A command whose own subcommands share those names
        # describes them differently, so they are kept.
        if _listed_entries(children) == top_level_entries:
            continue
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


def _help_words(text: str) -> tuple[str, ...]:
    return tuple(text.split())


def _listed_entries(commands: Iterable[LocalCliCommand]) -> frozenset[tuple[str, str]]:
    return frozenset((command.command_id, " ".join(command.description.split())) for command in commands)


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

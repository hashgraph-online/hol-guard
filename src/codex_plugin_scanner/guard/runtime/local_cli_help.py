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
_SECTION_HEADER = re.compile(
    r"^(?:commands|available commands|core commands|additional commands|"
    r"management commands|general commands|positional arguments)\s*:?\s*$",
    re.IGNORECASE,
)
_ARGPARSE_SET = re.compile(r"\{([A-Za-z][A-Za-z0-9_-]*(?:\s*,\s*[A-Za-z][A-Za-z0-9_-]*)+)\}")
_SKIP_NAMES = frozenset({"help", "completion", "completions"})
_HELP_TIMEOUT_SECONDS = 2.5
_HELP_OUTPUT_LIMIT = 8192
_MAX_NESTED_PROBES = 8
_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"


def parse_cli_help_text(text: str, *, parent_id: str | None = None) -> tuple[LocalCliCommand, ...]:
    """Extract first-level commands from typical CLI --help output."""

    found: list[LocalCliCommand] = []
    seen: set[str] = set()
    in_section = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            if in_section and raw_line == "":
                in_section = False
            continue
        if _SECTION_HEADER.fullmatch(stripped):
            in_section = True
            for name in _argparse_names(stripped):
                _append_command(found, seen, name, parent_id=parent_id)
            continue
        if not in_section:
            continue
        for name in _argparse_names(stripped):
            _append_command(found, seen, name, parent_id=parent_id)
        parsed = _row_command(stripped)
        if parsed is None:
            if stripped.endswith(":") and not stripped.startswith("-"):
                in_section = False
            continue
        name, description = parsed
        _append_command(found, seen, name, description=description, parent_id=parent_id)
    if not found:
        for name in _argparse_names(text):
            _append_command(found, seen, name, parent_id=parent_id)
    return tuple(found)


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
) -> tuple[tuple[LocalCliCommand, ...], HelpStatus]:
    """Run --help and merge discovered commands onto the default catalog."""

    probe: Callable[[Sequence[str]], str] = runner if runner is not None else run_cli_help
    output = str(probe(tuple(argv)))
    discovered = parse_cli_help_text(output)
    if output.strip() == "":
        status: HelpStatus = "failed"
    elif not discovered:
        status = "empty"
    else:
        status = "ok"
        if len(discovered) <= _MAX_NESTED_PROBES:
            discovered = _with_nested_commands(tuple(argv), discovered, probe)
    return merge_discovered_commands(identity.name, discovered), status


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
) -> tuple[LocalCliCommand, ...]:
    nested: list[LocalCliCommand] = list(discovered)
    seen = {command.command_id for command in nested}
    prefix = tuple(argv[:-1])
    for command in discovered:
        if command.parent_id is not None:
            continue
        child_output = probe((*prefix, command.name, "--help"))
        for child in parse_cli_help_text(child_output):
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


def _row_command(line: str) -> tuple[str, str] | None:
    if line.startswith("-"):
        return None
    parts = line.split()
    if not parts:
        return None
    name = parts[0]
    if not _COMMAND_NAME.fullmatch(name) or name.lower() in _SKIP_NAMES:
        return None
    description = line[len(name) :].strip()
    return name, description[:200]


def _argparse_names(text: str) -> tuple[str, ...]:
    names: list[str] = []
    for match in _ARGPARSE_SET.finditer(text):
        for raw in match.group(1).split(","):
            name = raw.strip()
            if _COMMAND_NAME.fullmatch(name) and name.lower() not in _SKIP_NAMES:
                names.append(name)
    return tuple(names)


def _append_command(
    found: list[LocalCliCommand],
    seen: set[str],
    name: str,
    *,
    description: str = "",
    parent_id: str | None,
) -> None:
    command_id = name if parent_id is None else f"{parent_id}.{name}"
    if command_id in seen or name.lower() in _SKIP_NAMES:
        return
    if parent_id is None and not _COMMAND_NAME.fullmatch(name):
        return
    seen.add(command_id)
    found.append(
        LocalCliCommand(
            command_id=command_id,
            name=name,
            usage=name,
            description=description,
            parent_id=parent_id,
        )
    )

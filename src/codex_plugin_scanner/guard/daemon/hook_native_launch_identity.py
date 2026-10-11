"""Launch-identity proofs for daemon native exact-action approvals.

A launch identity binds the code a reviewed command would run. Anything that
loads code the identity cannot bind (interpreters, task runners, wrappers) is
refused with a stable ``OnceOnlyError`` reason, and a compound command is persistable
only when every segment passes the same proof.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from pathlib import Path

from ..runtime.approval_context import build_runtime_launch_identity, runtime_launch_identity_is_reusable
from ..runtime.local_cli_runner import LOCAL_BIN_RUNNERS, runner_local_bin
from .hook_native_exact_identity import (
    COMPOUND_COMMAND,
    DESTRUCTIVE_COMMAND,
    MUTABLE_LAUNCHER,
    SENSITIVE_PATH,
    UNPROVEN_LAUNCH,
    OnceOnlyError,
    git_readonly_identity,
)

# Runners whose target is accepted only when it resolves to a content-hashed
# project-local binary. Registry and cache fetches stay once-only.
_LOCAL_BIN_RUNNERS = LOCAL_BIN_RUNNERS
# Interpreters, task runners and wrappers beyond the once-retry list whose
# launch identity does not bind the code they load or run.
_EXTRA_MUTABLE_LAUNCHERS = frozenset(
    {
        "nodejs",
        "php",
        "go",
        "tsx",
        "ts-node",
        "vite-node",
        "jiti",
        "esno",
        "babel-node",
        "nodemon",
        "zx",
        "docker",
        "podman",
        # git runs aliases, hooks and config-defined helpers from mutable files.
        "git",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "xargs",
        "parallel",
        "env",
        "sudo",
        "doas",
        "nohup",
        "timeout",
        "watch",
        "osascript",
        "pwsh",
        "powershell",
        "java",
        "dotnet",
        "lua",
        "rscript",
        "julia",
        "swift",
        "r",
        # Tools that load project code or config the token cannot bind.
        *("terraform", "tofu", "terragrunt", "pulumi", "ansible", "ansible-playbook"),
        *("pytest", "py.test", "tox", "nox", "jest", "vitest", "mocha", "rake", "gradle", "mvn"),
        # GNU sed can run shell commands from its script (``e``).
        "sed",
    }
)
# Commands that delete, overwrite, move or reach the network. They never carry
# a persistent allow, alone or as one segment of a compound command.
_DESTRUCTIVE_EXECUTABLES = frozenset(
    {"rm", "rmdir", "unlink", "shred", "dd", "mv", "chmod", "chown", "truncate", "mkfs", "kill", "pkill", "killall"}
    | {"curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "telnet", "ftp"}
)
# A lone version flag makes any program print its version and exit; it loads no
# project code, so the binary's own launch identity is the whole proof.
_VERSION_PROBE_ARGUMENTS = frozenset({("--version",), ("-V",), ("-version",)})
_MAX_COMPOUND_SEGMENTS = 8
_FIND_EXEC_OPTIONS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
# Existing file operands are content-bound so an edited script, program or
# input re-prompts. Larger or more numerous operands stay once-only.
_MAX_BOUND_OPERANDS = 16
_MAX_BOUND_OPERAND_BYTES = 4_194_304


def launch_identity(command: str, *, cwd: Path, home_dir: Path | None) -> dict[str, object]:
    """Return the launch identity of a command, or raise ``OnceOnlyError`` with the reason."""

    from ..runtime.command_model import CanonicalCommand, parse_shell_command

    try:
        model = parse_shell_command(command, cwd=cwd, home_dir=home_dir)
    except ValueError as error:
        raise OnceOnlyError(UNPROVEN_LAUNCH) from error
    if len(model.segments) > 1:
        return _compound_identity(model, cwd=cwd, home_dir=home_dir)
    if not isinstance(model, CanonicalCommand):
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    return _segment_identity(model, command, cwd=cwd, home_dir=home_dir)


def _compound_identity(model: object, *, cwd: Path, home_dir: Path | None) -> dict[str, object]:
    """Bind every segment of ``a && b`` / ``a; b`` / ``a | b`` to its own proof.

    Redirects, substitutions, wrappers and environment prefixes are refused for
    the whole command, and a segment that is not independently provable (an
    interpreter on the right of a pipe, for example) makes it once-only.
    """

    from ..runtime.command_model import CanonicalCommand, CommandSegment

    assert isinstance(model, CanonicalCommand)
    if model.confidence != "exact" or model.redirects or model.embedded_commands or model.wrapper_chain:
        raise OnceOnlyError(COMPOUND_COMMAND)
    if model.path_overridden or len(model.segments) > _MAX_COMPOUND_SEGMENTS:
        raise OnceOnlyError(COMPOUND_COMMAND)
    segments: list[dict[str, object]] = []
    segment_cwd = cwd
    for segment in model.segments:
        if not isinstance(segment, CommandSegment) or not segment.execution_context.startswith("top:"):
            raise OnceOnlyError(COMPOUND_COMMAND)
        if segment.environment_names or segment.wrapper_chain or segment.path_overridden or not segment.executable:
            raise OnceOnlyError(COMPOUND_COMMAND)
        name = _normalized_name(segment.executable)
        if name == "cd":
            segment_cwd = _cd_target(segment.arguments, segment_cwd)
            segments.append({"kind": "cd", "target": str(segment_cwd)})
            continue
        try:
            segments.append(_segment_launch(segment, name, "", cwd=segment_cwd, home_dir=home_dir, compound=True))
        except OnceOnlyError as once_only:
            if once_only.reason in {UNPROVEN_LAUNCH, MUTABLE_LAUNCHER}:
                raise OnceOnlyError(COMPOUND_COMMAND) from once_only
            raise
    return {"kind": "compound", "segments": segments}


def _cd_target(arguments: tuple[str, ...], cwd: Path) -> Path:
    if len(arguments) != 1 or arguments[0].startswith(("-", "$", "~")):
        raise OnceOnlyError(COMPOUND_COMMAND)
    candidate = Path(arguments[0])
    try:
        resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve(strict=True)
    except OSError as error:
        raise OnceOnlyError(COMPOUND_COMMAND) from error
    if not resolved.is_dir():
        raise OnceOnlyError(COMPOUND_COMMAND)
    return resolved


def _segment_identity(model: object, command: str, *, cwd: Path, home_dir: Path | None) -> dict[str, object]:
    from ..runtime.command_model import CanonicalCommand
    from ..runtime.local_cli_identity import unlisted_cli_invocation_is_safe

    assert isinstance(model, CanonicalCommand)
    if not unlisted_cli_invocation_is_safe(model):
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    segment = model.segments[0]
    return _segment_launch(segment, _normalized_name(segment.executable), command, cwd=cwd, home_dir=home_dir)


def _normalized_name(executable: str | None) -> str:
    from ..runtime.command_tokens import executable_name

    name = (executable_name(executable) or "").lower()
    for suffix in (".exe", ".cmd"):
        name = name.removesuffix(suffix)
    return name


def _segment_launch(
    segment: object, name: str, command: str, *, cwd: Path, home_dir: Path | None, compound: bool = False
) -> dict[str, object]:
    from ..runtime.command_model import CommandSegment

    assert isinstance(segment, CommandSegment)
    arguments = list(segment.arguments)
    if name in _DESTRUCTIVE_EXECUTABLES:
        raise OnceOnlyError(DESTRUCTIVE_COMMAND)
    if any(_argument_is_sensitive(argument, cwd=cwd, home_dir=home_dir) for argument in arguments):
        raise OnceOnlyError(SENSITIVE_PATH)
    operands = _file_operand_hashes(arguments, cwd=cwd)
    if operands is None:
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    if name == "git":
        binary = build_runtime_launch_identity(
            segment.executable, args=segment.arguments, structured_command=True, cwd=cwd, home_dir=home_dir
        )
        if not runtime_launch_identity_is_reusable(binary):
            raise OnceOnlyError(UNPROVEN_LAUNCH)
        git = git_readonly_identity(arguments, cwd=cwd, home_dir=home_dir)
        return {"kind": "direct", "identity": binary, "git": git, "operands": operands}
    if _is_version_probe(segment, name):
        launch = build_runtime_launch_identity(
            segment.executable, args=segment.arguments, structured_command=True, cwd=cwd, home_dir=home_dir
        )
        if not runtime_launch_identity_is_reusable(launch):
            raise OnceOnlyError(UNPROVEN_LAUNCH)
        return {"kind": "direct", "identity": launch, "operands": operands, "version_probe": True}
    if name in _LOCAL_BIN_RUNNERS:
        local_bin = None if compound else _runner_local_bin(command, name, arguments, cwd=cwd, home_dir=home_dir)
        if local_bin is None:
            raise OnceOnlyError(MUTABLE_LAUNCHER)
        return {"kind": "runner-local-bin", "runner": name, "local_bin": local_bin, "operands": operands}
    if _loads_unbound_code(name, arguments):
        raise OnceOnlyError(MUTABLE_LAUNCHER)
    launch = build_runtime_launch_identity(
        segment.executable,
        args=segment.arguments,
        structured_command=True,
        cwd=cwd,
        home_dir=home_dir,
    )
    if not runtime_launch_identity_is_reusable(launch):
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    return {"kind": "direct", "identity": launch, "operands": operands}


def _is_version_probe(segment: object, name: str) -> bool:
    """True for ``<program> --version`` with no environment, wrapper or path override."""

    from ..runtime.command_model import CommandSegment

    assert isinstance(segment, CommandSegment)
    return (
        name not in {"git", "sudo", "doas", "env", "xargs", "parallel", "timeout", "nohup", "watch"}
        and tuple(segment.arguments) in _VERSION_PROBE_ARGUMENTS
        and not segment.environment_names
        and not segment.wrapper_chain
        and not segment.path_overridden
    )


def _argument_is_sensitive(argument: str, *, cwd: Path, home_dir: Path | None) -> bool:
    from ..runtime.secret_sensitivity import classify_secret_path

    value = argument.partition("=")[2] if argument.startswith("-") else argument
    return (
        bool(value)
        and not value.startswith("-")
        and classify_secret_path(value, cwd=cwd, home_dir=home_dir) is not None
    )


def _loads_unbound_code(name: str, arguments: list[str]) -> bool:
    from .hook_native_review_approval import (
        _FILE_BACKED_PROGRAM_COMMANDS,
        _rg_executes_unreviewed_preprocessor,
        _uses_file_backed_program,
    )

    if _is_mutable_launcher(name):
        return True
    if name == "find" and any(argument in _FIND_EXEC_OPTIONS for argument in arguments):
        return True
    if name in _FILE_BACKED_PROGRAM_COMMANDS and _uses_file_backed_program(arguments):
        return True
    return name == "rg" and _rg_executes_unreviewed_preprocessor(arguments)


def _is_mutable_launcher(name: str) -> bool:
    from .hook_native_review_approval import _MUTABLE_CODE_LAUNCHERS, _PYTHON_LAUNCHER

    return name in _MUTABLE_CODE_LAUNCHERS or name in _EXTRA_MUTABLE_LAUNCHERS or bool(_PYTHON_LAUNCHER.fullmatch(name))


def _runner_local_bin(
    command: str, runner: str, arguments: list[str], *, cwd: Path, home_dir: Path | None
) -> dict[str, object] | None:
    # A local interpreter or task runner loads code its identity does not bind.
    return runner_local_bin(command, runner, arguments, cwd=cwd, home_dir=home_dir, reject_target=_is_mutable_launcher)


def _file_operand_hashes(arguments: list[str], *, cwd: Path) -> list[dict[str, str]] | None:
    """Hash file operands (marking absent and non-file ones), or ``None`` when they cannot be bound."""

    bound: list[dict[str, str]] = []
    for argument in arguments:
        value = argument.partition("=")[2] if argument.startswith("-") else argument
        if not value or value.startswith("-"):
            continue
        candidate = Path(value) if os.path.isabs(value) else cwd / value
        try:
            if not candidate.is_file():
                # An absent operand is bound too, so creating the file re-prompts.
                bound.append({"argument": argument, "sha256": "absent" if not candidate.exists() else "non-file"})
                continue
            if candidate.stat().st_size > _MAX_BOUND_OPERAND_BYTES or len(bound) >= _MAX_BOUND_OPERANDS:
                return None
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        except (OSError, ValueError):
            return None
        bound.append({"argument": argument, "sha256": digest})
    return bound


def launch_cwd(payload: Mapping[str, object], workspace: Path | None) -> Path | None:
    raw = payload.get("cwd")
    candidate = Path(raw) if isinstance(raw, str) and raw.strip() else workspace
    if candidate is None or not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    return resolved if os.path.isdir(resolved) else None


__all__ = ["launch_cwd", "launch_identity"]

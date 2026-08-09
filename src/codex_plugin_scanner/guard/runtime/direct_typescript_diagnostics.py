"""Proof-backed recognition for local TypeScript diagnostic filters."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Protocol

from .github_actions_read_workflow import shell_read_execution_environment_is_safe
from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment

_PATH_COMPONENT = r"(?:[A-Za-z0-9_-]|\\\.)+"
_TYPESCRIPT_DIAGNOSTIC_PATH_FILTER = re.compile(
    rf"^{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*(?:\|{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*)*$"
)
_NODE_CODE_LOADING_ENVIRONMENT = frozenset({"node_options", "node_path"})
_NPM_NON_EXECUTION_KEYS = frozenset(
    {
        "always-auth",
        "audit",
        "color",
        "fund",
        "loglevel",
        "progress",
        "registry",
        "strict-ssl",
    }
)
_NPM_REGISTRY_AUTH_SUFFIXES = (
    ":-auth",
    ":-authtoken",
    ":-password",
    ":always-auth",
    ":email",
    ":username",
)
_MAX_NPM_CONFIG_BYTES = 64 * 1024
_TSC_WRITE_FLAGS = frozenset(
    {
        "--build",
        "-b",
        "--composite",
        "--declaration",
        "--declarationMap",
        "--emitDeclarationOnly",
        "--generateCpuProfile",
        "--generateTrace",
        "--incremental",
        "--init",
        "--out",
        "--outDir",
        "--tsBuildInfoFile",
    }
)
_TSC_PATH_VALUE_FLAGS = frozenset({"--baseUrl", "--project", "-p", "--rootDir", "--typeRoots"})
_TSC_PACKAGE_VALUE_FLAGS = frozenset({"--types"})
_TSC_BOOLEAN_FLAGS = frozenset({"--noEmit", "--skipLibCheck"})
_TSC_VALUE_FLAGS = frozenset(
    {
        "--jsx",
        "--lib",
        "--module",
        "--moduleResolution",
        "--target",
        "--types",
        *_TSC_PATH_VALUE_FLAGS,
    }
)


class TrustedPathCommand(Protocol):
    def __call__(self, command: str, *, cwd: Path, home_dir: Path) -> bool: ...


def direct_typescript_diagnostic_filter_context(
    context: ShellExecutionContext,
    *,
    workspace: Path,
    home_dir: Path,
    trusted_path_command: TrustedPathCommand,
    workspace_typescript_is_bound: WorkspaceTypeScriptBinding,
) -> ShellExecutionContext | None:
    routine_context = _routine_typescript_diagnostic_context(
        context,
        workspace=workspace,
        home_dir=home_dir,
        trusted_path_command=trusted_path_command,
        workspace_typescript_is_bound=workspace_typescript_is_bound,
    )
    if routine_context is not None:
        return routine_context
    if not context.complete or len(context.segments) != 4:
        return None
    directory, compiler, grep, marker = context.segments
    if (
        directory.directory_operation != "cd"
        or directory.control_before
        or compiler.control_before != ("&&",)
        or compiler.effective_cwd != workspace
        or grep.control_before != ("|",)
        or marker.control_before != ("||",)
    ):
        return None
    compiler_tokens = list(compiler.tokens)
    if compiler_tokens[-1:] != ["2>&1"]:
        return None
    _ = compiler_tokens.pop()
    if (
        compiler_tokens != ["npx", "tsc", "--noEmit"]
        or not shell_read_execution_environment_is_safe(cwd=workspace)
        or _node_execution_environment_is_configurable(workspace, home_dir)
        or not trusted_path_command("npx", cwd=workspace, home_dir=home_dir)
        or not trusted_path_command("node", cwd=workspace, home_dir=home_dir)
        or not workspace_typescript_is_bound(workspace)
        or not _workspace_npx_typescript_runner_is_bound(workspace)
    ):
        return None
    if (
        len(grep.tokens) != 3
        or grep.tokens[:2] != ("grep", "-E")
        or len(grep.tokens[2]) > 512
        or _TYPESCRIPT_DIAGNOSTIC_PATH_FILTER.fullmatch(grep.tokens[2]) is None
        or not trusted_path_command("grep", cwd=workspace, home_dir=home_dir)
    ):
        return None
    if marker.tokens != ("echo", "NO_ERRORS_IN_TOUCHED_FILES"):
        return None
    return context


def _routine_typescript_diagnostic_context(
    context: ShellExecutionContext,
    *,
    workspace: Path,
    home_dir: Path,
    trusted_path_command: TrustedPathCommand,
    workspace_typescript_is_bound: WorkspaceTypeScriptBinding,
) -> ShellExecutionContext | None:
    """Recognize a local no-emit compiler followed by bounded stream observers."""

    if not context.complete or len(context.segments) not in {4, 5}:
        return None
    directory, compiler, *observers = context.segments
    if (
        directory.directory_operation != "cd"
        or directory.control_before
        or compiler.control_before != ("&&",)
        or compiler.effective_cwd != workspace
    ):
        return None
    compiler_tokens = list(compiler.tokens)
    if compiler_tokens[-1:] != ["2>&1"]:
        return None
    _ = compiler_tokens.pop()
    node_options = compiler_tokens[0] if compiler_tokens and compiler_tokens[0].startswith("NODE_OPTIONS=") else None
    if node_options is not None and not _safe_typecheck_node_options(node_options):
        return None
    if node_options is not None:
        _ = compiler_tokens.pop(0)
    if (
        compiler_tokens[:2] != ["npx", "tsc"]
        or not _typescript_no_emit_args_are_safe(compiler_tokens[2:], workspace=workspace)
        or not shell_read_execution_environment_is_safe(cwd=workspace)
        or _node_execution_environment_is_configurable(workspace, home_dir)
        or not trusted_path_command("npx", cwd=workspace, home_dir=home_dir)
        or not trusted_path_command("node", cwd=workspace, home_dir=home_dir)
        or not workspace_typescript_is_bound(workspace)
        or not _workspace_npx_typescript_runner_is_bound(workspace)
    ):
        return None
    stream_observers = observers
    if observers[-1].control_before == (";",):
        marker = observers[-1]
        if len(marker.tokens) != 2 or marker.tokens[0] != "echo" or not _static_marker_is_safe(marker.tokens[1]):
            return None
        stream_observers = observers[:-1]
    if not stream_observers or any(
        not _typescript_stream_observer_is_safe(
            segment,
            workspace=workspace,
            home_dir=home_dir,
            trusted_path_command=trusted_path_command,
        )
        for segment in stream_observers
    ):
        return None
    if not any(segment.tokens[:1] in {("head",), ("tail",)} for segment in stream_observers):
        return None
    return context


def _typescript_no_emit_args_are_safe(args: list[str], *, workspace: Path) -> bool:
    write_flag_prefixes = tuple(f"{flag}=" for flag in _TSC_WRITE_FLAGS if flag.startswith("--"))
    if (
        args.count("--noEmit") != 1
        or any(_token_has_shell_dynamics(arg) for arg in args)
        or any(arg in _TSC_WRITE_FLAGS or arg.startswith(write_flag_prefixes) for arg in args)
    ):
        return False
    no_emit_index = args.index("--noEmit")
    if no_emit_index + 1 < len(args) and args[no_emit_index + 1].casefold() in {"false", "true"}:
        return False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("@"):
            return False
        if "=" in arg:
            flag, value = arg.split("=", 1)
            if flag not in _TSC_VALUE_FLAGS or not value:
                return False
            if flag in _TSC_PACKAGE_VALUE_FLAGS and not _typescript_package_list_is_safe(value):
                return False
            if flag in _TSC_PATH_VALUE_FLAGS and not _typescript_path_is_contained(value, workspace=workspace):
                return False
            index += 1
            continue
        if arg in _TSC_BOOLEAN_FLAGS:
            if index + 1 < len(args) and args[index + 1].casefold() in {"false", "true"}:
                return False
            index += 1
            continue
        if arg in _TSC_VALUE_FLAGS:
            if index + 1 >= len(args):
                return False
            value = args[index + 1]
            if arg in _TSC_PACKAGE_VALUE_FLAGS and not _typescript_package_list_is_safe(value):
                return False
            if arg in _TSC_PATH_VALUE_FLAGS and not _typescript_path_is_contained(value, workspace=workspace):
                return False
            index += 2
            continue
        if arg.startswith("-"):
            return False
        if (
            not arg.startswith("-")
            and ("/" in arg or arg.endswith((".ts", ".tsx", ".mts", ".cts")))
            and not _typescript_path_is_contained(arg, workspace=workspace)
        ):
            return False
        index += 1
    return True


def _typescript_path_is_contained(value: str, *, workspace: Path) -> bool:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        _ = candidate.resolve(strict=True).relative_to(workspace.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _typescript_package_list_is_safe(value: str) -> bool:
    package = r"(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*"
    return bool(value) and all(re.fullmatch(package, item) is not None for item in value.split(","))


def _typescript_stream_observer_is_safe(
    segment: ShellExecutionSegment,
    *,
    workspace: Path,
    home_dir: Path,
    trusted_path_command: TrustedPathCommand,
) -> bool:
    control_before = segment.control_before
    tokens = segment.tokens
    if control_before != ("|",) or not tokens:
        return False
    if any(_token_has_shell_dynamics(token) for token in tokens):
        return False
    if not trusted_path_command(tokens[0], cwd=workspace, home_dir=home_dir):
        return False
    if tokens[0] == "grep":
        flags = tokens[1:-1]
        return (
            bool(tokens[-1])
            and not tokens[-1].startswith("-")
            and len(tokens[-1]) <= 512
            and all(flag in {"-a", "-E", "-i", "-v", "-aE", "-ai", "-iv"} for flag in flags)
        )
    if tokens[0] in {"head", "tail"} and len(tokens) == 2:
        count = tokens[1].removeprefix("-")
        return count.isdigit() and 1 <= int(count) <= 200
    return False


def _static_marker_is_safe(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value))


def _safe_typecheck_node_options(value: str) -> bool:
    match = re.fullmatch(r"NODE_OPTIONS=--max-old-space-size=([1-9][0-9]{2,4})", value)
    return match is not None and 256 <= int(match.group(1)) <= 65536


def _token_has_shell_dynamics(value: str) -> bool:
    return any(marker in value for marker in ("$", "`", "<(", ">(", "\x00", "\n"))


def _node_execution_environment_is_configurable(workspace: Path, home_dir: Path) -> bool:
    for key, value in os.environ.items():
        normalized_key = key.casefold()
        if value and (normalized_key in _NODE_CODE_LOADING_ENVIRONMENT or normalized_key.startswith("npm_config_")):
            return True
    return any(_npm_configuration_can_load_code(path) for path in (workspace / ".npmrc", home_dir / ".npmrc"))


def _npm_configuration_can_load_code(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        if not path.is_file() or path.stat().st_size > _MAX_NPM_CONFIG_BYTES:
            return True
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return True
    for line in lines:
        candidate = line.strip()
        if not candidate or candidate.startswith(("#", ";")):
            continue
        key, separator, _value = candidate.partition("=")
        if not separator:
            return True
        normalized_key = key.strip().casefold().replace("_", "-")
        if not _npm_configuration_key_is_nonexecuting(normalized_key):
            return True
    return False


def _npm_configuration_key_is_nonexecuting(key: str) -> bool:
    if key in _NPM_NON_EXECUTION_KEYS:
        return True
    if key.startswith("@") and key.endswith(":registry"):
        return True
    return key.startswith("//") and key.endswith(_NPM_REGISTRY_AUTH_SUFFIXES)


class WorkspaceTypeScriptBinding(Protocol):
    def __call__(self, workspace: Path) -> bool: ...


def _workspace_npx_typescript_runner_is_bound(workspace: Path) -> bool:
    bin_entry = workspace / "node_modules" / ".bin" / "tsc"
    compiler = workspace / "node_modules" / "typescript" / "bin" / "tsc"
    try:
        return bin_entry.is_symlink() and bin_entry.resolve(strict=True) == compiler.resolve(strict=True)
    except (OSError, RuntimeError):
        return False

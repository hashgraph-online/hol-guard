"""Identify CLIs that are not already a built-in command extension."""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ..native_local_cli_identity import native_local_cli_identity
from .approval_context import (
    build_runtime_launch_identity,
    runtime_launch_identity_is_reusable,
)
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .command_model import CanonicalCommand, CommandSegment, parse_shell_command
from .command_tokens import executable_name
from .custom_extension_suggestion import common_utility_reject_message, is_common_shell_utility
from .local_cli_runner import runner_name, unwrap_local_runner

LocalCliKind = Literal["executable", "script"]

# ``local-cli.pkg-`` is taken by package.json script identities.
REGISTRY_PACKAGE_CLI_PREFIX = "local-cli.npm-"
REGISTRY_PACKAGE_PATH_CLASS = "registry-package"
_CLI_ID_PATTERN = re.compile(r"^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$")
_INTERPRETER_NAMES = frozenset(
    {
        "ash",
        "bash",
        "bun",
        "dash",
        "deno",
        "ksh",
        "lua",
        "node",
        "nodejs",
        "osascript",
        "perl",
        "php",
        "powershell",
        "pwsh",
        "python",
        "python3",
        "ruby",
        "rscript",
        "sh",
        "ts-node",
        "tsx",
        "zsh",
    }
)
# Local-bin evidence fields the grant identity binds.
_LOCAL_BIN_IDENTITY_KEYS = ("resolved_path", "content_hash", "installed_version")
_PACKAGE_SCRIPT_KINDS = frozenset({"bun-package-script"})
_INLINE_KINDS = frozenset({"python-c", "python-m", "node-eval", "inline-script"})
_RESERVED_TOOL_NAMES = frozenset({"hol-guard", "hol_guard", "guard"})
_SCRIPT_LAUNCHERS = {
    ".py": "python3",
    ".js": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "tsx",
    ".rb": "ruby",
}


@dataclass(frozen=True, slots=True)
class UnlistedCliIdentity:
    """Stable identity for one unlisted CLI. Public payloads stay path-redacted."""

    cli_id: str
    name: str
    kind: LocalCliKind
    identity_hash: str
    example_label: str
    interpreter_name: str | None = None
    source_path: str | None = None
    # Stored observation class; derived from ``source_path`` when unset.
    path_class: str | None = None
    # Package runner (``npx``) that launched the CLI, if any.
    runner: str | None = None
    # Verified launch material the native runtime derived this identity from.
    # The grant decision re-derives the identity from it, so it is never part
    # of equality, hashing, or the public payload.
    identity_source: Mapping[str, object] | None = field(default=None, compare=False, repr=False)

    @property
    def is_registry_package(self) -> bool:
        """Runner fetches without a proven local bin never carry a persistent allow."""

        return self.runner is not None and self.path_class == REGISTRY_PACKAGE_PATH_CLASS

    def to_dict(self) -> dict[str, object]:
        return {
            "cli_id": self.cli_id,
            "name": self.name,
            "kind": self.kind,
            "identity_hash": self.identity_hash,
            "example_label": self.example_label,
            "interpreter_name": self.interpreter_name,
        }


def catalog_owned_executables(
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> frozenset[str]:
    """Return lowercase executable names already owned by built-in extensions."""

    return registry.owned_executables


def identify_unlisted_cli(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> UnlistedCliIdentity | None:
    """Return an unlisted CLI identity when the command is a single safe invocation."""

    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    return identify_unlisted_cli_from_command(model, cwd=cwd, home_dir=home_dir, registry=registry)


def identify_unlisted_cli_from_command(
    command: CanonicalCommand,
    *,
    cwd: Path,
    home_dir: Path | None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> UnlistedCliIdentity | None:
    """Return an unlisted CLI identity from an already parsed command."""

    if not unlisted_cli_invocation_is_safe(command):
        return None
    segment = command.segments[0]
    if runner_name(segment.executable) is not None:
        # ``pnpm run <script>`` and other non-launch forms keep the script path.
        runner_identity = _runner_identity(command, segment, cwd=cwd, home_dir=home_dir)
        if runner_identity is not None:
            return runner_identity
    launch = build_runtime_launch_identity(
        segment.executable,
        args=segment.arguments,
        structured_command=True,
        cwd=cwd,
        home_dir=home_dir,
    )
    if not runtime_launch_identity_is_reusable(launch):
        return None
    executable = launch.get("executable")
    entrypoint = launch.get("entrypoint")
    if not isinstance(executable, dict) or not isinstance(entrypoint, dict):
        return None
    owned = catalog_owned_executables(registry)
    exe_name = executable_name(segment.executable)
    entrypoint_kind = str(entrypoint.get("kind") or "")
    entrypoint_status = str(entrypoint.get("status") or "")
    script_cli = _script_identity(entrypoint, interpreter_name=exe_name)
    if script_cli is not None:
        return script_cli
    if exe_name is None:
        return None
    if _is_interpreter_name(exe_name):
        return None
    if is_common_shell_utility(exe_name) or is_reserved_tool_name(exe_name):
        return None
    if exe_name in owned and not _looks_like_script_kind(entrypoint_kind, entrypoint_status):
        return None
    return _executable_identity(executable, exe_name)


def unlisted_cli_invocation_is_safe(command: CanonicalCommand) -> bool:
    """Return whether the command is a single top-level invocation without wrappers."""

    if command.confidence != "exact":
        return False
    if command.redirects or command.embedded_commands or command.path_overridden:
        return False
    if command.wrapper_chain:
        return False
    if len(command.segments) != 1:
        return False
    segment = command.segments[0]
    return _safe_primary_segment(segment)


def is_local_cli_id(value: str) -> bool:
    return _CLI_ID_PATTERN.fullmatch(value) is not None


def is_reserved_tool_name(name: str) -> bool:
    return _normalize_tool_name(name) in _RESERVED_TOOL_NAMES


def recognize_operator_cli(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> tuple[UnlistedCliIdentity | None, str, str]:
    """Identify a pasted command or file path. Returns (identity, error_code, message)."""

    stripped = command_text.strip()
    if not stripped:
        return None, "missing_command", "Paste a command or a path to the tool."
    candidates = _recognition_candidates(stripped, cwd=cwd, home_dir=home_dir)
    last_code = "unrecognized_command"
    last_message = (
        "Guard could not turn that into one tool. Paste a single command, "
        "not a pipeline, and include the script or binary path."
    )
    owned = catalog_owned_executables(registry)
    for candidate in candidates:
        identity = identify_unlisted_cli(candidate, cwd=cwd, home_dir=home_dir, registry=registry)
        if identity is not None:
            return identity, "", ""
        exe = _first_executable_name(candidate, cwd=cwd, home_dir=home_dir)
        if exe is not None and is_common_shell_utility(exe):
            return None, "common_shell_utility", common_utility_reject_message(exe)
        if exe is not None and is_reserved_tool_name(exe):
            return None, "reserved_tool", "Guard itself is not added as a custom extension."
        if exe is not None and exe in owned and not _is_interpreter_name(exe):
            return None, "already_built_in", f"{exe} is already a built-in Guard extension."
        if "&&" in candidate or "||" in candidate or "|" in candidate:
            last_code = "compound_command"
            last_message = "Paste only the tool itself. Wrappers, pipes, and chained commands are not covered."
    return None, last_code, last_message


def _safe_primary_segment(segment: CommandSegment) -> bool:
    return (
        segment.execution_context == "top:0"
        and segment.pipeline_index == 0
        and not segment.environment_names
        and not segment.wrapper_chain
        and not segment.path_overridden
        and segment.executable is not None
    )


def _script_identity(entrypoint: dict[str, object], *, interpreter_name: str | None) -> UnlistedCliIdentity | None:
    if not _looks_like_script_kind(str(entrypoint.get("kind") or ""), str(entrypoint.get("status") or "")):
        return None
    source = {"source": "script", "entrypoint": entrypoint}
    identity = native_local_cli_identity(source)
    if identity is None:
        return None
    return UnlistedCliIdentity(
        cli_id=identity["cli_id"],
        name=identity["name"],
        kind="script",
        identity_hash=identity["identity_hash"],
        example_label=_example_label(interpreter_name, identity["name"]),
        interpreter_name=interpreter_name,
        source_path=_nonempty_string(entrypoint.get("path")),
        identity_source=source,
    )


def _executable_identity(executable: dict[str, object], exe_name: str) -> UnlistedCliIdentity | None:
    source = {"source": "executable", "executable": executable, "name": exe_name}
    identity = native_local_cli_identity(source)
    if identity is None:
        return None
    return UnlistedCliIdentity(
        cli_id=identity["cli_id"],
        name=exe_name,
        kind="executable",
        identity_hash=identity["identity_hash"],
        example_label=exe_name,
        interpreter_name=None,
        source_path=_nonempty_string(executable.get("path")),
        identity_source=source,
    )


def _runner_identity(
    command: CanonicalCommand,
    segment: CommandSegment,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> UnlistedCliIdentity | None:
    invocation = unwrap_local_runner(
        command.raw_text, segment.executable, segment.arguments, cwd=cwd, home_dir=home_dir
    )
    if invocation is None:
        return None
    name = invocation.target
    if _is_interpreter_name(name) or is_common_shell_utility(name) or is_reserved_tool_name(name):
        return None
    local_bin = invocation.local_bin
    if local_bin is None:
        registry_source = {"source": "registry_package", "name": name, "package_name": invocation.package_name}
        identity = native_local_cli_identity(registry_source)
        if identity is None:
            return None
        return UnlistedCliIdentity(
            cli_id=identity["cli_id"],
            name=name,
            kind="executable",
            identity_hash=identity["identity_hash"],
            example_label=f"{invocation.runner} {name}",
            path_class=REGISTRY_PACKAGE_PATH_CLASS,
            runner=invocation.runner,
            identity_source=registry_source,
        )
    evidence = {key: value for key in _LOCAL_BIN_IDENTITY_KEYS if isinstance(value := local_bin.get(key), str)}
    bin_target = local_bin.get("bin_target")
    if isinstance(bin_target, dict):
        # A ``.bin`` shim only launches this script, so it binds the grant too.
        evidence["bin_target_content_hash"] = str(bin_target.get("content_hash") or "")
    local_bin_source = {
        "source": "runner_local_bin",
        "name": name,
        "package_name": invocation.package_name,
        "local_bin": evidence,
    }
    identity = native_local_cli_identity(local_bin_source)
    if identity is None:
        return None
    return UnlistedCliIdentity(
        cli_id=identity["cli_id"],
        name=name,
        kind="executable",
        identity_hash=identity["identity_hash"],
        example_label=name,
        source_path=_nonempty_string(local_bin.get("resolved_path")),
        path_class="project-tool" if invocation.direct_dependency else "package-store",
        runner=invocation.runner,
        identity_source=local_bin_source,
    )


def _looks_like_script_kind(kind: str, status: str) -> bool:
    if status != "verified":
        return False
    if kind in _PACKAGE_SCRIPT_KINDS or kind in _INLINE_KINDS:
        return False
    return kind.endswith("-script") or kind == "direct-script"


def _is_interpreter_name(name: str) -> bool:
    base = name.lower()
    if base.endswith(".exe") or base.endswith(".cmd"):
        base = base.rsplit(".", 1)[0]
    if base in _INTERPRETER_NAMES:
        return True
    return base.startswith("python3.")


def _example_label(interpreter_name: str | None, script_name: str) -> str:
    if interpreter_name:
        return f"{interpreter_name} {script_name}"
    return script_name


def _nonempty_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _normalize_tool_name(name: str) -> str:
    base = name.strip().lower()
    if base.endswith(".exe") or base.endswith(".cmd"):
        return base.rsplit(".", 1)[0]
    return base


def local_cli_recognition_candidates(command_text: str, *, cwd: Path, home_dir: Path) -> tuple[str, ...]:
    """Return pasted-command variants Guard can bind to a single file."""

    return _recognition_candidates(command_text, cwd=cwd, home_dir=home_dir)


def _recognition_candidates(command_text: str, *, cwd: Path, home_dir: Path) -> tuple[str, ...]:
    expanded = command_text.replace("~/", f"{home_dir}/")
    candidates = [expanded]
    path = Path(expanded).expanduser()
    if not path.is_absolute():
        path = cwd / path
    try:
        resolved = path.resolve()
    except OSError:
        return tuple(candidates)
    if resolved.is_file():
        quoted = shlex.quote(str(resolved))
        launcher = _SCRIPT_LAUNCHERS.get(resolved.suffix.lower())
        if launcher is not None:
            candidates.append(f"{launcher} {quoted}")
        else:
            candidates.append(quoted)
    return tuple(dict.fromkeys(candidates))


def _first_executable_name(command_text: str, *, cwd: Path, home_dir: Path) -> str | None:
    try:
        model = parse_shell_command(command_text, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    if not model.segments:
        return None
    return executable_name(model.segments[0].executable)

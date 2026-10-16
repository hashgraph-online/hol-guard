"""Discover package.json scripts as a custom extension catalog.

The native runtime parses the pasted command, finds and reads the
package.json, and derives the catalog and grant identity. Python only shapes
the answer for enrollment. A failed or malformed native answer is reported to
``track_local_cli_identity_failures`` so grant callers fail closed instead of
treating the command as "not a package script".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..native_context import _is_sha256_digest, _resolve_digest_home, native_context_digest
from ..native_local_cli_identity import (
    LocalCliIdentityUnavailableError,
    record_local_cli_identity_failure,
    track_local_cli_identity_failures,
    valid_local_cli_identity,
)
from .local_cli_commands import LocalCliCommand, merge_discovered_commands
from .local_cli_identity import UnlistedCliIdentity

_MANAGERS = ("npm", "pnpm", "yarn", "bun")
_MAX_WALK = 8
_RESULT_KEYS = frozenset(
    {
        "manifest_path",
        "runner",
        "focused_script",
        "focused_listed",
        "source",
        "identity",
        "commands",
        "command_tokens",
    }
)
_SOURCE_KEYS = frozenset({"source", "manifest_path", "content_sha256", "package_name"})
_COMMAND_KEYS = frozenset({"command_id", "name", "usage", "description", "parent_id"})


@dataclass(frozen=True, slots=True)
class PackageJsonScriptsDiscovery:
    """One package.json script catalog ready for custom-extension enrollment."""

    identity: UnlistedCliIdentity
    commands: tuple[LocalCliCommand, ...]
    summary: str
    runner: str
    focused_script: str | None


@dataclass(frozen=True, slots=True)
class _NativeScripts:
    identity: UnlistedCliIdentity | None
    commands: tuple[LocalCliCommand, ...]
    command_tokens: tuple[str, ...]
    runner: str
    focused_script: str | None
    focused_listed: bool


def recognize_package_json_scripts(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path,
) -> PackageJsonScriptsDiscovery | None:
    """Return a script catalog when the paste is npm/pnpm/yarn/bun run or a project path."""

    found = _native_package_scripts(command_text, cwd=cwd, home_dir=home_dir)
    if found is None or not found.commands or found.identity is None:
        return None
    runner = found.runner
    commands = merge_discovered_commands(f"{runner} run", found.commands)
    count = max(0, len(commands) - 2)
    focus_note = f" {found.focused_script} is listed first." if found.focused_listed else ""
    summary = (
        f"Guard found {count} scripts in {found.identity.name}. "
        f"Recommended keeps the usual review. Allow or block each {runner} run script."
        f"{focus_note}"
    )
    return PackageJsonScriptsDiscovery(
        identity=found.identity,
        commands=commands,
        summary=summary,
        runner=runner,
        focused_script=found.focused_script,
    )


def identify_package_json_scripts(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> UnlistedCliIdentity | None:
    """Return the package.json identity for a live npm/pnpm/yarn/bun run command."""

    found = _native_package_scripts(command_text, cwd=cwd, home_dir=home_dir or cwd)
    return None if found is None else found.identity


def package_script_command_tokens(command_text: str, *, cwd: Path, home_dir: Path | None) -> tuple[str, ...] | None:
    """Return colon-nested tokens for one package script name.

    ``None`` means the command is not a package script. A failed or malformed
    native answer raises ``LocalCliIdentityUnavailableError`` instead, so a
    grant decision is never made against generic argv tokens.
    """

    with track_local_cli_identity_failures() as failures:
        found = _native_package_scripts(command_text, cwd=cwd, home_dir=home_dir or cwd)
    if failures:
        record_local_cli_identity_failure(failures[0])
        raise LocalCliIdentityUnavailableError(failures[0])
    return None if found is None else found.command_tokens


def find_nearest_package_json(start: Path, *, home_dir: Path | None = None) -> Path | None:
    current = start.resolve()
    home = home_dir.resolve() if home_dir is not None else None
    for _ in range(_MAX_WALK):
        candidate = current / "package.json"
        if candidate.is_file():
            return candidate
        if home is not None and current == home:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent
    return None


def looks_like_package_script_paste(command_text: str) -> bool:
    stripped = command_text.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if lowered == "package.json" or lowered.endswith("/package.json"):
        return True
    first = stripped.split(None, 1)[0].lower()
    return first in _MANAGERS


def _native_package_scripts(command_text: str, *, cwd: Path, home_dir: Path) -> _NativeScripts | None:
    result = native_context_digest(
        "package_json_scripts",
        {"command_text": command_text, "cwd": str(cwd), "home_dir": str(home_dir)},
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        record_local_cli_identity_failure("native_package_json_scripts_unavailable")
        return None
    if "package_json_scripts" not in result:
        return None
    found = _parse_native_scripts(result["package_json_scripts"])
    if found is None:
        record_local_cli_identity_failure("native_package_json_scripts_malformed")
    return found


def _parse_native_scripts(payload: object) -> _NativeScripts | None:
    if not isinstance(payload, dict) or set(payload) != _RESULT_KEYS:
        return None
    manifest_path = payload["manifest_path"]
    runner = payload["runner"]
    focused = payload["focused_script"]
    focused_listed = payload["focused_listed"]
    source = payload["source"]
    raw_identity = payload["identity"]
    raw_commands = payload["commands"]
    raw_tokens = payload["command_tokens"]
    if (
        not isinstance(manifest_path, str)
        or runner not in _MANAGERS
        or (focused is not None and not isinstance(focused, str))
        or not isinstance(focused_listed, bool)
        or not _valid_source(source)
        or (raw_identity is not None and not valid_local_cli_identity(raw_identity))
        or not isinstance(raw_commands, list)
        or not isinstance(raw_tokens, list)
        or any(not isinstance(token, str) for token in raw_tokens)
    ):
        return None
    commands: list[LocalCliCommand] = []
    for raw in raw_commands:
        command = _parse_command(raw)
        if command is None:
            return None
        commands.append(command)
    identity = None
    if raw_identity is not None:
        identity = UnlistedCliIdentity(
            cli_id=raw_identity["cli_id"],
            name=raw_identity["name"],
            kind="script",
            identity_hash=raw_identity["identity_hash"],
            example_label=f"{runner} run",
            interpreter_name=runner,
            source_path=manifest_path,
            identity_source=source,
        )
    return _NativeScripts(
        identity=identity,
        commands=tuple(commands),
        command_tokens=tuple(raw_tokens),
        runner=runner,
        focused_script=focused,
        focused_listed=focused_listed,
    )


def _valid_source(source: object) -> bool:
    return (
        isinstance(source, dict)
        and set(source) == _SOURCE_KEYS
        and source["source"] == "package_json"
        and all(isinstance(source[key], str) for key in _SOURCE_KEYS)
        and _is_sha256_digest(source["content_sha256"])
    )


def _parse_command(raw: Any) -> LocalCliCommand | None:
    if not isinstance(raw, dict) or set(raw) != _COMMAND_KEYS:
        return None
    parent_id = raw["parent_id"]
    texts = (raw["command_id"], raw["name"], raw["usage"], raw["description"])
    if any(not isinstance(text, str) for text in texts) or (parent_id is not None and not isinstance(parent_id, str)):
        return None
    return LocalCliCommand(
        command_id=raw["command_id"],
        name=raw["name"],
        usage=raw["usage"],
        description=raw["description"],
        parent_id=parent_id,
    )

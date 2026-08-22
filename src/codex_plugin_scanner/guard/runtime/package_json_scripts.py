"""Discover package.json scripts as a custom extension catalog."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .command_model import parse_shell_command
from .command_tokens import executable_name
from .local_cli_commands import (
    OTHER_COMMAND_ID,
    ROOT_COMMAND_ID,
    LocalCliCommand,
    merge_discovered_commands,
)
from .local_cli_identity import UnlistedCliIdentity, unlisted_cli_invocation_is_safe

_PACKAGE_SCRIPT_SURFACE = "package-scripts"
_MANAGERS = ("npm", "pnpm", "yarn", "bun")
_NPM_SHORTHAND = frozenset({"start", "test", "stop", "restart"})
_RUN_TOKENS = frozenset({"run", "run-script"})
_LIFECYCLE = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "preuninstall",
        "uninstall",
        "postuninstall",
        "prepublish",
        "prepare",
        "preprepare",
        "postprepare",
        "prepack",
        "postpack",
        "preversion",
        "version",
        "postversion",
    }
)
_COMMAND_PART = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,40}$")
_MAX_JSON_BYTES = 1_048_576
_MAX_WALK = 8
_MAX_SCRIPTS = 78
_PREFIX_FLAGS = {
    "npm": frozenset({"--prefix", "-C"}),
    "pnpm": frozenset({"--dir", "-C", "--workspace-dir"}),
    "yarn": frozenset({"--cwd"}),
    "bun": frozenset({"--cwd"}),
}
_LOCKFILES = (
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("bun.lock", "bun"),
    ("bun.lockb", "bun"),
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
)


@dataclass(frozen=True, slots=True)
class PackageJsonScriptsDiscovery:
    """One package.json script catalog ready for custom-extension enrollment."""

    identity: UnlistedCliIdentity
    commands: tuple[LocalCliCommand, ...]
    summary: str
    runner: str
    focused_script: str | None


def recognize_package_json_scripts(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path,
) -> PackageJsonScriptsDiscovery | None:
    """Return a script catalog when the paste is npm/pnpm/yarn/bun run or a project path."""

    invocation = parse_package_script_invocation(command_text, cwd=cwd, home_dir=home_dir)
    if invocation is None:
        return None
    manifest_path, runner, focused = invocation
    scripts = _read_scripts(manifest_path)
    if not scripts:
        return None
    identity = identity_for_package_json(manifest_path, runner=runner)
    commands = commands_from_package_scripts(scripts, runner=runner, focused_script=focused)
    project = identity.name
    count = max(0, len(commands) - 2)
    focus_note = f" {focused} is listed first." if focused and focused in scripts else ""
    summary = (
        f"Guard found {count} scripts in {project}. "
        f"Recommended keeps the usual review. Allow or block each {runner} run script."
        f"{focus_note}"
    )
    return PackageJsonScriptsDiscovery(
        identity=identity,
        commands=commands,
        summary=summary,
        runner=runner,
        focused_script=focused,
    )


def identify_package_json_scripts(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> UnlistedCliIdentity | None:
    """Return the package.json identity for a live npm/pnpm/yarn/bun run command."""

    home = home_dir or cwd
    invocation = parse_package_script_invocation(command_text, cwd=cwd, home_dir=home)
    if invocation is None:
        return None
    manifest_path, runner, _focused = invocation
    return identity_for_package_json(manifest_path, runner=runner)


def package_script_command_tokens(command_text: str, *, cwd: Path, home_dir: Path | None) -> tuple[str, ...] | None:
    """Return colon-nested tokens for one package script name."""

    home = home_dir or cwd
    invocation = parse_package_script_invocation(command_text, cwd=cwd, home_dir=home)
    if invocation is None:
        return None
    _manifest, _runner, focused = invocation
    if not focused:
        return ()
    command_id = command_id_for_script(focused)
    if command_id == OTHER_COMMAND_ID:
        return ()
    return tuple(command_id.split("."))


def parse_package_script_invocation(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path,
) -> tuple[Path, str, str | None] | None:
    """Return (package.json path, runner, focused script) or None."""

    stripped = command_text.strip()
    if not stripped:
        return None
    path_hit = _manifest_from_path(stripped, cwd=cwd, home_dir=home_dir)
    if path_hit is not None:
        return path_hit, detect_package_runner(path_hit.parent), None
    try:
        model = parse_shell_command(stripped, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    if not unlisted_cli_invocation_is_safe(model):
        return None
    segment = model.segments[0]
    manager = executable_name(segment.executable)
    if manager is None:
        return None
    normalized = manager.lower()
    if normalized.endswith(".cmd") or normalized.endswith(".exe"):
        normalized = normalized.rsplit(".", 1)[0]
    if normalized not in _MANAGERS:
        return None
    prefix, remainder = _strip_manager_options(normalized, list(segment.arguments))
    search_root = (cwd / prefix).resolve() if prefix is not None else cwd.resolve()
    if not search_root.is_dir():
        return None
    manifest = find_nearest_package_json(search_root, home_dir=home_dir)
    if manifest is None:
        return None
    runner = detect_package_runner(manifest.parent)
    if not remainder:
        return None
    focused = _focused_script_name(normalized, remainder)
    if focused is None and remainder[0] not in _RUN_TOKENS:
        return None
    return manifest, runner, focused


def identity_for_package_json(manifest_path: Path, *, runner: str) -> UnlistedCliIdentity:
    payload, digest = _read_package_payload(manifest_path)
    package_name = _package_name(payload, manifest_path.parent)
    path_fingerprint = hashlib.sha256(str(manifest_path.resolve()).encode("utf-8")).hexdigest()
    compact = re.sub(r"[^a-z0-9]", "", package_name.lower())[:16] or "app"
    identity_hash = hashlib.sha256(
        json.dumps(
            {
                "kind": _PACKAGE_SCRIPT_SURFACE,
                "content_sha256": digest,
                "path_fingerprint": path_fingerprint,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return UnlistedCliIdentity(
        cli_id=f"local-cli.pkg-{compact}-{path_fingerprint[:8]}",
        name=package_name[:120],
        kind="script",
        identity_hash=identity_hash,
        example_label=f"{runner} run",
        interpreter_name=runner,
        source_path=str(manifest_path),
    )


def commands_from_package_scripts(
    scripts: dict[str, str],
    *,
    runner: str,
    focused_script: str | None,
) -> tuple[LocalCliCommand, ...]:
    names = _ordered_script_names(scripts, focused_script=focused_script)
    discovered: list[LocalCliCommand] = []
    seen: set[str] = {ROOT_COMMAND_ID, OTHER_COMMAND_ID}
    for name in names:
        command_id = command_id_for_script(name)
        if command_id in seen:
            continue
        parent_id = parent_command_id(name)
        body = " ".join(scripts[name].split())
        discovered.append(
            LocalCliCommand(
                command_id=command_id,
                name=name,
                usage=f"{runner} run {name}",
                description=body[:240],
                parent_id=parent_id,
            )
        )
        seen.add(command_id)
        if len(discovered) >= _MAX_SCRIPTS:
            break
    root_label = f"{runner} run"
    return merge_discovered_commands(root_label, discovered)


def command_id_for_script(script_name: str) -> str:
    parts = command_id_parts(script_name)
    if parts:
        candidate = ".".join(parts)
        if candidate not in {ROOT_COMMAND_ID, OTHER_COMMAND_ID}:
            return candidate
    digest = hashlib.sha256(script_name.encode("utf-8")).hexdigest()[:8]
    compact = "".join(ch.lower() if ch.isalnum() else "-" for ch in script_name).strip("-")
    base = (compact or "script")[:31]
    candidate = f"{base}-{digest}"
    if candidate in {ROOT_COMMAND_ID, OTHER_COMMAND_ID} or not _COMMAND_PART.fullmatch(candidate.split(".", 1)[0]):
        return f"script-{digest}"
    return candidate


def command_id_parts(script_name: str) -> tuple[str, ...]:
    raw_parts = script_name.split(":")
    if any(part == "" for part in raw_parts):
        return ()
    parts = raw_parts
    if not parts or len(parts) > 4:
        return ()
    if not all(_COMMAND_PART.fullmatch(part) for part in parts):
        return ()
    return tuple(parts)


def parent_command_id(script_name: str) -> str | None:
    parts = command_id_parts(script_name)
    if len(parts) < 2:
        return None
    return ".".join(parts[:-1])


def detect_package_runner(directory: Path) -> str:
    for filename, runner in _LOCKFILES:
        if (directory / filename).is_file():
            return runner
    return "npm"


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


def _focused_script_name(manager: str, remainder: list[str]) -> str | None:
    if not remainder:
        return None
    head = remainder[0]
    if head in _RUN_TOKENS:
        if len(remainder) == 1:
            return None
        return remainder[1]
    if manager == "npm" and head in _NPM_SHORTHAND:
        return head
    return None


def _strip_manager_options(manager: str, args: list[str]) -> tuple[Path | None, list[str]]:
    prefix: Path | None = None
    flags = _PREFIX_FLAGS[manager]
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        assigned = _assigned_prefix(token, flags)
        if assigned is not None:
            prefix = Path(assigned)
            index += 1
            continue
        if token in flags and index + 1 < len(args):
            prefix = Path(args[index + 1])
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return prefix, args[index:]


def _assigned_prefix(token: str, flags: frozenset[str]) -> str | None:
    for flag in flags:
        prefix = f"{flag}="
        if token.startswith(prefix) and len(token) > len(prefix):
            return token[len(prefix) :]
    return None


def _manifest_from_path(command_text: str, *, cwd: Path, home_dir: Path) -> Path | None:
    expanded = command_text.replace("~/", f"{home_dir}/")
    path = Path(expanded).expanduser()
    if not path.is_absolute():
        path = cwd / path
    try:
        resolved = path.resolve()
    except OSError:
        return None
    if resolved.is_file() and resolved.name == "package.json":
        return resolved
    if resolved.is_dir() and (resolved / "package.json").is_file():
        return resolved / "package.json"
    return None


def _read_scripts(manifest_path: Path) -> dict[str, str]:
    payload, _digest = _read_package_payload(manifest_path)
    raw = payload.get("scripts")
    if not isinstance(raw, dict):
        return {}
    scripts: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(value, str):
            continue
        name = key.strip()
        if name in _LIFECYCLE:
            continue
        scripts[name] = value
    return {name: body for name, body in scripts.items() if not _is_pre_post_script(name, scripts)}


def _read_package_payload(manifest_path: Path) -> tuple[dict[str, object], str]:
    try:
        data = manifest_path.read_bytes()
    except OSError:
        return {}, hashlib.sha256(b"").hexdigest()
    if len(data) > _MAX_JSON_BYTES:
        return {}, hashlib.sha256(data).hexdigest()
    digest = hashlib.sha256(data).hexdigest()
    try:
        payload = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {}, digest
    if not isinstance(payload, dict):
        return {}, digest
    return payload, digest


def _package_name(payload: dict[str, object], directory: Path) -> str:
    raw = payload.get("name")
    if isinstance(raw, str) and raw.strip():
        return raw.strip().lstrip("@").replace("/", "-")
    return directory.name or "package"


def _is_pre_post_script(name: str, scripts: dict[str, str]) -> bool:
    return any(name.startswith(prefix) and name[len(prefix) :] in scripts for prefix in ("pre", "post"))


def _ordered_script_names(scripts: dict[str, str], *, focused_script: str | None) -> list[str]:
    names = list(scripts)

    def sort_key(name: str) -> tuple[int, int, str]:
        related = focused_script is not None and (
            name == focused_script or name.startswith(f"{focused_script}:") or focused_script.startswith(f"{name}:")
        )
        focused = 0 if related else 1
        nested = 0 if ":" in name else 1
        return (focused, nested, name)

    names.sort(key=sort_key)
    return names

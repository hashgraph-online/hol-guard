"""Identity proofs for read-only git commands and no-command file tools.

``hook_native_saved_approval`` binds an exact-action "Always" decision to a
token. The helpers here prove two more shapes are stable enough to persist:

* a read-only git subcommand, bound to every config file git would read, since
  ``git`` can run helpers (fsmonitor, textconv, external diff, pager) that those
  files define;
* a read-style file tool (``read``, ``glob``, ``grep``), bound to its canonical
  target paths and refused when a target looks sensitive.

Each helper raises ``OnceOnlyError`` with a stable reason code when the action must
stay a one-time allow. The same codes reach the dashboard as ``once_only_reason``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..runtime.secret_sensitivity import classify_secret_path
from .hook_request_parsing import pre_tool_input

NO_COMMAND_IDENTITY = "no_command_identity"
MUTABLE_LAUNCHER = "mutable_launcher"
COMPOUND_COMMAND = "compound_command"
GUARD_CONTROL = "guard_control"
PACKAGE_ACTION = "package_action"
NON_OVERRIDABLE = "non_overridable"
UNPROVEN_LAUNCH = "unproven_launch"
SENSITIVE_PATH = "sensitive_path"
BROAD_SCOPE = "broad_scope"
DESTRUCTIVE_COMMAND = "destructive_command"

ONCE_ONLY_REASONS = frozenset(
    {
        NO_COMMAND_IDENTITY,
        MUTABLE_LAUNCHER,
        COMPOUND_COMMAND,
        GUARD_CONTROL,
        PACKAGE_ACTION,
        NON_OVERRIDABLE,
        UNPROVEN_LAUNCH,
        SENSITIVE_PATH,
        BROAD_SCOPE,
        DESTRUCTIVE_COMMAND,
    }
)

_MAX_CONFIG_BYTES = 1_048_576
_MAX_CONFIG_FILES = 24
_MAX_INCLUDE_DEPTH = 3
_GLOBAL_OPTIONS = frozenset({"--no-pager", "--no-optional-locks"})
_READ_SUBCOMMANDS = frozenset({"status", "log", "diff", "show", "rev-parse", "ls-files"})
# Options that write files, name helper programs, or redirect git's own lookup.
_FORBIDDEN_PREFIXES = (
    "--output",
    "--exec-path",
    "--git-dir",
    "--work-tree",
    "--config",
    "--upload-pack",
    "--receive-pack",
    "--open-files-in-pager",
    "--paginate",
    "--ext-diff",
    "--textconv",
    "--namespace",
    "--super-prefix",
    "-O",
)
_BRANCH_FLAGS = frozenset(
    {"-a", "-r", "-v", "-vv", "--all", "--remotes", "--verbose", "--list", "--show-current", "--no-color", "--color"}
)
_WORKTREE_LIST_FLAGS = frozenset({"--porcelain", "-v", "--verbose"})
_INCLUDE_SECTION = re.compile(r"^\s*\[\s*include(?:if)?\b", re.IGNORECASE)
_ANY_SECTION = re.compile(r"^\s*\[")
_INCLUDE_PATH = re.compile(r"^\s*path\s*=\s*(.+?)\s*$", re.IGNORECASE)

_FILE_READ_TOOLS = frozenset({"read", "read_file", "view"})
_FILE_SEARCH_TOOLS = frozenset({"glob", "grep", "ls", "list_dir"})
_PATH_KEYS = frozenset({"path", "file_path", "filePath", "directory", "dir"})
_PATTERN_KEYS = frozenset({"pattern", "glob", "include"})
_OPTION_KEYS = frozenset(
    {"limit", "offset", "type", "output_mode", "head_limit", "case_sensitive", "multiline", "context", "-i", "-n"}
    | {"-A", "-B", "-C", "line_start", "line_end", "lines"}
)


class OnceOnlyError(Exception):
    """The action cannot carry a persistent exact-action decision."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def git_readonly_identity(arguments: Sequence[str], *, cwd: Path, home_dir: Path | None) -> dict[str, object]:
    """Return a config-bound identity for an allowlisted read-only git command."""

    args = list(arguments)
    target = cwd
    index = 0
    changed_dir = False
    while index < len(args) and args[index].startswith("-"):
        option = args[index]
        if option in _GLOBAL_OPTIONS:
            index += 1
        elif option == "-C" and not changed_dir and index + 1 < len(args) and not args[index + 1].startswith("-"):
            target = _directory(args[index + 1], cwd)
            changed_dir = True
            index += 2
        else:
            # -c, --exec-path, --git-dir, --work-tree, -p and unknown options.
            raise OnceOnlyError(MUTABLE_LAUNCHER)
    if index >= len(args):
        raise OnceOnlyError(MUTABLE_LAUNCHER)
    subcommand, rest = args[index], args[index + 1 :]
    if not _subcommand_is_read_only(subcommand, rest):
        raise OnceOnlyError(MUTABLE_LAUNCHER)
    root, git_dir, common_dir = _repository(target)
    return {
        "kind": "git-readonly",
        "subcommand": subcommand,
        "target": str(target),
        "repository": str(root),
        "config_digest": _git_config_digest(root, git_dir, common_dir, home_dir),
    }


def _subcommand_is_read_only(subcommand: str, rest: list[str]) -> bool:
    if any(argument.startswith(_FORBIDDEN_PREFIXES) or argument == "-c" for argument in rest):
        return False
    if subcommand in _READ_SUBCOMMANDS:
        return True
    if subcommand == "branch":
        flags = [argument for argument in rest if argument.startswith("-")]
        positionals = [argument for argument in rest if not argument.startswith("-")]
        return all(flag in _BRANCH_FLAGS for flag in flags) and (not positionals or "--list" in flags)
    if subcommand == "remote":
        return rest in ([], ["-v"], ["--verbose"])
    if subcommand == "worktree":
        return bool(rest) and rest[0] == "list" and all(flag in _WORKTREE_LIST_FLAGS for flag in rest[1:])
    return False


def _directory(value: str, cwd: Path) -> Path:
    candidate = Path(value)
    try:
        resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve(strict=True)
    except OSError as error:
        raise OnceOnlyError(UNPROVEN_LAUNCH) from error
    if not resolved.is_dir():
        raise OnceOnlyError(UNPROVEN_LAUNCH)
    return resolved


def _repository(start: Path) -> tuple[Path, Path, Path]:
    for directory in (start, *start.parents):
        marker = directory / ".git"
        try:
            if marker.is_dir():
                return directory, marker, marker
            if marker.is_file():
                text = marker.read_text(encoding="utf-8", errors="replace").strip()
                if not text.startswith("gitdir:"):
                    raise OnceOnlyError(UNPROVEN_LAUNCH)
                git_dir = (directory / text.removeprefix("gitdir:").strip()).resolve(strict=True)
                common = git_dir
                pointer = git_dir / "commondir"
                if pointer.is_file():
                    common = (git_dir / pointer.read_text(encoding="utf-8").strip()).resolve(strict=True)
                return directory, git_dir, common
        except OSError as error:
            raise OnceOnlyError(UNPROVEN_LAUNCH) from error
    raise OnceOnlyError(UNPROVEN_LAUNCH)


def _git_config_digest(root: Path, git_dir: Path, common_dir: Path, home_dir: Path | None) -> str:
    """Digest every file whose edit changes which helpers a read-only git runs."""

    candidates: list[Path] = [
        common_dir / "config",
        git_dir / "config",
        git_dir / "config.worktree",
        common_dir / "info" / "attributes",
        git_dir / "info" / "attributes",
        root / ".gitattributes",
        Path("/etc/gitconfig"),
    ]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    for base in ([Path(xdg)] if xdg else []) + ([home_dir / ".config"] if home_dir is not None else []):
        candidates.extend((base / "git" / "config", base / "git" / "attributes"))
    if home_dir is not None:
        candidates.append(home_dir / ".gitconfig")
    seen: dict[str, str] = {}
    queue = [(path, 0) for path in dict.fromkeys(candidates)]
    while queue:
        path, depth = queue.pop(0)
        key = str(path)
        if key in seen:
            continue
        if len(seen) >= _MAX_CONFIG_FILES:
            raise OnceOnlyError(UNPROVEN_LAUNCH)
        try:
            if not path.is_file():
                seen[key] = "absent"
                continue
            if path.stat().st_size > _MAX_CONFIG_BYTES:
                raise OnceOnlyError(UNPROVEN_LAUNCH)
            data = path.read_bytes()
        except OSError as error:
            raise OnceOnlyError(UNPROVEN_LAUNCH) from error
        seen[key] = hashlib.sha256(data).hexdigest()
        if path.name.startswith(("config", ".gitconfig")) or path.name == "gitconfig":
            for included in _included_paths(data.decode("utf-8", errors="replace"), path, home_dir):
                if depth + 1 > _MAX_INCLUDE_DEPTH:
                    raise OnceOnlyError(UNPROVEN_LAUNCH)
                queue.append((included, depth + 1))
    return hashlib.sha256(json.dumps(sorted(seen.items()), separators=(",", ":")).encode("utf-8")).hexdigest()


def _included_paths(text: str, config_path: Path, home_dir: Path | None) -> list[Path]:
    included: list[Path] = []
    in_include = False
    for line in text.splitlines():
        if _ANY_SECTION.match(line):
            in_include = bool(_INCLUDE_SECTION.match(line))
            continue
        match = _INCLUDE_PATH.match(line) if in_include else None
        if match is None:
            continue
        value = match.group(1).strip().strip('"')
        candidate = home_dir / value[2:] if value.startswith("~/") and home_dir is not None else Path(value)
        included.append(candidate if candidate.is_absolute() else config_path.parent / candidate)
    return included


def tool_target_identity(
    tool_name: str,
    payload: Mapping[str, object],
    *,
    cwd: Path,
    workspace: Path | None,
    home_dir: Path | None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Return ``(launch identity, content)`` for a read-style file tool with no command."""

    name = tool_name.strip().lower()
    is_read = name in _FILE_READ_TOOLS
    if not is_read and name not in _FILE_SEARCH_TOOLS:
        raise OnceOnlyError(NO_COMMAND_IDENTITY)
    tool_input = pre_tool_input(payload)
    if tool_input is None:
        arguments = payload.get("arguments")
        tool_input = arguments if isinstance(arguments, Mapping) else None
    if tool_input is None:
        raise OnceOnlyError(NO_COMMAND_IDENTITY)
    paths: list[str] = []
    patterns: list[str] = []
    for key, value in tool_input.items():
        if key in _PATH_KEYS and isinstance(value, str) and value.strip():
            paths.append(value)
        elif key == "paths" and isinstance(value, list) and all(isinstance(item, str) for item in value):
            paths.extend(str(item) for item in value)
        elif key in _PATTERN_KEYS and isinstance(value, str) and value.strip():
            patterns.append(value)
        elif key not in _OPTION_KEYS or not isinstance(value, (str, int, float, bool)):
            # Unknown fields could carry commands, preprocessors or destinations.
            raise OnceOnlyError(NO_COMMAND_IDENTITY)
    if is_read and (not paths or patterns):
        raise OnceOnlyError(NO_COMMAND_IDENTITY)
    if not is_read and not paths:
        paths.append(str(cwd))
    root = (workspace or cwd).resolve()
    targets: list[str] = []
    for raw in paths:
        candidate = Path(raw).expanduser() if home_dir is None else Path(_expand(raw, home_dir))
        try:
            resolved = (candidate if candidate.is_absolute() else cwd / candidate).resolve()
        except (OSError, RuntimeError) as error:
            raise OnceOnlyError(UNPROVEN_LAUNCH) from error
        if _sensitive(raw, cwd, home_dir) or _sensitive(str(resolved), cwd, home_dir):
            raise OnceOnlyError(SENSITIVE_PATH)
        if not is_read and not (resolved == root or root in resolved.parents):
            raise OnceOnlyError(BROAD_SCOPE)
        targets.append(str(resolved))
    for pattern in patterns:
        if _sensitive(pattern, cwd, home_dir):
            raise OnceOnlyError(SENSITIVE_PATH)
        if not is_read and (os.path.isabs(pattern) or ".." in Path(pattern).parts):
            raise OnceOnlyError(BROAD_SCOPE)
    identity: dict[str, object] = {"kind": "tool-target", "tool": name, "targets": sorted(targets)}
    options = {key: value for key, value in tool_input.items() if key in _OPTION_KEYS}
    content = {"patterns": sorted(patterns), "options": json.loads(json.dumps(options, sort_keys=True, default=str))}
    return identity, content


def _expand(value: str, home_dir: Path) -> str:
    return str(home_dir / value[2:]) if value.startswith("~/") else value


def _sensitive(value: str, cwd: Path, home_dir: Path | None) -> bool:
    return classify_secret_path(value, cwd=cwd, home_dir=home_dir) is not None


__all__ = [
    "BROAD_SCOPE",
    "COMPOUND_COMMAND",
    "DESTRUCTIVE_COMMAND",
    "GUARD_CONTROL",
    "MUTABLE_LAUNCHER",
    "NON_OVERRIDABLE",
    "NO_COMMAND_IDENTITY",
    "ONCE_ONLY_REASONS",
    "PACKAGE_ACTION",
    "SENSITIVE_PATH",
    "UNPROVEN_LAUNCH",
    "OnceOnlyError",
    "git_readonly_identity",
    "tool_target_identity",
]

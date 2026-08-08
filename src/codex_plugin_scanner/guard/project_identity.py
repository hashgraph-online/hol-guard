"""Portable project identity for cross-device Guard decision memory.

Project-scoped memory must not depend on where a repository is cloned on one
machine. This module derives an opaque classification from Git repository
metadata while keeping local filesystem paths out of the identity itself.
Repository-controlled metadata is not an authentication boundary; callers must
never use the identity alone to grant permissive authority.
"""

from __future__ import annotations

import configparser
import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

PORTABLE_PROJECT_IDENTITY_PREFIX = "git-project:v1:"
_GIT_CONFIG_MAX_BYTES = 1024 * 1024
_GIT_REFLOG_MAX_BYTES = 4 * 1024 * 1024
_SCP_REMOTE_PATTERN = re.compile(r"^(?:[^@/]+@)?([^:/]+):(.+)$")
_CASE_INSENSITIVE_REMOTE_PATH_HOSTS = frozenset({"github.com", "www.github.com"})
_DEFAULT_REMOTE_PORTS = {
    "git": 9418,
    "http": 80,
    "https": 443,
    "ssh": 22,
}
_CLONE_REFLOG_PREFIX = "clone: from "


def is_portable_project_identity(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(PORTABLE_PROJECT_IDENTITY_PREFIX)
        and len(value) == len(PORTABLE_PROJECT_IDENTITY_PREFIX) + 64
        and all(character in "0123456789abcdef" for character in value[-64:])
    )


def portable_project_identity_revision(workspace: str | Path | None) -> int | None:
    """Return a cache revision covering every Git metadata input to project identity."""
    workspace_path = _workspace_path(workspace)
    if workspace_path is None:
        return None
    repository = _discover_git_repository(workspace_path)
    if repository is None:
        return None
    _repository_root, config_path, provenance_logs = repository
    fingerprints: list[str] = []
    for candidate in (config_path, *provenance_logs):
        try:
            stat = candidate.stat()
        except OSError:
            continue
        fingerprints.append(f"{candidate}:{stat.st_mtime_ns}:{stat.st_size}")
    if not fingerprints:
        return None
    digest = hashlib.sha256("\n".join(fingerprints).encode()).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False)


def resolve_portable_project_identity(workspace: str | Path | None) -> str | None:
    """Return a stable opaque classification for a conventional Git project.

    The identity is stable across clone locations when the clones share the
    same canonical origin remote. The initial HEAD reflog is used only as a
    consistency signal that the configured origin matches the clone metadata;
    both files are repository-controlled and therefore do not authenticate the
    workspace. Permission-bearing callers must independently prevent portable
    identity from elevating authority. Discovery reads Git metadata directly
    and never launches a subprocess, preserving Guard's live enforcement
    block-before-subprocess invariant.

    Linked-worktree/external ``gitdir`` layouts deliberately fail closed here.
    A workspace-local ``.git`` directory is required so an unrelated workspace
    cannot point at another readable repository's metadata and inherit its
    portable selector.
    """
    workspace_path = _workspace_path(workspace)
    if workspace_path is None:
        return None

    repository = _discover_git_repository(workspace_path)
    if repository is None:
        return None
    repository_root, config_path, provenance_logs = repository
    remote = _read_origin_remote(config_path)
    anchor = _canonical_remote(remote)
    if anchor is None or _clone_remote_anchor(provenance_logs) != anchor:
        return None

    relative_workspace = _relative_workspace(workspace_path, repository_root)
    digest = hashlib.sha256(f"{anchor}\n{relative_workspace}".encode()).hexdigest()
    return f"{PORTABLE_PROJECT_IDENTITY_PREFIX}{digest}"


def resolve_project_identity_from_metadata(metadata: Mapping[str, object]) -> str | None:
    """Resolve explicit project identity first, upgrading path-like ids when possible."""
    explicit = _first_string(metadata, "project_id", "projectId")
    if explicit and not _looks_like_local_path(explicit):
        return explicit

    workspace = _first_string(metadata, "workspace_path", "workspacePath") or explicit
    portable = resolve_portable_project_identity(workspace)
    if portable is not None:
        return portable
    return explicit


def enrich_project_identity_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    """Return metadata with the canonical project identity in ``project_id``."""
    enriched = {str(key): value for key, value in metadata.items()}
    project_identity = resolve_project_identity_from_metadata(metadata)
    if project_identity is not None:
        enriched["project_id"] = project_identity
    return enriched


def _workspace_path(workspace: str | Path | None) -> Path | None:
    if isinstance(workspace, Path):
        return workspace.expanduser().resolve(strict=False)
    if not isinstance(workspace, str) or not workspace.strip():
        return None
    return Path(workspace.strip()).expanduser().resolve(strict=False)


def _metadata_file_is_workspace_local(git_dir: Path, candidate: Path) -> bool:
    """Require Git identity inputs to be regular files beneath a non-symlink path."""
    try:
        relative = candidate.relative_to(git_dir)
    except ValueError:
        return False

    current = git_dir
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            return False
    return not candidate.is_symlink() and candidate.is_file()


def _discover_git_repository(workspace: Path) -> tuple[Path, Path, tuple[Path, ...]] | None:
    current = workspace if workspace.is_dir() else workspace.parent
    for repository_root in (current, *current.parents):
        marker = repository_root / ".git"
        if marker.is_file() or marker.is_symlink():
            # A gitdir pointer or symlink can target metadata owned by an
            # unrelated workspace. Portable identity is optional, so fail
            # closed rather than treating external Git metadata as authority.
            return None
        if not marker.is_dir():
            continue
        config_path = marker / "config"
        head_log_path = marker / "logs" / "HEAD"
        if not _metadata_file_is_workspace_local(marker, config_path):
            return None
        if not _metadata_file_is_workspace_local(marker, head_log_path):
            return None
        return repository_root, config_path, (head_log_path,)
    return None


def _read_origin_remote(config_path: Path) -> str | None:
    try:
        if config_path.stat().st_size > _GIT_CONFIG_MAX_BYTES:
            return None
        content = config_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None

    parser = configparser.RawConfigParser(interpolation=None, strict=False, allow_no_value=True)
    try:
        parser.read_string(content)
    except configparser.Error:
        return None
    value = parser.get('remote "origin"', "url", fallback=None)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _clone_remote_anchor(log_paths: tuple[Path, ...]) -> str | None:
    """Return the canonical remote recorded by Git's initial clone reflog entry."""
    for log_path in log_paths:
        try:
            if log_path.stat().st_size > _GIT_REFLOG_MAX_BYTES:
                continue
            content = log_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for line in content.splitlines():
            metadata, separator, message = line.partition("\t")
            if not separator or not message.startswith(_CLONE_REFLOG_PREFIX):
                continue
            fields = metadata.split()
            if len(fields) < 2:
                continue
            previous_oid = fields[0]
            if not previous_oid or set(previous_oid) != {"0"}:
                continue
            clone_remote = message[len(_CLONE_REFLOG_PREFIX) :].strip()
            anchor = _canonical_remote(clone_remote)
            if anchor is not None:
                return anchor
    return None


def _canonical_remote(remote: str | None) -> str | None:
    if not isinstance(remote, str) or not remote.strip():
        return None
    value = remote.strip()
    host: str | None = None
    path_case_host: str | None = None
    path: str | None = None

    if "://" in value:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme == "file" or not parsed.hostname:
            return None
        hostname = parsed.hostname.lower()
        path_case_host = hostname
        host = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parsed.port
        except ValueError:
            return None
        if port is not None and port != _DEFAULT_REMOTE_PORTS.get(scheme):
            host = f"{host}:{port}"
        path = parsed.path
    else:
        match = _SCP_REMOTE_PATTERN.match(value)
        if match:
            host = match.group(1).lower()
            path_case_host = host
            path = match.group(2)

    if not host or not path or not path_case_host:
        return None
    normalized_path = path.strip().strip("/")
    if normalized_path.lower().endswith(".git"):
        normalized_path = normalized_path[:-4]
    if path_case_host in _CASE_INSENSITIVE_REMOTE_PATH_HOSTS or path_case_host.endswith(".ghe.com"):
        normalized_path = normalized_path.lower()
    if not normalized_path:
        return None
    return f"remote:{host}/{normalized_path}"


def _relative_workspace(workspace: Path, repository_root: Path) -> str:
    try:
        relative = workspace.relative_to(repository_root)
    except ValueError:
        return "."
    value = relative.as_posix().strip()
    return value or "."


def _first_string(metadata: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _looks_like_local_path(value: str) -> bool:
    normalized = value.strip()
    if normalized.startswith(("/", "~/", "./", "../", "\\\\")):
        return True
    return len(normalized) >= 3 and normalized[1:3] in {":\\", ":/"}

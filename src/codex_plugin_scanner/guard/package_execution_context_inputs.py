"""Filesystem-backed inputs for package execution context identities."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .runtime.approval_context import build_runtime_launch_identity, runtime_launch_identity_is_reusable
from .runtime.workspace_path_guard import resolve_path_within_workspace

_MAX_CONFIG_FILE_BYTES = 2 * 1024 * 1024
_MAX_DEPENDENCY_FILE_BYTES = 32 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAX_CONTEXT_BYTES = 96 * 1024 * 1024
_MAX_TREE_FILES = 512
_MAX_GIT_POINTER_BYTES = 16 * 1024


@dataclass(slots=True)
class ContextFiles:
    """Read stable regular files while enforcing the context resource budget."""

    total_bytes: int = 0
    count: int = 0

    def read(self, path: Path, *, maximum_bytes: int, allow_symlink: bool = False) -> bytes:
        descriptor: int | None = None
        try:
            if path.is_symlink() and not allow_symlink:
                raise ContextUnavailableError("symlinked_configuration")
            resolved = path.resolve(strict=True) if allow_symlink else path
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(resolved, flags)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ContextUnavailableError("unsupported_configuration")
            if before.st_size > maximum_bytes or self.total_bytes + before.st_size > _MAX_CONTEXT_BYTES:
                raise ContextUnavailableError("oversized_configuration")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining > 0:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        except ContextUnavailableError:
            raise
        except (OSError, RuntimeError):
            raise ContextUnavailableError("unreadable_configuration") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        stable_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        final_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if len(payload) != before.st_size or stable_identity != final_identity:
            raise ContextUnavailableError("configuration_changed_during_review")
        self.total_bytes += len(payload)
        self.count += 1
        if self.count > _MAX_TREE_FILES:
            raise ContextUnavailableError("oversized_configuration")
        return payload


class ContextUnavailableError(RuntimeError):
    """Signal that a complete, portable context cannot be proven."""

    reason: str

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def repository_material(
    workspace: Path,
    *,
    files: ContextFiles,
) -> tuple[Path | None, dict[str, object], str | None]:
    for candidate_root in (workspace, *workspace.parents):
        marker = candidate_root / ".git"
        if not marker.exists():
            continue
        try:
            git_dir = _resolve_git_dir(marker, files=files)
            common_dir = _resolve_git_common_dir(git_dir, files=files)
            remotes = _git_remote_urls(common_dir / "config", files=files)
        except ContextUnavailableError as error:
            return None, {"workspace_path": str(workspace)}, error.reason
        return (
            candidate_root,
            {
                "common_git_dir": str(common_dir),
                "remote_urls": list(remotes),
            },
            None,
        )
    return None, {"workspace_path": str(workspace)}, "repository_identity_unavailable"


def _resolve_git_dir(marker: Path, *, files: ContextFiles) -> Path:
    if marker.is_dir():
        return marker.resolve()
    payload = files.read(marker, maximum_bytes=_MAX_GIT_POINTER_BYTES)
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ContextUnavailableError("repository_identity_unavailable") from None
    if not text.startswith("gitdir:"):
        raise ContextUnavailableError("repository_identity_unavailable")
    raw_path = text.partition(":")[2].strip()
    if not raw_path:
        raise ContextUnavailableError("repository_identity_unavailable")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = marker.parent / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise ContextUnavailableError("repository_identity_unavailable") from None
    if not resolved.is_dir():
        raise ContextUnavailableError("repository_identity_unavailable")
    return resolved


def _resolve_git_common_dir(git_dir: Path, *, files: ContextFiles) -> Path:
    marker = git_dir / "commondir"
    if not marker.exists():
        return git_dir.resolve()
    payload = files.read(marker, maximum_bytes=_MAX_GIT_POINTER_BYTES)
    try:
        raw_path = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ContextUnavailableError("repository_identity_unavailable") from None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = git_dir / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise ContextUnavailableError("repository_identity_unavailable") from None
    if not resolved.is_dir():
        raise ContextUnavailableError("repository_identity_unavailable")
    return resolved


def _git_remote_urls(config_path: Path, *, files: ContextFiles) -> tuple[str, ...]:
    if not config_path.exists():
        return ()
    payload = files.read(config_path, maximum_bytes=_MAX_CONFIG_FILE_BYTES)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ContextUnavailableError("repository_identity_unavailable") from None
    in_remote = False
    urls: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_remote = stripped.lower().startswith('[remote "')
            continue
        if not in_remote or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip().lower() == "url" and value.strip():
            urls.append(value.strip())
    return tuple(sorted(dict.fromkeys(urls)))


def workspace_material(workspace: Path, repository_root: Path | None, *, portable: bool) -> dict[str, object]:
    if portable and repository_root is not None:
        try:
            relative = workspace.relative_to(repository_root).as_posix() or "."
        except ValueError:
            relative = str(workspace)
        return {"repository_relative_path": relative}
    return {"exact_path": str(workspace)}


def executable_material(
    *,
    workspace: Path,
    repository_root: Path | None,
    manager: str,
    executable: str | None,
    arguments: Sequence[str] = (),
    environment: Mapping[str, str],
    files: ContextFiles,
) -> tuple[dict[str, object], str | None]:
    requested = executable or manager
    if not requested or requested == "unknown" or any(token in requested for token in (";", "&&", "||", "|")):
        return {"manager": manager, "status": "unavailable"}, "package_manager_executable_unavailable"
    candidate: Path | None
    if "/" in requested or "\\" in requested:
        raw_path = Path(requested).expanduser()
        candidate = raw_path if raw_path.is_absolute() else workspace / raw_path
        try:
            candidate = candidate.resolve(strict=True)
        except OSError:
            candidate = None
    else:
        resolved = shutil.which(requested, path=environment.get("PATH"))
        candidate = Path(resolved).resolve() if resolved is not None else None
    if candidate is None:
        return {"manager": manager, "requested": Path(requested).name, "status": "unavailable"}, (
            "package_manager_executable_unavailable"
        )
    try:
        payload = files.read(candidate, maximum_bytes=_MAX_EXECUTABLE_BYTES, allow_symlink=True)
    except ContextUnavailableError as error:
        return {"manager": manager, "requested": Path(requested).name, "status": error.reason}, error.reason
    location = _canonical_executable_location(candidate, workspace=workspace, repository_root=repository_root)
    launch_identity = build_runtime_launch_identity(
        requested,
        args=arguments,
        structured_command=True,
        direct_executable=True,
        search_path=environment.get("PATH"),
        cwd=workspace,
        launch_env=environment,
    )
    executable_identity = launch_identity.get("executable")
    if (
        not isinstance(executable_identity, Mapping)
        or executable_identity.get("status") != "verified"
        or executable_identity.get("sha256") != hashlib.sha256(payload).hexdigest()
    ):
        return {
            "manager": manager,
            "requested": Path(requested).name,
            "status": "package_manager_launch_identity_unavailable",
        }, "package_manager_launch_identity_unavailable"
    material: dict[str, object] = {
        "content_digest": hashlib.sha256(payload).hexdigest(),
        "launch_identity": _portable_launch_identity(
            launch_identity,
            workspace=workspace,
            repository_root=repository_root,
        ),
        "location": location,
        "manager": manager,
        "requested": Path(requested).name,
    }
    if not ("/" in requested or "\\" in requested):
        material["search_path_digest"] = hashlib.sha256((environment.get("PATH") or "").encode("utf-8")).hexdigest()
    if not runtime_launch_identity_is_reusable(launch_identity):
        material["status"] = "package_manager_launch_identity_unavailable"
        return material, "package_manager_launch_identity_unavailable"
    return material, None


def _canonical_executable_location(candidate: Path, *, workspace: Path, repository_root: Path | None) -> str:
    for label, root in (("workspace", workspace), ("repository", repository_root)):
        if root is None:
            continue
        try:
            return f"{label}:{candidate.relative_to(root).as_posix()}"
        except ValueError:
            continue
    return f"external:{candidate}"


def _portable_launch_identity(
    value: object,
    *,
    workspace: Path,
    repository_root: Path | None,
) -> object:
    """Normalize local absolute paths while retaining only hashed argv data."""

    if isinstance(value, Mapping):
        typed_value = cast(Mapping[object, object], value)
        normalized: dict[str, object] = {}
        for raw_key, item in typed_value.items():
            key = str(raw_key)
            if key in {"path", "launch_cwd", "command"} and isinstance(item, str):
                candidate = Path(item)
                normalized[key] = (
                    _canonical_executable_location(
                        candidate,
                        workspace=workspace,
                        repository_root=repository_root,
                    )
                    if candidate.is_absolute()
                    else item
                )
                continue
            normalized[key] = _portable_launch_identity(
                item,
                workspace=workspace,
                repository_root=repository_root,
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_portable_launch_identity(item, workspace=workspace, repository_root=repository_root) for item in value]
    return value


def dependency_material(
    *,
    workspace: Path,
    metadata: Mapping[str, object],
    files: ContextFiles,
) -> tuple[dict[str, object], str | None]:
    entries: list[dict[str, str]] = []
    failure: str | None = None
    manager = _string_value(metadata.get("package_manager")) or ""
    for kind, key in (("manifest", "manifest_paths"), ("lockfile", "lockfile_paths")):
        configured_paths = _string_items(metadata.get(key))
        inferred_paths = (
            tuple(path for path in _default_dependency_paths(manager, kind=kind) if (workspace / path).is_file())
            if not configured_paths
            else ()
        )
        for relative_path in configured_paths or inferred_paths:
            resolved = resolve_path_within_workspace(workspace, relative_path)
            if resolved is None or not resolved.exists():
                entries.append({"kind": kind, "path": relative_path, "status": "missing"})
                failure = failure or "dependency_file_unavailable"
                continue
            try:
                payload = files.read(resolved, maximum_bytes=_MAX_DEPENDENCY_FILE_BYTES)
            except ContextUnavailableError as error:
                entries.append({"kind": kind, "path": relative_path, "status": error.reason})
                failure = failure or error.reason
                continue
            entries.append(
                {
                    "digest": hashlib.sha256(payload).hexdigest(),
                    "kind": kind,
                    "path": relative_path,
                }
            )
    return {"files": entries}, failure


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _default_dependency_paths(manager: str, *, kind: str) -> tuple[str, ...]:
    normalized = manager.strip().lower()
    manifests: dict[str, tuple[str, ...]] = {
        "bun": ("package.json",),
        "bunx": ("package.json",),
        "npm": ("package.json",),
        "npx": ("package.json",),
        "pnpm": ("package.json", "pnpm-workspace.yaml"),
        "yarn": ("package.json",),
        "pip": ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"),
        "pip3": ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"),
        "poetry": ("pyproject.toml",),
        "uv": ("pyproject.toml", "requirements.txt"),
    }
    lockfiles: dict[str, tuple[str, ...]] = {
        "bun": ("bun.lock", "bun.lockb"),
        "bunx": ("bun.lock", "bun.lockb"),
        "npm": ("package-lock.json", "npm-shrinkwrap.json"),
        "npx": ("package-lock.json", "npm-shrinkwrap.json"),
        "pnpm": ("pnpm-lock.yaml",),
        "yarn": ("yarn.lock",),
        "pip": ("uv.lock", "poetry.lock", "Pipfile.lock"),
        "pip3": ("uv.lock", "poetry.lock", "Pipfile.lock"),
        "poetry": ("poetry.lock",),
        "uv": ("uv.lock",),
    }
    return (manifests if kind == "manifest" else lockfiles).get(normalized, ())


def _string_value(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = [
    "ContextFiles",
    "ContextUnavailableError",
    "dependency_material",
    "executable_material",
    "repository_material",
    "workspace_material",
]

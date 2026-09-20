"""Contain workspace-relative manifest and lockfile reads."""

from __future__ import annotations

import io
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from ..stable_digest import stable_digest_chunks

WORKSPACE_INPUT_MAX_BYTES = 8 * 1024 * 1024
WORKSPACE_SNAPSHOT_MAX_BYTES = 128 * 1024 * 1024
WORKSPACE_INPUT_READ_BUDGET_SECONDS = 1.5


class WorkspaceInputSnapshotError(RuntimeError):
    """A whole-evaluation input admission failure; no target may be omitted."""

    def __init__(
        self,
        relative_path: str,
        reason: str,
        *,
        source_hash: str | None,
        bytes_observed: int,
        byte_limit: int,
    ) -> None:
        super().__init__(reason)
        self.relative_path = relative_path
        self.reason = reason
        self.source_hash = source_hash
        self.bytes_observed = bytes_observed
        self.byte_limit = byte_limit


@dataclass(frozen=True, slots=True)
class _WorkspaceInput:
    resolved: Path | None
    exists: bool
    is_file: bool


@dataclass(slots=True)
class _WorkspaceInputSnapshot:
    paths: dict[tuple[Path, str], _WorkspaceInput] = field(default_factory=dict)
    files: dict[Path, _WorkspaceInput] = field(default_factory=dict)
    contents: dict[Path, bytes | None | WorkspaceInputSnapshotError] = field(default_factory=dict)
    max_retained_bytes: int = WORKSPACE_SNAPSHOT_MAX_BYTES
    retained_bytes: int = 0


_INPUT_SNAPSHOT: ContextVar[_WorkspaceInputSnapshot | None] = ContextVar(
    "package_workspace_input_snapshot", default=None
)


@contextmanager
def workspace_input_snapshot(*, max_retained_bytes: int = WORKSPACE_SNAPSHOT_MAX_BYTES) -> Iterator[None]:
    """Bind one evaluation's reads and hashes to immutable bytes, then discard them.

    This does not authorize a later package launch. Execution must independently
    revalidate the resulting content/policy identity after evaluation finishes.
    There is no cross-evaluation filename, stat, or timestamp cache.
    """

    token = _INPUT_SNAPSHOT.set(_WorkspaceInputSnapshot(max_retained_bytes=max_retained_bytes))
    try:
        yield
    finally:
        _INPUT_SNAPSHOT.reset(token)


def _snapshot_input(workspace_dir: Path, relative_path: str) -> _WorkspaceInput | None:
    snapshot = _INPUT_SNAPSHOT.get()
    if snapshot is None:
        return None
    key = (workspace_dir, relative_path)
    if key not in snapshot.paths:
        resolved = _resolve_path_within_workspace(workspace_dir, relative_path)
        captured = snapshot.files.get(resolved) if resolved is not None else None
        if captured is None:
            exists = resolved is not None and resolved.exists()
            captured = _WorkspaceInput(resolved, exists, resolved is not None and resolved.is_file())
            if resolved is not None:
                snapshot.files[resolved] = captured
        snapshot.paths[key] = captured
    return snapshot.paths[key]


def _read_snapshot_content(
    snapshot: _WorkspaceInputSnapshot, captured: _WorkspaceInput, relative_path: str
) -> bytes | None:
    resolved = captured.resolved
    if resolved is None or not captured.is_file:
        return None
    if resolved not in snapshot.contents:
        try:
            content = _bounded_snapshot_read(snapshot, resolved, relative_path)
        except WorkspaceInputSnapshotError as error:
            snapshot.contents[resolved] = error
            raise
        except OSError:
            content = None
        snapshot.contents[resolved] = content
        if content is not None:
            snapshot.retained_bytes += len(content)
    content = snapshot.contents[resolved]
    if isinstance(content, WorkspaceInputSnapshotError):
        raise content
    return content


def _bounded_snapshot_read(snapshot: _WorkspaceInputSnapshot, resolved: Path, relative_path: str) -> bytes:
    remaining = max(0, snapshot.max_retained_bytes - snapshot.retained_bytes)
    retained_limit = min(WORKSPACE_INPUT_MAX_BYTES, remaining)
    buffer = io.BytesIO()
    byte_count = 0
    deadline = time.monotonic() + WORKSPACE_INPUT_READ_BUDGET_SECONDS

    def chunks() -> Iterator[bytes]:
        nonlocal byte_count
        with resolved.open("rb") as stream:
            while True:
                if time.monotonic() > deadline:
                    raise WorkspaceInputSnapshotError(
                        relative_path,
                        "deadline_exceeded",
                        source_hash=None,
                        bytes_observed=byte_count,
                        byte_limit=retained_limit,
                    )
                chunk = stream.read(64 * 1024)
                byte_count += len(chunk)
                if time.monotonic() > deadline:
                    raise WorkspaceInputSnapshotError(
                        relative_path,
                        "deadline_exceeded",
                        source_hash=None,
                        bytes_observed=byte_count,
                        byte_limit=retained_limit,
                    )
                if not chunk:
                    return
                if byte_count <= retained_limit:
                    buffer.write(chunk)
                elif buffer.tell():
                    # Continue computing the exact identity without retaining the oversized input.
                    buffer.seek(0)
                    buffer.truncate()
                yield chunk

    try:
        source_hash = stable_digest_chunks(chunks())
        if byte_count > retained_limit:
            reason = "byte_limit_exceeded" if byte_count > WORKSPACE_INPUT_MAX_BYTES else "resource_limit_exceeded"
            raise WorkspaceInputSnapshotError(
                relative_path,
                reason,
                source_hash=source_hash,
                bytes_observed=byte_count,
                byte_limit=retained_limit,
            )
        return buffer.getvalue()
    finally:
        # A cached typed exception must not retain a partially read buffer through its traceback.
        buffer.close()


def resolve_path_within_workspace(workspace_dir: Path, relative_path: str) -> Path | None:
    """Resolve a workspace-relative path and ensure it remains inside the workspace."""

    if (captured := _snapshot_input(workspace_dir, relative_path)) is not None:
        return captured.resolved
    return _resolve_path_within_workspace(workspace_dir, relative_path)


def _resolve_path_within_workspace(workspace_dir: Path, relative_path: str) -> Path | None:
    if not relative_path:
        return None
    candidate = Path(relative_path)
    if candidate.is_absolute():
        return None
    workspace_root = workspace_dir.expanduser().resolve()
    try:
        resolved = (workspace_root / candidate).resolve()
        resolved.relative_to(workspace_root)
    except (OSError, ValueError):
        return None
    return resolved


def read_text_within_workspace(workspace_dir: Path, relative_path: str) -> str | None:
    if (captured := _snapshot_input(workspace_dir, relative_path)) is not None:
        snapshot = _INPUT_SNAPSHOT.get()
        assert snapshot is not None
        content = _read_snapshot_content(snapshot, captured, relative_path)
        if content is None:
            return None
        try:
            # Match Path.read_text's universal-newline behavior for manifest consumers.
            return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError:
            return None
    resolved = resolve_path_within_workspace(workspace_dir, relative_path)
    if resolved is None or not resolved.is_file():
        return None
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def read_bytes_within_workspace(workspace_dir: Path, relative_path: str) -> bytes | None:
    if (captured := _snapshot_input(workspace_dir, relative_path)) is not None:
        snapshot = _INPUT_SNAPSHOT.get()
        assert snapshot is not None
        return _read_snapshot_content(snapshot, captured, relative_path)
    resolved = resolve_path_within_workspace(workspace_dir, relative_path)
    if resolved is None or not resolved.is_file():
        return None
    try:
        return resolved.read_bytes()
    except OSError:
        return None


def path_exists_within_workspace(workspace_dir: Path, relative_path: str) -> bool:
    """Use the captured existence state when evaluating an immutable input snapshot."""

    if (captured := _snapshot_input(workspace_dir, relative_path)) is not None:
        return captured.exists
    resolved = resolve_path_within_workspace(workspace_dir, relative_path)
    return resolved is not None and resolved.exists()


def existing_paths_within_workspace(
    workspace: Path | None,
    candidates: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    """Return workspace-contained relative paths that exist on disk."""

    if workspace is None:
        return ()
    workspace_root = workspace.expanduser().resolve()
    resolved_paths: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        disk_path = resolve_path_within_workspace(workspace_root, candidate)
        if disk_path is None or not disk_path.exists():
            continue
        try:
            normalized = disk_path.relative_to(workspace_root).as_posix()
        except ValueError:
            continue
        if normalized not in resolved_paths:
            resolved_paths.append(normalized)
    return tuple(resolved_paths)

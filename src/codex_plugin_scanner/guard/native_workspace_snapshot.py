"""Bridge to the native ``workspace-snapshot`` command.

The snapshot runs out of process so hashing a large worktree can never hold a
hook decision. It reads files without following symlinks, never runs Git and
returns only digests, counts and the worktree's local keys.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

WORKSPACE_SNAPSHOT_FEATURE = "workspace-snapshot-v1"
WORKSPACE_SNAPSHOT_COMMAND = "workspace-snapshot"
WORKSPACE_SNAPSHOT_SCHEMA = "guard.workspace-snapshot.v1"

_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
# The child inherits nothing it could use to reach a network or a repository
# config: it reads plain files under the root it is given.
_CHILD_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")


class WorkspaceSnapshotError(RuntimeError):
    """The native snapshot was unavailable or returned an unusable reply."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class WorkspaceSnapshot:
    mode: Literal["content", "stat"]
    root: str
    worktree_key: str
    codebase_key: str
    snapshot_digest: str
    input_manifest_digest: str
    head_commit: str | None
    coverage: Literal["complete", "partial"]
    partial_reasons: tuple[str, ...]
    entry_count: int
    summary: dict[str, object]


def workspace_snapshot(root: Path, *, mode: Literal["content", "stat"] = "content") -> WorkspaceSnapshot:
    reply = _native_request({"root": str(root), "mode": mode})
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise WorkspaceSnapshotError(error if isinstance(error, str) and error else "workspace_snapshot_failed")
    return _parse_result(reply.get("result"))


def _native_request(request: dict[str, object]) -> dict[str, object]:
    import os

    from .codex_hook_launch_runtime import run_isolated_hook_process
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or WORKSPACE_SNAPSHOT_FEATURE not in status.capabilities.features
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_native_unavailable")
    runtime = status.identity.path
    environment = {key: value for key in _CHILD_ENVIRONMENT_KEYS if (value := os.environ.get(key))}
    completed = run_isolated_hook_process(
        (str(runtime), WORKSPACE_SNAPSHOT_COMMAND, "--stdin"),
        input_text=json.dumps(request, sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=environment,
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_failed")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise WorkspaceSnapshotError("workspace_snapshot_failed") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise WorkspaceSnapshotError("workspace_snapshot_failed")
    return response


def _parse_result(result: object) -> WorkspaceSnapshot:
    if not isinstance(result, dict) or result.get("schema") != WORKSPACE_SNAPSHOT_SCHEMA:
        raise WorkspaceSnapshotError("workspace_snapshot_failed")
    mode = result.get("mode")
    coverage = result.get("coverage")
    digests = [result.get(key) for key in ("worktree_key", "codebase_key", "snapshot_digest", "input_manifest_digest")]
    if (
        mode not in {"content", "stat"}
        or coverage not in {"complete", "partial"}
        or not all(_is_digest(value) for value in digests)
        or not isinstance(result.get("root"), str)
        or not isinstance(result.get("entry_count"), int)
    ):
        raise WorkspaceSnapshotError("workspace_snapshot_failed")
    git = result.get("git")
    head = git.get("head_commit") if isinstance(git, dict) else None
    reasons = result.get("partial_reasons")
    summary: dict[str, object] = {
        key: result.get(key)
        for key in ("entry_count", "hashed_bytes", "excluded", "unreadable_count", "unstable_count", "limits")
    }
    return WorkspaceSnapshot(
        mode=mode,  # type: ignore[arg-type]
        root=str(result["root"]),
        worktree_key=str(digests[0]),
        codebase_key=str(digests[1]),
        snapshot_digest=str(digests[2]),
        input_manifest_digest=str(digests[3]),
        head_commit=head if isinstance(head, str) else None,
        coverage=coverage,  # type: ignore[arg-type]
        partial_reasons=tuple(str(item) for item in reasons) if isinstance(reasons, list) else (),
        entry_count=int(result["entry_count"]),
        summary=summary,
    )


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


__all__ = [
    "WORKSPACE_SNAPSHOT_FEATURE",
    "WorkspaceSnapshot",
    "WorkspaceSnapshotError",
    "workspace_snapshot",
]

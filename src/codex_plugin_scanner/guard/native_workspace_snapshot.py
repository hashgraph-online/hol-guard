"""Bridge to the native ``workspace-snapshot`` command.

The snapshot runs out of process so hashing a large worktree can never hold a
hook decision. It reads files without following symlinks, never runs Git and
returns only digests, counts and the worktree's local keys. A request may also
ask for the secret scan of the same bytes; the native side redacts every
finding before it crosses this boundary. It may likewise ask for the skill
content rules over the agent skills among those bytes; their findings carry
fixed rule text and never quote the skill. A request may also ask for the
check of every hook command in the project's agent configuration files; its
findings name the file and hook event, never the command, and for the check of
the hooks and MCP servers every agent plugin in the worktree ships, whose
findings name the file and hook event or server, never the command or URL.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

WORKSPACE_SNAPSHOT_FEATURE = "workspace-snapshot-v1"
WORKSPACE_SECRETS_FEATURE = "workspace-snapshot-secrets-v1"
WORKSPACE_SKILLS_FEATURE = "workspace-snapshot-skills-v1"
WORKSPACE_HOOKS_FEATURE = "workspace-snapshot-hooks-v1"
WORKSPACE_PLUGINS_FEATURE = "workspace-snapshot-plugins-v1"
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
    secrets: dict[str, object] | None = None
    skills: dict[str, object] | None = None
    hooks: dict[str, object] | None = None
    plugins: dict[str, object] | None = None


def workspace_snapshot(
    root: Path,
    *,
    mode: Literal["content", "stat"] = "content",
    secrets: bool = False,
    secret_key: str | None = None,
    skills: bool = False,
    hooks: bool = False,
    plugins: bool = False,
) -> WorkspaceSnapshot:
    """Snapshot ``root``; ``secrets`` also scans the hashed bytes for secrets.

    ``secret_key`` is the per-install secret that keys secret fingerprints. It
    goes to the native process on stdin only and is never part of a result.

    A native runtime without the secret scan raises
    ``workspace_snapshot_secrets_unavailable`` so the caller can fall back to a
    plain snapshot and report the detector as not run. ``skills`` runs the
    skill content rules; a runtime without them raises
    ``workspace_snapshot_skills_unavailable`` the same way, and ``hooks``,
    the project hook check, raises ``workspace_snapshot_hooks_unavailable``.
    ``plugins``, the agent plugin check, raises
    ``workspace_snapshot_plugins_unavailable``.
    """

    request: dict[str, object] = {"root": str(root), "mode": mode}
    if secrets:
        request["secrets"] = True
        if secret_key is not None:
            request["secret_key"] = secret_key
    if skills:
        request["skills"] = True
    if hooks:
        request["hooks"] = True
    if plugins:
        request["plugins"] = True
    reply = _native_request(
        request, needs_secrets=secrets, needs_skills=skills, needs_hooks=hooks, needs_plugins=plugins
    )
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise WorkspaceSnapshotError(error if isinstance(error, str) and error else "workspace_snapshot_failed")
    return _parse_result(reply.get("result"))


def _native_request(
    request: dict[str, object],
    *,
    needs_secrets: bool = False,
    needs_skills: bool = False,
    needs_hooks: bool = False,
    needs_plugins: bool = False,
) -> dict[str, object]:
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
    if needs_secrets and WORKSPACE_SECRETS_FEATURE not in status.capabilities.features:
        raise WorkspaceSnapshotError("workspace_snapshot_secrets_unavailable")
    if needs_skills and WORKSPACE_SKILLS_FEATURE not in status.capabilities.features:
        raise WorkspaceSnapshotError("workspace_snapshot_skills_unavailable")
    if needs_hooks and WORKSPACE_HOOKS_FEATURE not in status.capabilities.features:
        raise WorkspaceSnapshotError("workspace_snapshot_hooks_unavailable")
    if needs_plugins and WORKSPACE_PLUGINS_FEATURE not in status.capabilities.features:
        raise WorkspaceSnapshotError("workspace_snapshot_plugins_unavailable")
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
    secrets = result.get("secrets")
    skills = result.get("skills")
    hooks = result.get("hooks")
    plugins = result.get("plugins")
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
        secrets=secrets if isinstance(secrets, dict) else None,
        skills=skills if isinstance(skills, dict) else None,
        hooks=hooks if isinstance(hooks, dict) else None,
        plugins=plugins if isinstance(plugins, dict) else None,
    )


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


__all__ = [
    "WORKSPACE_HOOKS_FEATURE",
    "WORKSPACE_PLUGINS_FEATURE",
    "WORKSPACE_SECRETS_FEATURE",
    "WORKSPACE_SKILLS_FEATURE",
    "WORKSPACE_SNAPSHOT_FEATURE",
    "WorkspaceSnapshot",
    "WorkspaceSnapshotError",
    "workspace_snapshot",
]

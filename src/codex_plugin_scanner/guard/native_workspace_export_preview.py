"""Bridge to the native ``workspace-export-preview`` command.

The native command works out what a source export of named files in a tracked
worktree would contain, and nothing leaves the machine. It reaches each file
without following a symlink, keeps credential stores, policy directories,
binary and oversize files out, and redacts every secret the shared detector
finds. A secret that survives its redaction marks the file
``redaction_failed`` and the whole preview ``blocked``. The reply lists paths,
byte counts, digests and redacted rule ids; it never carries file content or
matched text.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

WORKSPACE_EXPORT_PREVIEW_FEATURE = "workspace-export-preview-v1"
WORKSPACE_EXPORT_PREVIEW_COMMAND = "workspace-export-preview"
WORKSPACE_EXPORT_PREVIEW_SCHEMA = "guard.workspace-export-preview.v1"
# The native command refuses more; checking first keeps an oversized request
# from starting a process at all.
MAX_EXPORT_PREVIEW_PATHS = 200

_STATUSES = frozenset({"ready", "empty", "blocked"})
_TIMEOUT_SECONDS = 60.0
_OUTPUT_LIMIT_BYTES = 1024 * 1024
# The child reads plain files under the root it is given and needs nothing else.
_CHILD_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")


class WorkspaceExportPreviewError(RuntimeError):
    """The native preview was unavailable, refused, or returned an unusable reply."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def preview(root: Path, paths: list[str]) -> dict[str, object]:
    """What exporting ``paths`` (root-relative, ``/``-separated) from ``root`` would send."""

    if len(paths) > MAX_EXPORT_PREVIEW_PATHS:
        raise WorkspaceExportPreviewError("workspace_export_preview_too_many_paths")
    reply = _native_request({"root": str(root), "paths": paths})
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise WorkspaceExportPreviewError(
            error if isinstance(error, str) and error else "workspace_export_preview_failed"
        )
    result = reply.get("result")
    if (
        not isinstance(result, dict)
        or result.get("schema") != WORKSPACE_EXPORT_PREVIEW_SCHEMA
        or result.get("status") not in _STATUSES
        or not isinstance(result.get("files"), list)
        or not isinstance(result.get("excluded"), list)
        or not all(_is_digest(result.get(key)) for key in ("worktree_key", "codebase_key", "bundle_digest"))
    ):
        raise WorkspaceExportPreviewError("workspace_export_preview_failed")
    return result


def _native_request(request: dict[str, object]) -> dict[str, object]:
    from .codex_hook_launch_runtime import run_isolated_hook_process
    from .native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or WORKSPACE_EXPORT_PREVIEW_FEATURE not in status.capabilities.features
    ):
        raise WorkspaceExportPreviewError("workspace_export_preview_native_unavailable")
    runtime = status.identity.path
    environment = {key: value for key in _CHILD_ENVIRONMENT_KEYS if (value := os.environ.get(key))}
    completed = run_isolated_hook_process(
        (str(runtime), WORKSPACE_EXPORT_PREVIEW_COMMAND, "--stdin"),
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
        raise WorkspaceExportPreviewError("workspace_export_preview_failed")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise WorkspaceExportPreviewError("workspace_export_preview_failed") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise WorkspaceExportPreviewError("workspace_export_preview_failed")
    return response


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


__all__ = [
    "MAX_EXPORT_PREVIEW_PATHS",
    "WORKSPACE_EXPORT_PREVIEW_FEATURE",
    "WorkspaceExportPreviewError",
    "preview",
]

"""Bridge to the native ``workspace-fix`` command.

The native command owns everything deterministic about a reviewed dependency
fix: finding the manifests the assessment inventory covers, planning the
minimal version-spec edit and its diff, and replacing a manifest only if it
is unchanged. All of it runs out of process, reads files without following
symlinks and never runs a package manager or project code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

WORKSPACE_FIX_FEATURE = "workspace-fix-v1"
WORKSPACE_FIX_COMMAND = "workspace-fix"

_TIMEOUT_SECONDS = 60.0
_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
# The child reads plain files under the root it is given and needs nothing else.
_CHILD_ENVIRONMENT_KEYS = ("SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP")


class WorkspaceFixError(RuntimeError):
    """The native fix command was unavailable, refused, or returned an unusable reply."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def plan(root: Path, *, package: str, fix_version: str, max_proposals: int, max_diff_bytes: int) -> dict[str, object]:
    """Edits for each inventory manifest that declares ``package``, plus why others were skipped."""

    result = _result(
        {
            "op": "plan",
            "root": str(root),
            "package": package,
            "fix_version": fix_version,
            "max_proposals": max_proposals,
            "max_diff_bytes": max_diff_bytes,
        }
    )
    proposals, skipped = result.get("proposals"), result.get("skipped")
    if (
        not isinstance(proposals, list)
        or not isinstance(skipped, list)
        or not isinstance(result.get("truncated"), bool)
    ):
        raise WorkspaceFixError("workspace_fix_failed")
    return result


def apply(
    root: Path, *, manifest_path: str, base_sha256: str, new_sha256: str, edits: list[dict[str, object]]
) -> dict[str, object]:
    """Write the reviewed edit if the manifest is unchanged; ``status`` is ``applied`` or ``stale``."""

    result = _result(
        {
            "op": "apply",
            "root": str(root),
            "manifest_path": manifest_path,
            "base_sha256": base_sha256,
            "new_sha256": new_sha256,
            "edits": edits,
        }
    )
    if result.get("status") not in {"applied", "stale"}:
        raise WorkspaceFixError("workspace_fix_failed")
    return result


def _result(request: dict[str, object]) -> dict[str, object]:
    reply = _native_request(request)
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise WorkspaceFixError(error if isinstance(error, str) and error else "workspace_fix_failed")
    result = reply.get("result")
    if not isinstance(result, dict):
        raise WorkspaceFixError("workspace_fix_failed")
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
        or WORKSPACE_FIX_FEATURE not in status.capabilities.features
    ):
        raise WorkspaceFixError("workspace_fix_native_unavailable")
    runtime = status.identity.path
    environment = {key: value for key in _CHILD_ENVIRONMENT_KEYS if (value := os.environ.get(key))}
    completed = run_isolated_hook_process(
        (str(runtime), WORKSPACE_FIX_COMMAND, "--stdin"),
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
        raise WorkspaceFixError("workspace_fix_failed")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise WorkspaceFixError("workspace_fix_failed") from error
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise WorkspaceFixError("workspace_fix_failed")
    return response


__all__ = ["WORKSPACE_FIX_FEATURE", "WorkspaceFixError", "apply", "plan"]

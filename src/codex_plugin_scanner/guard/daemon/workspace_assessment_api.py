"""Dashboard routes for background workspace assessments.

The routes live under ``/v1/supply-chain/`` so they inherit that family's
header-token and dashboard-session policy; scoped claim sessions cannot reach
them. Reads return digests, counts and package-coordinate findings. Writes
admit, pause, queue or cancel runs (a run itself happens on the worker thread)
or prepare and apply a reviewed dependency fix. Preparing only stores a diff;
applying is the user's explicit action and edits one manifest, never more.
An export preview reports what a source export of named files in a tracked
worktree would contain; it reads and redacts locally and sends nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, Protocol, cast
from urllib.parse import parse_qs

from .. import native_workspace_export_preview as export_preview
from .. import workspace_assessment_fix_proposals as fixes
from .. import workspace_assessment_store as assessments
from ..workspace_assessment_pressure import deferral_reason
from ..workspace_assessment_worker import WorkspaceAdmissionError, admit_workspace, queue_manual_run

ASSESSMENTS_PATH: Final = "/v1/supply-chain/workspace-assessments"
FINDINGS_PATH: Final = "/v1/supply-chain/workspace-findings"
FIX_PROPOSALS_PATH: Final = "/v1/supply-chain/workspace-fix-proposals"
EXPORT_PREVIEW_PATH: Final = "/v1/supply-chain/workspace-export-preview"
_ACTIONS: Final = frozenset({"run", "cancel", "pause", "resume"})
_MAX_QUERY_CHARS: Final = 1024


class WorkspaceAssessmentHandler(Protocol):
    server: Any

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None: ...


def handle_workspace_assessment_get(request_handler: object, path: str, query: str = "") -> bool:
    # The daemon's route mixins are typed apart from the handler class that
    # provides ``server`` and ``_write_json``.
    handler = cast(WorkspaceAssessmentHandler, request_handler)
    store = handler.server.store
    if path == ASSESSMENTS_PATH:
        handler._write_json(
            {
                "worktrees": assessments.list_worktrees(store),
                "runs": assessments.recent_runs(store, limit=50),
                # The newest run of each worktree, so a busy worktree keeps its
                # queued or running state however long the history above is.
                "latest_runs": assessments.latest_runs(store),
                # Set while a busy host holds automatic runs back.
                "deferred_reason": deferral_reason(store),
            }
        )
        return True
    if path == FINDINGS_PATH:
        worktrees = assessments.list_worktrees(store)
        payload: dict[str, object] = {
            "worktrees": worktrees,
            "assessments": assessments.latest_assessed_runs(store),
        }
        suggested = _suggested_root(query)
        if suggested is not None:
            payload["suggested_root_tracked"] = _is_tracked(worktrees, suggested)
        handler._write_json(payload)
        return True
    if path == FIX_PROPOSALS_PATH:
        _list_fix_proposals(handler, query)
        return True
    return False


def _suggested_root(query: str) -> str | None:
    values = parse_qs(query).get("root")
    if not values or not 0 < len(values[0]) <= 4096:
        return None
    return values[0]


def _is_tracked(worktrees: list[dict[str, object]], root: str) -> bool:
    # Worktrees are stored by their resolved root, so resolve the suggestion the
    # same way: symlinks, ``..`` and trailing separators then compare equal.
    try:
        resolved = str(Path(root).resolve(strict=True))
    except (OSError, ValueError):
        return False
    return any(worktree.get("root") == resolved for worktree in worktrees)


def handle_workspace_assessment_post(
    request_handler: object,
    path: str,
    payload: dict[str, object],
) -> bool:
    handler = cast(WorkspaceAssessmentHandler, request_handler)
    if path == ASSESSMENTS_PATH:
        _admit(handler, payload)
        return True
    if path == FIX_PROPOSALS_PATH:
        _prepare_fix(handler, payload)
        return True
    if path == EXPORT_PREVIEW_PATH:
        _preview_export(handler, payload)
        return True
    fix_prefix = FIX_PROPOSALS_PATH + "/"
    if path.startswith(fix_prefix) and path.endswith("/apply"):
        proposal_id = path[len(fix_prefix) : -len("/apply")]
        if not _is_proposal_id(proposal_id):
            handler._write_json({"error": "invalid_proposal_id"}, status=400)
            return True
        _apply_fix(handler, proposal_id)
        return True
    prefix = ASSESSMENTS_PATH + "/"
    if not path.startswith(prefix) or path[len(prefix) :] not in _ACTIONS:
        return False
    action = path[len(prefix) :]
    store = handler.server.store
    if action == "cancel":
        run_id = payload.get("run_id")
        if not isinstance(run_id, str) or not 0 < len(run_id) <= 64:
            handler._write_json({"error": "invalid_run_id"}, status=400)
            return True
        canceled = assessments.cancel(store, run_id, now_ms=_now_ms())
        handler._write_json({"canceled": canceled}, status=200 if canceled else 409)
        return True
    keys = _keys(payload)
    if keys is None:
        handler._write_json({"error": "invalid_worktree"}, status=400)
        return True
    if action in {"pause", "resume"}:
        changed = assessments.set_paused(store, keys, paused=action == "pause")
        handler._write_json({"paused": action == "pause"}, status=200 if changed else 404)
        return True
    run_id = queue_manual_run(store, keys)
    handler._write_json({"run_id": run_id}, status=202 if run_id else 404)
    return True


def _admit(handler: WorkspaceAssessmentHandler, payload: dict[str, object]) -> None:
    root = payload.get("root")
    if not isinstance(root, str) or not 0 < len(root) <= 4096:
        handler._write_json({"error": "invalid_root"}, status=400)
        return
    try:
        admitted = admit_workspace(handler.server.store, root)
    except WorkspaceAdmissionError as error:
        handler._write_json({"error": error.code}, status=422)
        return
    handler._write_json(admitted, status=202)


def _list_fix_proposals(handler: WorkspaceAssessmentHandler, query: str) -> None:
    params = {name: values[0] for name, values in parse_qs(query[:_MAX_QUERY_CHARS]).items() if values}
    keys = _keys(params)
    if keys is None:
        handler._write_json({"error": "invalid_worktree"}, status=400)
        return
    limit = params.get("limit", "")
    # str.isdigit() accepts Unicode digits that int() then rejects or misreads.
    valid_limit = 0 < len(limit) <= 9 and all("0" <= char <= "9" for char in limit)
    proposals = fixes.list_proposals(
        handler.server.store,
        keys,
        limit=int(limit) if valid_limit else fixes.MAX_LISTED_PROPOSALS,
        now_ms=_now_ms(),
    )
    handler._write_json({"proposals": proposals})


def _prepare_fix(handler: WorkspaceAssessmentHandler, payload: dict[str, object]) -> None:
    keys = _keys(payload)
    finding_id = payload.get("finding_id")
    if keys is None:
        handler._write_json({"error": "invalid_worktree"}, status=400)
        return
    if not isinstance(finding_id, str) or len(finding_id) != 32 or not _is_hex(finding_id):
        handler._write_json({"error": "invalid_finding_id"}, status=400)
        return
    try:
        prepared = fixes.prepare(handler.server.store, keys, finding_id, now_ms=_now_ms())
    except fixes.FixProposalError as error:
        handler._write_json({"error": error.code, **error.detail}, status=error.status)
        return
    handler._write_json(prepared, status=201)


def _apply_fix(handler: WorkspaceAssessmentHandler, proposal_id: str) -> None:
    try:
        applied = fixes.apply(handler.server.store, proposal_id, now_ms=_now_ms())
    except fixes.FixProposalError as error:
        handler._write_json({"error": error.code, **error.detail}, status=error.status)
        return
    handler._write_json(applied)


def _preview_export(handler: WorkspaceAssessmentHandler, payload: dict[str, object]) -> None:
    keys = _keys(payload)
    paths = payload.get("paths")
    if keys is None:
        handler._write_json({"error": "invalid_worktree"}, status=400)
        return
    if (
        not isinstance(paths, list)
        or len(paths) > export_preview.MAX_EXPORT_PREVIEW_PATHS
        or not all(isinstance(item, str) and 0 < len(item) <= 4096 for item in paths)
    ):
        handler._write_json({"error": "invalid_paths"}, status=400)
        return
    worktree = next(
        (
            item
            for item in assessments.list_worktrees(handler.server.store)
            if item["codebase_key"] == keys.codebase_key and item["worktree_key"] == keys.worktree_key
        ),
        None,
    )
    if worktree is None:
        handler._write_json({"error": "worktree_not_found"}, status=404)
        return
    try:
        result = export_preview.preview(Path(str(worktree["root"])), [str(item) for item in paths])
    except export_preview.WorkspaceExportPreviewError as error:
        status = 503 if error.code == "workspace_export_preview_native_unavailable" else 422
        handler._write_json({"error": error.code}, status=status)
        return
    # The native side keys the root it actually opened. A root that now resolves
    # elsewhere, through a replaced directory or symlink, or whose Git pointer now
    # names another repository, is another worktree.
    if result["worktree_key"] != keys.worktree_key or result["codebase_key"] != keys.codebase_key:
        handler._write_json({"error": "worktree_moved"}, status=409)
        return
    handler._write_json(result)


def _keys(payload: Mapping[str, object]) -> assessments.WorktreeKeys | None:
    codebase_key = payload.get("codebase_key")
    worktree_key = payload.get("worktree_key")
    if not (_is_key(codebase_key) and _is_key(worktree_key)):
        return None
    return assessments.WorktreeKeys(str(codebase_key), str(worktree_key))


def _is_key(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and _is_hex(value)


def _is_proposal_id(value: str) -> bool:
    return 0 < len(value) <= 64 and _is_hex(value)


def _is_hex(value: str) -> bool:
    return all(char in "0123456789abcdef" for char in value)


def _now_ms() -> int:
    from ..workspace_assessment_runner import now_ms

    return now_ms()


__all__ = [
    "ASSESSMENTS_PATH",
    "EXPORT_PREVIEW_PATH",
    "FINDINGS_PATH",
    "FIX_PROPOSALS_PATH",
    "handle_workspace_assessment_get",
    "handle_workspace_assessment_post",
]

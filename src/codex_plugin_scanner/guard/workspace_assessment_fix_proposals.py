"""Reviewed dependency fix proposals for workspace assessment findings.

A proposal is one minimal ``package.json`` version-spec edit that moves a
directly declared npm dependency to a finding's fix version. It moves through
three separate steps and never runs on its own:

* prepare asks the native ``workspace-fix`` command for the edits (it reads
  only manifests the assessment inventory covers) and stores each edit, its
  diff, and the hashes of the manifest before and after;
* apply is the user's explicit approval. The native command replaces the
  manifest only if it still has the prepared hash and otherwise the proposal
  goes stale, so a user's own edits are never overwritten; a verification run
  is then queued;
* verification marks the proposal fixed only after a later, complete
  supply-chain run, started after the apply, no longer reports the finding.

Python keeps the request handling and the state machine; the stored rows, the
manifest scan, edit planning, diff, hashing and file replacement are native.
Guard does not run a package manager or any project code, so the lockfile is
left for the user to update with their own tooling.
"""

from __future__ import annotations

import base64
import json
import threading
import uuid
from pathlib import Path
from typing import Any, Final

from . import native_workspace_fix as native
from . import workspace_assessment_store as assessments
from .store_workspace_assessment_schema import MAX_FIX_DIFF_BYTES
from .workspace_assessment_worker import queue_manual_run
from .workspace_fix_proposal_pages import native_pages as _pages
from .workspace_fix_proposal_pages import native_row as _row
from .workspace_fix_proposal_pages import native_text as _text

MAX_LISTED_PROPOSALS: Final = 100
MAX_PROPOSALS_PER_PREPARE: Final = 20
_EDIT_KEYS: Final = ("section", "start", "end", "from_spec", "to_spec")
# Room the stored proposals may take in the one native request that saves
# them, under the store's 4 MiB request limit.
_PREPARE_REQUEST_BYTES: Final = 3 * 1024 * 1024
_ROOT_UNAVAILABLE: Final = frozenset(
    {
        "workspace_fix_root_not_absolute",
        "workspace_fix_root_missing",
        "workspace_fix_root_not_directory",
        "workspace_fix_root_not_utf8",
    }
)
_MAX_FIELD_CHARS: Final = 128
# Newer runs finishing during each native call can only delay settling.
_VERIFY_ATTEMPTS: Final = 3
_VERIFY_RUN_KEYS: Final = ("run_id", "snapshot_digest", "started_at_ms", "coverage", "findings")
_VERIFY_PROPOSAL_KEYS: Final = (
    "proposal_id",
    "ecosystem",
    "package_name",
    "fix_version",
    "advisory_ids",
    "rule_ids",
    "snapshot_digest",
    "applied_at_ms",
    "state",
    "verification_run_id",
)
_COLUMNS: Final = (
    "proposal_id",
    "codebase_key",
    "worktree_key",
    "finding_id",
    "ecosystem",
    "package_name",
    "fix_version",
    "advisory_ids_json",
    "rule_ids_json",
    "source_run_id",
    "snapshot_digest",
    "manifest_path",
    "base_sha256",
    "new_sha256",
    "edits_json",
    "diff_text",
    "state",
    "created_at_ms",
    "updated_at_ms",
    "applied_at_ms",
    "verified_at_ms",
    "verification_run_id",
)
_WORKTREE_KEYS: Final = frozenset({"root", "paused"})
# One apply at a time, so two requests cannot both pass the hash check.
_APPLY_LOCK: Final = threading.Lock()


class FixProposalError(Exception):
    """A refused request; ``code`` and ``status`` become the API response."""

    def __init__(self, code: str, status: int, **detail: object) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.detail = detail


def prepare(store: Any, keys: assessments.WorktreeKeys, finding_id: str, *, now_ms: int) -> dict[str, object]:
    """Store a proposal for each direct declaration of the finding's package."""

    root, _paused = _worktree(store, keys)
    run = assessments.latest_assessed_run(store, keys)
    if run is None:
        raise FixProposalError("no_assessed_run", 409)
    findings = run["findings"] if isinstance(run["findings"], list) else []
    finding = next((item for item in findings if isinstance(item, dict) and item.get("finding_id") == finding_id), None)
    if finding is None:
        raise FixProposalError("finding_not_found", 404)
    package, fix_version = finding.get("package_name"), finding.get("fix_version")
    if finding.get("source_kind") != "supply_chain":
        raise FixProposalError("fix_unsupported", 422, reason="unsupported_source")
    if finding.get("ecosystem") != "npm":
        raise FixProposalError("fix_unsupported", 422, reason="unsupported_ecosystem")
    if not isinstance(fix_version, str) or not fix_version:
        raise FixProposalError("fix_unsupported", 422, reason="no_fix_version")
    if not isinstance(package, str) or not package or len(fix_version) > _MAX_FIELD_CHARS or len(package) > 256:
        raise FixProposalError("fix_unsupported", 422, reason="finding_incomplete")
    try:
        planned = native.plan(
            root,
            package=package,
            fix_version=fix_version,
            max_proposals=MAX_PROPOSALS_PER_PREPARE,
            max_diff_bytes=MAX_FIX_DIFF_BYTES,
        )
    except native.WorkspaceFixError as error:
        raise _native_failure(error) from error
    raw_proposals = planned["proposals"]
    proposals = [item for item in raw_proposals if isinstance(item, dict)] if isinstance(raw_proposals, list) else []
    skipped = _skipped_payload(planned["skipped"])
    truncated = planned["truncated"] is True
    if not proposals:
        reason = (
            skipped[0]["reason"] if skipped else ("manifest_scan_incomplete" if truncated else "transitive_dependency")
        )
        raise FixProposalError("fix_unsupported", 422, reason=reason, skipped=skipped, truncated=truncated)
    identity: dict[str, object] = {
        "ecosystem": "npm",
        "package_name": package,
        "fix_version": fix_version,
        "advisory_ids": _id_list(finding.get("advisory_ids")),
        "rule_ids": _id_list(finding.get("rule_ids")),
    }
    stored = _store_prepared(store, keys, finding_id, run, proposals, identity, now_ms=now_ms)
    # `truncated` means the manifest scan stopped early, so a proposal list is
    # still incomplete even when it is not empty.
    return {"proposals": stored, "skipped": skipped, "truncated": truncated}


def apply(store: Any, proposal_id: str, *, now_ms: int) -> dict[str, object]:
    """Write a prepared proposal if its manifest is unchanged, then queue verification."""

    with _APPLY_LOCK:
        row = _fetch(store, proposal_id)
        if row is None:
            raise FixProposalError("fix_proposal_not_found", 404)
        if row["state"] == "stale":
            raise FixProposalError("fix_proposal_stale", 409)
        if row["state"] != "prepared":
            raise FixProposalError("fix_proposal_not_prepared", 409, state=row["state"])
        keys = assessments.WorktreeKeys(str(row["codebase_key"]), str(row["worktree_key"]))
        root, paused = _worktree(store, keys)
        if paused:
            # A paused worktree cannot queue the verification run that decides
            # whether the fix worked, so nothing is written until it resumes.
            raise FixProposalError("worktree_paused", 409)
        relative = str(row["manifest_path"])
        try:
            outcome = native.apply(
                root,
                manifest_path=relative,
                base_sha256=str(row["base_sha256"]),
                new_sha256=str(row["new_sha256"]),
                edits=_stored_edits(row),
            )
        except native.WorkspaceFixError as error:
            raise _native_failure(error) from error
        if outcome["status"] == "stale":
            # The file moved on since the review (or no longer matches what was
            # reviewed): nothing was written, so the user's own edits stay.
            _set_state(store, proposal_id, "stale", now_ms=now_ms)
            detail: dict[str, object] = {"reason": outcome.get("reason")}
            if isinstance(outcome.get("preserved_path"), str):
                detail["preserved_path"] = outcome["preserved_path"]
            raise FixProposalError("fix_proposal_stale", 409, **detail)
        _set_state(store, proposal_id, "applied", now_ms=now_ms, applied=True)
    queued = queue_manual_run(store, keys, trigger_kind="fix_verification", clock=lambda: now_ms)
    lockfiles = outcome.get("lockfiles")
    return {
        "proposal": _payload(_fetch(store, proposal_id) or row),
        "lockfile_update_required": True,
        "lockfiles": [item for item in lockfiles if isinstance(item, str)] if isinstance(lockfiles, list) else [],
        "verification_queued": queued is not None,
        "verification_run_id": queued,
    }


def list_proposals(
    store: Any, keys: assessments.WorktreeKeys, *, limit: int = MAX_LISTED_PROPOSALS, now_ms: int
) -> list[dict[str, object]]:
    """Newest proposals of a worktree, after settling any that a later run decides."""

    verify_proposals(store, keys, now_ms=now_ms)
    wanted = max(1, min(limit, MAX_LISTED_PROPOSALS))
    args: dict[str, object] = {**_key_args(keys), "limit": wanted}
    rows = _pages(store, "list_workspace_fix_proposals", args, "before", frozenset(_COLUMNS), limit=wanted)
    return [_payload(row) for row in rows]


def verify_proposals(store: Any, keys: assessments.WorktreeKeys, *, now_ms: int) -> None:
    """Settle applied proposals against the worktree's newest assessed run.

    Only the newest run is consulted, so the outcome is deterministic. The
    native runtime decides each verdict: a run that cannot vouch for the whole
    supply-chain input leaves a proposal as it is, and nothing but such a run
    can mark one fixed. An unavailable native runtime also changes nothing.
    A run that finishes while the native runtime answers is consulted next.
    """

    for _ in range(_VERIFY_ATTEMPTS):
        if _settle_against_newest(store, keys, now_ms=now_ms):
            return


def _settle_against_newest(store: Any, keys: assessments.WorktreeKeys, *, now_ms: int) -> bool:
    """Settle against the newest run; False when a newer run finished meanwhile."""

    run = assessments.latest_assessed_run(store, keys)
    if run is None:
        return True
    method = "list_workspace_fix_proposals_to_verify"
    proposals = _pages(store, method, _key_args(keys), "after", frozenset(_VERIFY_PROPOSAL_KEYS))
    if not proposals:
        return True
    for item in proposals:
        prior_run = item["verification_run_id"]
        if not isinstance(item["proposal_id"], str) or not isinstance(item["state"], str):
            raise RuntimeError(f"native {method} returned no answer")
        if prior_run is not None and not isinstance(prior_run, str):
            raise RuntimeError(f"native {method} returned no answer")
        item["advisory_ids"] = json.loads(_text(item["advisory_ids"], method))
        item["rule_ids"] = json.loads(_text(item["rule_ids"], method))
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(
            "workspace_fix_verify",
            {"run": {key: run[key] for key in _VERIFY_RUN_KEYS}, "proposals": proposals},
        )
    except NativeRunnerAuthorityError:
        return True
    updates = answer.get("updates")
    prior_by_id = {item["proposal_id"]: item for item in proposals}
    verdicts: list[dict[str, object]] = []
    for update in updates if isinstance(updates, list) else []:
        proposal = prior_by_id.get(update.get("proposal_id")) if isinstance(update, dict) else None
        if proposal is None or update.get("state") not in ("still_present", "verified_fixed"):
            continue
        # Only a proposal still as it was read takes the verdict; a
        # concurrent verification settles it otherwise.
        verdicts.append(
            {
                "proposal_id": proposal["proposal_id"],
                "state": update["state"],
                "prior_state": proposal["state"],
                "prior_verification_run_id": proposal["verification_run_id"],
            }
        )
    # A run that finished while the native runtime answered decides instead.
    settled = store._native_store_call(
        "settle_workspace_fix_proposals",
        {**_key_args(keys), "run_id": run["run_id"], "now_ms": now_ms, "updates": verdicts},
    )
    if not isinstance(settled, bool):
        raise RuntimeError("native settle_workspace_fix_proposals returned no answer")
    return settled


def _id_set(value: object) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _store_prepared(
    store: Any,
    keys: assessments.WorktreeKeys,
    finding_id: str,
    run: dict[str, object],
    planned: list[dict[str, object]],
    identity: dict[str, object],
    *,
    now_ms: int,
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    size = 0
    for item in planned:
        raw_edits = item["edits"]
        if not isinstance(raw_edits, list):
            raise FixProposalError("workspace_fix_failed", 500)
        edits: list[object] = raw_edits
        # Text goes over as base64, so characters canonical JSON would escape
        # six bytes wide cannot outgrow the request.
        edits_base64 = _base64(json.dumps([_edit_record(edit) for edit in edits], separators=(",", ":")))
        diff_base64 = _base64(item["diff"])
        size += len(edits_base64) + len(diff_base64)
        items.append(
            {
                # The id a new proposal takes; a kept proposal keeps its own.
                "proposal_id": uuid.uuid4().hex,
                "manifest_path": item["manifest_path"],
                "base_sha256": item["base_sha256"],
                "new_sha256": item["new_sha256"],
                "edits_base64": edits_base64,
                "diff_base64": diff_base64,
            }
        )
    if size > _PREPARE_REQUEST_BYTES:
        raise FixProposalError("fix_unsupported", 422, reason="diff_too_large")
    method = "store_prepared_workspace_fix_proposals"
    ids = store._native_store_call(
        method,
        {
            **_key_args(keys),
            "finding_id": finding_id,
            "source_run_id": run["run_id"],
            "snapshot_digest": run["snapshot_digest"],
            "now_ms": now_ms,
            "ecosystem": identity["ecosystem"],
            "package_name": identity["package_name"],
            "fix_version": identity["fix_version"],
            "advisory_ids_json": json.dumps(identity["advisory_ids"], separators=(",", ":")),
            "rule_ids_json": json.dumps(identity["rule_ids"], separators=(",", ":")),
            "items": items,
        },
    )
    if not isinstance(ids, list) or len(ids) != len(items) or not all(isinstance(item, str) for item in ids):
        raise RuntimeError(f"native {method} returned no answer")
    return [_payload(row) for proposal_id in ids if (row := _fetch(store, proposal_id)) is not None]


def _base64(text: object) -> str:
    if not isinstance(text, str):
        raise FixProposalError("workspace_fix_failed", 500)
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _worktree(store: Any, keys: assessments.WorktreeKeys) -> tuple[Path, bool]:
    method = "workspace_assessment_worktree_root"
    row = store._native_store_call(method, _key_args(keys))
    if row is None:
        raise FixProposalError("worktree_not_found", 404)
    checked = _row(row, _WORKTREE_KEYS, method)
    paused = checked["paused"]
    if isinstance(paused, bool) or not isinstance(paused, int):
        raise RuntimeError(f"native {method} returned no answer")
    return Path(_text(checked["root"], method)), bool(paused)


def _fetch(store: Any, proposal_id: str) -> dict[str, Any] | None:
    method = "get_workspace_fix_proposal"
    row = store._native_store_call(method, {"proposal_id": proposal_id})
    if row is None:
        return None
    return _row(row, frozenset(_COLUMNS), method)


def _set_state(store: Any, proposal_id: str, state: str, *, now_ms: int, applied: bool = False) -> None:
    method = "set_workspace_fix_proposal_state"
    answer = store._native_store_call(
        method, {"proposal_id": proposal_id, "state": state, "now_ms": now_ms, "applied": applied}
    )
    if answer is not None:
        raise RuntimeError(f"native {method} returned no answer")


def _edit_record(edit: object) -> dict[str, object]:
    if not isinstance(edit, dict) or set(edit) != set(_EDIT_KEYS):
        raise FixProposalError("workspace_fix_failed", 500)
    return {key: edit[key] for key in _EDIT_KEYS}


def _stored_edits(row: dict[str, Any]) -> list[dict[str, object]]:
    return [_edit_record(item) for item in json.loads(str(row["edits_json"]))]


def _id_list(value: object) -> list[str]:
    return sorted(_id_set(value))


def _native_failure(error: native.WorkspaceFixError) -> FixProposalError:
    if error.code == "workspace_fix_native_unavailable":
        return FixProposalError("fix_native_unavailable", 503)
    if error.code in _ROOT_UNAVAILABLE:
        return FixProposalError("worktree_unavailable", 409)
    if error.code == "fix_apply_failed":
        return FixProposalError("fix_apply_failed", 500)
    if error.code == "fix_apply_unsupported":
        # The platform cannot write the manifest safely; nothing was changed.
        return FixProposalError("fix_apply_unsupported", 501)
    return FixProposalError("workspace_fix_failed", 500)


def _payload(row: dict[str, Any]) -> dict[str, object]:
    return {
        "proposal_id": row["proposal_id"],
        "codebase_key": row["codebase_key"],
        "worktree_key": row["worktree_key"],
        "finding_id": row["finding_id"],
        "ecosystem": row["ecosystem"],
        "package_name": row["package_name"],
        "fix_version": row["fix_version"],
        "advisory_ids": json.loads(str(row["advisory_ids_json"])),
        "rule_ids": json.loads(str(row["rule_ids_json"])),
        "source_run_id": row["source_run_id"],
        "snapshot_digest": row["snapshot_digest"],
        "manifest_path": row["manifest_path"],
        "base_sha256": row["base_sha256"],
        "new_sha256": row["new_sha256"],
        "edits": [
            {"section": item["section"], "from_spec": item["from_spec"], "to_spec": item["to_spec"]}
            for item in json.loads(str(row["edits_json"]))
        ],
        # Only a proposal still waiting for review needs its diff on the wire.
        "diff": row["diff_text"] if row["state"] == "prepared" else None,
        "state": row["state"],
        "created_at_ms": row["created_at_ms"],
        "updated_at_ms": row["updated_at_ms"],
        "applied_at_ms": row["applied_at_ms"],
        "verified_at_ms": row["verified_at_ms"],
        "verification_run_id": row["verification_run_id"],
    }


def _key_args(keys: assessments.WorktreeKeys) -> dict[str, object]:
    return {"codebase_key": keys.codebase_key, "worktree_key": keys.worktree_key}


def _skipped_payload(skipped: object) -> list[dict[str, str]]:
    items = skipped if isinstance(skipped, list) else []
    return [
        {"manifest_path": str(item["manifest_path"]), "reason": str(item["reason"])}
        for item in items[:MAX_PROPOSALS_PER_PREPARE]
        if isinstance(item, dict) and "manifest_path" in item and "reason" in item
    ]


__all__ = [
    "MAX_LISTED_PROPOSALS",
    "FixProposalError",
    "apply",
    "list_proposals",
    "prepare",
    "verify_proposals",
]

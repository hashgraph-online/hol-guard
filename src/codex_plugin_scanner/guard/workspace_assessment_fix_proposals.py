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

Python keeps the request handling, the stored state and the state machine; the
manifest scan, edit planning, diff, hashing and file replacement are native.
Guard does not run a package manager or any project code, so the lockfile is
left for the user to update with their own tooling.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from pathlib import Path
from typing import Any, Final

from . import native_workspace_fix as native
from . import workspace_assessment_store as assessments
from .store_workspace_assessment_schema import MAX_FIX_DIFF_BYTES
from .workspace_assessment_worker import queue_manual_run

MAX_LISTED_PROPOSALS: Final = 100
MAX_PROPOSALS_PER_PREPARE: Final = 20
_EDIT_KEYS: Final = ("section", "start", "end", "from_spec", "to_spec")
_VERSION: Final = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\Z")
_ROOT_UNAVAILABLE: Final = frozenset(
    {
        "workspace_fix_root_not_absolute",
        "workspace_fix_root_missing",
        "workspace_fix_root_not_directory",
        "workspace_fix_root_not_utf8",
    }
)
_MAX_FIELD_CHARS: Final = 128
# Absence of a finding only means "fixed" if the supply-chain detector looked at
# everything. These coverage reasons say it did not; any snapshot_* reason says
# the snapshot behind the run was itself partial. A detector_not_run:* reason
# (today the not-yet-existing secrets detector) is deliberately not listed: the
# finding comes from the supply-chain detector, so another detector's gap cannot
# hide it. Unknown or missing coverage is treated as incomplete.
_BLOCKING_COVERAGE_REASONS: Final = frozenset(
    {"finding_cap", "supply_chain_incomplete", "lockfile_warnings", "advisory_data_unavailable"}
)
# Snapshot reasons that leave nothing unread: the dependency file was read and
# hashed but never audited (another ecosystem, or below audit discovery), so it
# cannot hide a finding in a file the audit checked.
_READ_SNAPSHOT_REASONS: Final = frozenset(
    {"snapshot_unsupported_dependency_input", "snapshot_undiscovered_dependency_input"}
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
_SELECT: Final = ", ".join(_COLUMNS)
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
    with store._connect() as connection:
        rows = connection.execute(
            f"""
            select {_SELECT} from workspace_fix_proposals
            where codebase_key = ? and worktree_key = ?
            order by created_at_ms desc, proposal_id desc
            limit ?
            """,
            (keys.codebase_key, keys.worktree_key, max(1, min(limit, MAX_LISTED_PROPOSALS))),
        ).fetchall()
    return [_payload(dict(zip(_COLUMNS, row, strict=True))) for row in rows]


def verify_proposals(store: Any, keys: assessments.WorktreeKeys, *, now_ms: int) -> None:
    """Settle applied proposals against the worktree's newest assessed run.

    Only the newest run is consulted, so the outcome is deterministic: a run
    that cannot vouch for the whole supply-chain input leaves a proposal as it
    is, and nothing but such a run can mark one fixed.
    """

    run = assessments.latest_assessed_run(store, keys)
    if run is None or not _supply_chain_verifiable(run["coverage"]):
        return
    findings = [item for item in run["findings"] if isinstance(item, dict)] if isinstance(run["findings"], list) else []
    started = run["started_at_ms"]
    with store._connect() as connection:
        connection.execute("begin immediate")
        rows = connection.execute(
            """
            select proposal_id, ecosystem, package_name, fix_version, advisory_ids_json, rule_ids_json,
                   snapshot_digest, applied_at_ms, state, verification_run_id
            from workspace_fix_proposals
            where codebase_key = ? and worktree_key = ? and state in ('applied', 'still_present')
            """,
            (keys.codebase_key, keys.worktree_key),
        ).fetchall()
        for proposal_id, ecosystem, package, fix_version, advisories, rules, digest, applied_at, state, prior in rows:
            # A run that started at or before the apply may have read the old manifest.
            if run["snapshot_digest"] == digest or not isinstance(started, int) or started <= applied_at:
                continue
            identity = (ecosystem, package, fix_version, set(json.loads(advisories)), set(json.loads(rules)))
            outcome = (
                "still_present" if any(_same_issue(finding, *identity) for finding in findings) else "verified_fixed"
            )
            if outcome == state and prior == run["run_id"]:
                continue
            connection.execute(
                """
                update workspace_fix_proposals set
                  state = ?, verified_at_ms = ?, verification_run_id = ?,
                  updated_at_ms = max(created_at_ms, ?)
                where proposal_id = ? and state in ('applied', 'still_present')
                """,
                (outcome, now_ms, run["run_id"], now_ms, proposal_id),
            )


def _same_issue(
    finding: dict[str, Any], ecosystem: str, package: str, fix_version: str, advisories: set[str], rules: set[str]
) -> bool:
    """Whether a later finding is the problem the proposal set out to fix.

    A finding id also hashes the resolved version, so a package that is still
    vulnerable after the edit gets a new id. Identity is the package plus
    either an overlapping advisory or rule id, or a version still below the fix.
    """

    if finding.get("ecosystem") != ecosystem or finding.get("package_name") != package:
        return False
    if advisories & _id_set(finding.get("advisory_ids")) or rules & _id_set(finding.get("rule_ids")):
        return True
    return _below(finding.get("package_version"), fix_version)


def _id_set(value: object) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _below(version: object, fix_version: str) -> bool:
    """Whether ``version`` is older than ``fix_version``; unreadable versions count as older."""

    found, target = (_VERSION.match(version) if isinstance(version, str) else None), _VERSION.match(fix_version)
    if found is None or target is None:
        return True
    left, right = tuple(int(part) for part in found.groups()[:3]), tuple(int(part) for part in target.groups()[:3])
    return left < right or (left == right and found.group(4) is not None and target.group(4) is None)


def _supply_chain_verifiable(coverage: object) -> bool:
    if not isinstance(coverage, dict):
        return False
    detectors, reasons = coverage.get("detectors"), coverage.get("reasons")
    if not isinstance(detectors, dict) or detectors.get("supply_chain") != "complete":
        return False
    if not isinstance(reasons, list) or not all(isinstance(reason, str) for reason in reasons):
        return False
    return not any(
        reason in _BLOCKING_COVERAGE_REASONS
        or (reason.startswith("snapshot_") and reason not in _READ_SNAPSHOT_REASONS)
        for reason in reasons
    )


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
    ids: list[str] = []
    with store._connect() as connection:
        connection.execute("begin immediate")
        for item in planned:
            existing = connection.execute(
                """
                select proposal_id, base_sha256, new_sha256, snapshot_digest from workspace_fix_proposals
                where codebase_key = ? and worktree_key = ? and finding_id = ? and manifest_path = ?
                  and state = 'prepared'
                """,
                (keys.codebase_key, keys.worktree_key, finding_id, item["manifest_path"]),
            ).fetchall()
            same = next(
                (
                    row[0]
                    for row in existing
                    if (row[1], row[2], row[3]) == (item["base_sha256"], item["new_sha256"], run["snapshot_digest"])
                ),
                None,
            )
            for row in existing:
                if row[0] != same:
                    connection.execute(
                        "update workspace_fix_proposals set state = 'stale', updated_at_ms = max(created_at_ms, ?)"
                        " where proposal_id = ?",
                        (now_ms, row[0]),
                    )
            if same is not None:
                ids.append(str(same))
                continue
            proposal_id = uuid.uuid4().hex
            raw_edits = item["edits"]
            if not isinstance(raw_edits, list):
                raise FixProposalError("workspace_fix_failed", 500)
            edits: list[object] = raw_edits
            connection.execute(
                f"insert into workspace_fix_proposals ({_SELECT}) values ({', '.join('?' for _ in _COLUMNS)})",
                (
                    proposal_id,
                    keys.codebase_key,
                    keys.worktree_key,
                    finding_id,
                    identity["ecosystem"],
                    identity["package_name"],
                    identity["fix_version"],
                    json.dumps(identity["advisory_ids"], separators=(",", ":")),
                    json.dumps(identity["rule_ids"], separators=(",", ":")),
                    run["run_id"],
                    run["snapshot_digest"],
                    item["manifest_path"],
                    item["base_sha256"],
                    item["new_sha256"],
                    json.dumps([_edit_record(edit) for edit in edits], separators=(",", ":")),
                    item["diff"],
                    "prepared",
                    now_ms,
                    now_ms,
                    None,
                    None,
                    None,
                ),
            )
            ids.append(proposal_id)
    return [_payload(row) for proposal_id in ids if (row := _fetch(store, proposal_id)) is not None]


def _worktree(store: Any, keys: assessments.WorktreeKeys) -> tuple[Path, bool]:
    with store._connect() as connection:
        row = connection.execute(
            "select private_root, paused from workspace_assessment_state where codebase_key = ? and worktree_key = ?",
            (keys.codebase_key, keys.worktree_key),
        ).fetchone()
    if row is None:
        raise FixProposalError("worktree_not_found", 404)
    return Path(str(row[0])), bool(row[1])


def _fetch(store: Any, proposal_id: str) -> dict[str, Any] | None:
    with store._connect() as connection:
        row = connection.execute(
            f"select {_SELECT} from workspace_fix_proposals where proposal_id = ?", (proposal_id,)
        ).fetchone()
    return dict(zip(_COLUMNS, row, strict=True)) if row is not None else None


def _set_state(store: Any, proposal_id: str, state: str, *, now_ms: int, applied: bool = False) -> None:
    with store._connect() as connection:
        connection.execute(
            """
            update workspace_fix_proposals set
              state = ?, updated_at_ms = max(created_at_ms, ?),
              applied_at_ms = case when ? then ? else applied_at_ms end
            where proposal_id = ? and state = 'prepared'
            """,
            (state, now_ms, 1 if applied else 0, now_ms, proposal_id),
        )


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

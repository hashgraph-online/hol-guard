"""Resident bridge for the ``package_audit_projection`` op.

The resident owns the pure projections of a workspace supply-chain audit: the
receipt authority map, advisory-alias enrichment from the cached bundle, the CI
severity gate, the empty-inventory outcome and the supply-chain findings of a
workspace assessment run. This module only transports one
request and strictly validates the reply. A missing, mismatched or malformed
answer raises :class:`NativePackageAuditProjectionError`; there is no Python
fallback.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeGuard

from .native_context import _resolve_digest_home
from .native_package_approval_hash import _transport
from .native_workspace_inventory import check_audit_deadline

_FEATURE = "package-audit-projection-v1"
_RECEIPT_KEYS = frozenset({"policy_decision", "capabilities_summary", "artifact_name", "scanner_evidence"})
_CI_KEYS = frozenset({"matched", "matched_packages", "threshold"})
_ACTIONS = frozenset({"allow", "warn", "review", "block"})
_FINDING_KEYS = frozenset(
    {
        "finding_id",
        "source_kind",
        "detector",
        "severity",
        "decision",
        "ecosystem",
        "package_name",
        "package_version",
        "fix_version",
        "rule_ids",
        "advisory_ids",
        "validation_state",
        "lifecycle_state",
    }
)
# The workspace projection reads only these; the rest of the audit stays local.
_PROJECTED_KEYS = ("evaluation", "audit_status", "lockfile_warnings")
_EVALUATION_KEYS = ("bundle_version", "packages")
_PACKAGE_KEYS = (
    "decision",
    "ecosystem",
    "name",
    "namespace",
    "resolvedVersion",
    "requestedVersion",
    "ruleId",
    "recommendedFixVersion",
    "reasons",
    "relatedAdvisoryIds",
    "advisoryAliases",
)
_REASON_KEYS = ("code", "severity", "advisoryId")
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
_FINDING_DECISIONS = frozenset({"block", "ask", "warn"})
# Matches PACKAGE_AUDIT_PROJECTION_MAX_BYTES; stays under the resident client frame limit.
_MAX_REQUEST_BYTES = 5 * 1024 * 1024
# Packages per alias request are capped well below that, since a large
# workspace's full package list can outgrow it.
_ALIAS_BATCH_BYTES = 1024 * 1024


class NativePackageAuditProjectionError(RuntimeError):
    """No authoritative native audit projection was available."""


@dataclass(frozen=True)
class SupplyChainProjection:
    """The supply-chain findings of one local audit and what it could not check.

    ``listed`` is ``None`` when the audit stopped early or warned about a
    lockfile, since its package list may then be short.
    """

    findings: list[dict[str, object]]
    listed: frozenset[tuple[str, str, str]] | None
    unresolved: int
    unchecked: int


def _guard_home(store: Any | None) -> Path:
    guard_home = getattr(store, "guard_home", None)
    return _resolve_digest_home(Path(guard_home) if guard_home else None)


def _send(query: dict[str, object], store: Any | None) -> dict[str, Any]:
    return _transport(
        {"query": query},
        _guard_home(store),
        operation="package_audit_projection",
        feature=_FEATURE,
        error=NativePackageAuditProjectionError,
        max_request_bytes=_MAX_REQUEST_BYTES,
    )


def native_audit_receipt_metadata(
    result: dict[str, object],
    *,
    workspace_dir: Path | None,
    store: Any | None,
) -> dict[str, object]:
    """Return the resident-derived receipt authority map for an audit result."""

    query: dict[str, object] = {"query": "receipt", "result": result}
    if workspace_dir is not None:
        query["workspace_dir"] = str(workspace_dir)
    if store is not None:
        query["store_path"] = str(store.path)
    payload = _send(query, store)
    decision = payload.get("policy_decision")
    if (
        set(payload) != _RECEIPT_KEYS
        or not isinstance(decision, str)
        or decision not in _ACTIONS
        or not isinstance(payload.get("capabilities_summary"), str)
        or not isinstance(payload.get("artifact_name"), str)
        or not isinstance(payload.get("scanner_evidence"), dict)
    ):
        raise NativePackageAuditProjectionError("Native audit receipt invalid")
    return payload


def native_advisory_aliases(packages: Sequence[object], *, store: Any) -> dict[int, list[str]]:
    """Return ``advisoryAliases`` the cached bundle adds, keyed by package index."""

    aliases: dict[int, list[str]] = {}
    for start, batch in _alias_batches(packages):
        check_audit_deadline()
        payload = _send({"query": "aliases", "packages": batch, "store_path": str(store.path)}, store)
        entries = payload.get("aliases")
        if set(payload) != {"aliases"} or not isinstance(entries, list):
            raise NativePackageAuditProjectionError("Native advisory aliases invalid")
        for entry in entries:
            index = entry.get("index") if isinstance(entry, dict) else None
            values = entry.get("aliases") if isinstance(entry, dict) else None
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < len(batch)
                or not isinstance(values, list)
                or not all(isinstance(value, str) for value in values)
            ):
                raise NativePackageAuditProjectionError("Native advisory aliases invalid")
            aliases[start + index] = values
    return aliases


def _alias_batches(packages: Sequence[object]) -> list[tuple[int, list[object]]]:
    """``packages`` in order as ``(first index, batch)`` pairs within ``_ALIAS_BATCH_BYTES``.

    The resident resolves each package on its own, so batching changes only
    how many requests carry the list. An empty list is still one request.
    """

    batches: list[tuple[int, list[object]]] = []
    # ``used`` counts the serialized array: brackets plus a comma per item.
    start, current, used = 0, [], 2
    for index, package in enumerate(packages):
        size = len(json.dumps(package, default=str, separators=(",", ":")).encode("utf-8")) + 1
        if current and used + size > _ALIAS_BATCH_BYTES:
            batches.append((start, current))
            start, current, used = index, [], 2
        current.append(package)
        used += size
    batches.append((start, current))
    return batches


def native_ci_gate_result(evaluation: dict[str, object], *, threshold: str, store: Any) -> dict[str, object]:
    """Return the resident's CI severity gate verdict for an audit evaluation."""

    payload = _send({"query": "ci_gate", "evaluation": evaluation, "threshold": threshold}, store)
    matched_packages = payload.get("matched_packages")
    if (
        set(payload) != _CI_KEYS
        or not isinstance(payload.get("matched"), bool)
        or not isinstance(matched_packages, list)
        or not all(isinstance(name, str) and name for name in matched_packages)
        or not isinstance(payload.get("threshold"), str)
    ):
        raise NativePackageAuditProjectionError("Native CI gate invalid")
    return payload


def native_empty_audit_outcome(
    *,
    manifest_paths: Sequence[str],
    lockfile_paths: Sequence[str],
    posture: dict[str, object],
    store: Any,
) -> tuple[str, str]:
    """Return the resident's ``(audit_outcome, message)`` for an empty inventory."""

    payload = _send(
        {
            "query": "empty_outcome",
            "manifest_paths": list(manifest_paths),
            "lockfile_paths": list(lockfile_paths),
            "posture": posture,
        },
        store,
    )
    outcome, message = payload.get("audit_outcome"), payload.get("message")
    if set(payload) != {"audit_outcome", "message"} or not isinstance(outcome, str) or not isinstance(message, str):
        raise NativePackageAuditProjectionError("Native empty audit outcome invalid")
    return outcome, message


def native_workspace_package_findings(
    worktree_key: str, payload: Mapping[str, object], *, store: Any | None
) -> SupplyChainProjection:
    """Return the resident's supply-chain findings for a workspace audit, most severe first."""

    projected = {key: payload[key] for key in _PROJECTED_KEYS if key in payload}
    if "evaluation" in projected:
        projected["evaluation"] = _projected_evaluation(projected["evaluation"])
    reply = _send({"query": "workspace_findings", "worktree_key": worktree_key, "payload": projected}, store)
    findings, listed = reply.get("findings"), reply.get("listed")
    unresolved, unchecked = reply.get("unresolved"), reply.get("unchecked")
    if (
        set(reply) != {"findings", "listed", "unresolved", "unchecked"}
        or not isinstance(findings, list)
        or not all(_valid_finding(item) for item in findings)
        or not (listed is None or (isinstance(listed, list) and all(_valid_coordinate(item) for item in listed)))
        or not _count(unresolved)
        or not _count(unchecked)
    ):
        raise NativePackageAuditProjectionError("Native workspace package findings invalid")
    return SupplyChainProjection(
        findings=findings,
        listed=None if listed is None else frozenset(tuple(item) for item in listed),
        unresolved=unresolved,
        unchecked=unchecked,
    )


def native_package_identities(
    findings: Sequence[Mapping[str, object]],
    earlier: Sequence[object],
    listed: frozenset[tuple[str, str, str]] | None,
    *,
    store: Any | None,
) -> tuple[list[object], list[bool]]:
    """Return the id each finding keeps from ``earlier`` and which earlier packages are settled.

    Both lists are aligned with their input: ``finding_ids`` with ``findings``
    and ``settled`` with ``earlier``.
    """

    query: dict[str, object] = {
        "query": "package_identities",
        "findings": [dict(item) for item in findings],
        "earlier": list(earlier),
    }
    if listed is not None:
        query["listed"] = sorted(list(item) for item in listed)
    reply = _send(query, store)
    finding_ids, settled = reply.get("finding_ids"), reply.get("settled")
    if (
        set(reply) != {"finding_ids", "settled"}
        or not isinstance(finding_ids, list)
        or len(finding_ids) != len(findings)
        or not all(_kept_id(item, new_id) for item, new_id in zip(findings, finding_ids, strict=True))
        or not isinstance(settled, list)
        or len(settled) != len(earlier)
        or not all(isinstance(item, bool) for item in settled)
    ):
        raise NativePackageAuditProjectionError("Native package identities invalid")
    return finding_ids, settled


def _projected_evaluation(evaluation: object) -> object:
    """``evaluation`` with only the fields the resident reads, so a large audit stays under the request limit."""

    if not isinstance(evaluation, Mapping):
        return evaluation
    projected = {key: evaluation[key] for key in _EVALUATION_KEYS if key in evaluation}
    packages = projected.get("packages")
    if isinstance(packages, list):
        projected["packages"] = [_projected(package, _PACKAGE_KEYS) for package in packages]
        for package in projected["packages"]:
            if isinstance(package, dict) and isinstance(package.get("reasons"), list):
                package["reasons"] = [_projected(reason, _REASON_KEYS) for reason in package["reasons"]]
    return projected


def _projected(item: object, keys: tuple[str, ...]) -> object:
    return {key: item[key] for key in keys if key in item} if isinstance(item, Mapping) else item


def _kept_id(finding: Mapping[str, object], finding_id: object) -> bool:
    """A package finding may take an earlier id; any other finding keeps its own."""

    if finding.get("source_kind") == "supply_chain":
        return _text(finding_id)
    return finding_id == finding.get("finding_id")


def _valid_finding(item: object) -> bool:
    return (
        isinstance(item, dict)
        and set(item) == _FINDING_KEYS
        and _text(item["finding_id"])
        and item["source_kind"] == "supply_chain"
        and item["detector"] == "supply_chain_local_v1"
        and item["severity"] in _SEVERITIES
        and item["decision"] in _FINDING_DECISIONS
        and _text(item["ecosystem"])
        and _text(item["package_name"])
        and (item["package_version"] is None or _text(item["package_version"]))
        and (item["fix_version"] is None or _text(item["fix_version"]))
        and _texts(item["rule_ids"])
        and _texts(item["advisory_ids"])
        and item["validation_state"] == "confirmed"
        and item["lifecycle_state"] == "open"
    )


def _valid_coordinate(item: object) -> bool:
    return isinstance(item, list) and len(item) == 3 and all(isinstance(part, str) for part in item)


def _count(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _texts(value: object) -> bool:
    return isinstance(value, list) and all(_text(item) for item in value)


def _machine_name() -> str | None:
    try:
        machine = socket.gethostname().strip()
    except OSError:
        return None
    return machine or None


def native_cloud_audit_payload(
    store: Any,
    *,
    workspace_dir: Path,
    workspace_id: str,
    inventory_digest: str,
    sbom_paths: Sequence[str] = (),
    before_workspace_dir: Path | None = None,
    include_lockfile_warnings: bool = False,
    mode: str = "paged",
    page_size: int | None = None,
) -> dict[str, object]:
    """Return the resident-built Cloud workspace-audit request payload.

    The resident rebuilds the inventory from the options of the
    ``native_workspace_inventory`` read that reported ``inventory_digest`` and
    rejects a workspace whose snapshot no longer matches it.
    """

    query: dict[str, object] = {
        "query": "cloud_payload",
        "workspace_dir": str(workspace_dir),
        "workspace_id": workspace_id,
        "store_path": str(store.path),
        "inventory_workspace_dir": str(Path(workspace_dir).expanduser().absolute()),
        "sbom_paths": [str(path) for path in sbom_paths],
        "include_lockfile_warnings": include_lockfile_warnings,
        "inventory_digest": inventory_digest,
        "mode": mode,
    }
    machine = _machine_name()
    if machine is not None:
        query["machine"] = machine
    if before_workspace_dir is not None:
        query["before_workspace_dir"] = str(Path(before_workspace_dir).expanduser().absolute())
    if page_size is not None:
        query["page_size"] = page_size
    payload = _send(query, store)
    if not isinstance(payload.get("packages"), list) or not isinstance(payload.get("workspaceFingerprint"), str):
        raise NativePackageAuditProjectionError("Native cloud audit payload invalid")
    return payload


def native_batch_url(
    store: Any,
    sync_url: str,
    workspace_id: str,
    *,
    job_id: str | None = None,
    page_size: int | None = None,
) -> str:
    """Return the resident-normalised Cloud batch (or batch-job) URL."""

    query: dict[str, object] = {"query": "batch_url", "sync_url": sync_url, "workspace_id": workspace_id}
    if job_id is not None:
        query["job_id"] = job_id
        query["page_size"] = 1 if page_size is None else page_size
    payload = _send(query, store)
    url = payload.get("url")
    if set(payload) != {"url"} or not isinstance(url, str) or not url:
        raise NativePackageAuditProjectionError("Native cloud audit url invalid")
    return url


def native_normalize_cloud_audit_response(store: Any, response: dict[str, object]) -> dict[str, object]:
    """Return the resident's local-summary shape for a Cloud audit response."""

    payload = _send({"query": "cloud_normalize", "response": response}, store)
    if not isinstance(payload.get("decision"), str) or not isinstance(payload.get("packages"), list):
        raise NativePackageAuditProjectionError("Native cloud audit response invalid")
    return payload


def native_managed_workspaces(
    store: Any,
    *,
    candidates: bool,
    workspace_dir: Path | None = None,
) -> tuple[str, ...]:
    """Return the ordered managed audit workspaces, or the resolved audit candidates."""

    query: dict[str, object] = {
        "query": "workspace_candidates",
        "installs": list(store.list_managed_installs()),
        "candidates": candidates,
    }
    if workspace_dir is not None:
        query["workspace_dir"] = str(workspace_dir)
    payload = _send(query, store)
    workspaces = payload.get("workspaces")
    if (
        set(payload) != {"workspaces"}
        or not isinstance(workspaces, list)
        or not all(isinstance(item, str) for item in workspaces)
    ):
        raise NativePackageAuditProjectionError("Native managed workspaces invalid")
    return tuple(workspaces)

"""Resident bridge for the ``package_audit_projection`` op.

The resident owns the pure projections of a workspace supply-chain audit: the
receipt authority map, advisory-alias enrichment from the cached bundle, the CI
severity gate and the empty-inventory outcome. This module only transports one
request and strictly validates the reply. A missing, mismatched or malformed
answer raises :class:`NativePackageAuditProjectionError`; there is no Python
fallback.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .native_context import _resolve_digest_home
from .native_package_approval_hash import _transport

_FEATURE = "package-audit-projection-v1"
_RECEIPT_KEYS = frozenset({"policy_decision", "capabilities_summary", "artifact_name", "scanner_evidence"})
_CI_KEYS = frozenset({"matched", "matched_packages", "threshold"})
_ACTIONS = frozenset({"allow", "warn", "review", "block"})
# Matches PACKAGE_AUDIT_PROJECTION_MAX_BYTES; stays under the resident client frame limit.
_MAX_REQUEST_BYTES = 5 * 1024 * 1024


class NativePackageAuditProjectionError(RuntimeError):
    """No authoritative native audit projection was available."""


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

    payload = _send({"query": "aliases", "packages": list(packages), "store_path": str(store.path)}, store)
    entries = payload.get("aliases")
    if set(payload) != {"aliases"} or not isinstance(entries, list):
        raise NativePackageAuditProjectionError("Native advisory aliases invalid")
    aliases: dict[int, list[str]] = {}
    for entry in entries:
        index = entry.get("index") if isinstance(entry, dict) else None
        values = entry.get("aliases") if isinstance(entry, dict) else None
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < len(packages)
            or not isinstance(values, list)
            or not all(isinstance(value, str) for value in values)
        ):
            raise NativePackageAuditProjectionError("Native advisory aliases invalid")
        aliases[index] = values
    return aliases


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

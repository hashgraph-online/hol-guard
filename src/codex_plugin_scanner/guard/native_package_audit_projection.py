"""Resident bridge for the ``package_audit_projection`` op.

The resident owns the pure projections of a workspace supply-chain audit: the
receipt authority map, advisory-alias enrichment from the cached bundle, the CI
severity gate and the empty-inventory outcome. This module only transports one
request and strictly validates the reply. A missing, mismatched or malformed
answer raises :class:`NativePackageAuditProjectionError`; there is no Python
fallback.
"""

from __future__ import annotations

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

"""Audit receipts helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _audit_package_inventory_for_receipt(
    package_items: list[dict[str, object]],
    *,
    limit: int = 500,
    bundle: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    ranked = sorted(
        package_items,
        key=lambda item: (
            str(item.get("ecosystem") or ""),
            str(item.get("name") or ""),
        ),
    )
    return [_api._enrich_package_with_advisory_aliases(item, bundle=bundle) for item in ranked[:limit]]


def _audit_package_findings_for_receipt(
    package_items: list[dict[str, object]],
    *,
    limit: int = 100,
    bundle: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    decision_rank_map = {"block": 4, "ask": 3, "warn": 2, "monitor": 1, "allow": 0}
    ranked: list[tuple[int, int, dict[str, object]]] = []
    for item in package_items:
        if not _api._is_actionable_package_finding(item):
            continue
        decision = str(item.get("decision") or "monitor")
        severity_rank = _api._package_severity_rank(item)
        decision_rank = decision_rank_map.get(decision, 0)
        ranked.append((decision_rank, severity_rank, item))
    ranked.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
    return [_api._enrich_package_with_advisory_aliases(item, bundle=bundle) for _, _, item in ranked[:limit]]


def workspace_audit_path_hashes(
    workspace_dir: _api.Path | None,
    manifest_paths: _api.Sequence[str],
    lockfile_paths: _api.Sequence[str],
) -> dict[str, list[str]]:
    if workspace_dir is None:
        return {"manifest_hashes": [], "lockfile_hashes": []}
    return {
        "manifest_hashes": _api._hash_existing_paths(workspace_dir, manifest_paths),
        "lockfile_hashes": _api._hash_existing_paths(workspace_dir, lockfile_paths),
    }


def _resolve_empty_audit_outcome(
    *,
    manifest_paths: _api.Sequence[str],
    lockfile_paths: _api.Sequence[str],
    posture: dict[str, object],
) -> tuple[str, str]:
    supply_status = str(posture.get("status") or "")
    supply_detail = str(posture.get("detail") or _api._posture_detail(supply_status))
    if supply_status == "sync_required":
        return (
            "sync_required",
            "Sync Guard supply-chain intel on this device before auditing workspace packages.",
        )
    if supply_status in {"not_connected", "workspace_required", "expired", "degraded"}:
        return (supply_status, supply_detail)
    if lockfile_paths or manifest_paths:
        return (
            "inventory_empty",
            "Guard found project files but could not index any packages for audit.",
        )
    return (
        "no_project_files",
        "No supported manifests or lockfiles found in this workspace.",
    )


def _incomplete_audit_receipt_metadata(
    result: dict[str, object],
    *,
    workspace_dir: _api.Path | None = None,
) -> dict[str, object]:
    message = str(result.get("message") or "Workspace audit did not complete.")
    outcome = str(result.get("audit_outcome") or "incomplete")
    manifest_raw = result.get("manifest_paths")
    manifest_paths = (
        [str(path) for path in manifest_raw if isinstance(path, str)] if isinstance(manifest_raw, (list, tuple)) else []
    )
    lockfile_raw = result.get("lockfile_paths")
    lockfile_paths = (
        [str(path) for path in lockfile_raw if isinstance(path, str)] if isinstance(lockfile_raw, (list, tuple)) else []
    )
    path_hashes = _api.workspace_audit_path_hashes(workspace_dir, manifest_paths, lockfile_paths)
    policy_decision: _api.GuardAction = (
        "review" if outcome in {"sync_required", "inventory_empty", "no_project_files"} else "warn"
    )
    return {
        "policy_decision": policy_decision,
        "capabilities_summary": message,
        "artifact_name": "Workspace supply-chain audit",
        "scanner_evidence": {
            "operation": "audit",
            "audit_status": "incomplete",
            "audit_outcome": outcome,
            "audit_decision": "monitor",
            "blocked_package_count": 0,
            "total_packages": 0,
            "manifest_paths": manifest_paths,
            "lockfile_paths": lockfile_paths,
            "manifest_hashes": path_hashes["manifest_hashes"],
            "lockfile_hashes": path_hashes["lockfile_hashes"],
            "package_findings": [],
        },
    }


def audit_receipt_metadata(
    result: dict[str, object],
    *,
    workspace_dir: _api.Path | None = None,
    store: _api.Any | None = None,
) -> dict[str, object]:
    evaluation = result.get("evaluation")
    if not isinstance(evaluation, dict):
        return _api._incomplete_audit_receipt_metadata(result, workspace_dir=workspace_dir)
    decision = str(evaluation.get("decision") or "monitor")
    packages = evaluation.get("packages")
    package_items = [item for item in packages if isinstance(item, dict)] if isinstance(packages, list) else []
    blocked_packages = [item for item in package_items if str(item.get("decision") or "") == "block"]
    bundle = _api._cached_supply_chain_bundle_payload(store) if store is not None else None
    package_findings = _api._audit_package_findings_for_receipt(package_items, bundle=bundle)
    package_inventory = _api._audit_package_inventory_for_receipt(package_items, bundle=bundle)
    policy_decision: _api.GuardAction = "allow"
    if decision == "block":
        policy_decision = "block"
    elif decision == "ask":
        policy_decision = "review"
    elif decision == "warn":
        policy_decision = "warn"
    inventory = result.get("inventory")
    inventory_summary = inventory if isinstance(inventory, dict) else {}
    manifest_paths = list(_api._string_items(result.get("manifest_paths")))
    lockfile_paths = list(_api._string_items(result.get("lockfile_paths")))
    path_hashes = _api.workspace_audit_path_hashes(workspace_dir, manifest_paths, lockfile_paths)
    return {
        "policy_decision": policy_decision,
        "capabilities_summary": (
            f"Workspace audit completed with {policy_decision} decision across "
            f"{inventory_summary.get('total_packages', len(package_items))} packages."
        ),
        "artifact_name": "Workspace supply-chain audit",
        "scanner_evidence": {
            "operation": "audit",
            "audit_decision": decision,
            "blocked_package_count": len(blocked_packages),
            "lockfile_paths": lockfile_paths,
            "manifest_paths": manifest_paths,
            "manifest_hashes": path_hashes["manifest_hashes"],
            "lockfile_hashes": path_hashes["lockfile_hashes"],
            "total_packages": inventory_summary.get("total_packages", len(package_items)),
            "package_inventory": package_inventory,
            "package_findings": package_findings,
        },
    }


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402

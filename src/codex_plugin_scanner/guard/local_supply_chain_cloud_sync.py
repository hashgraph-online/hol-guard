"""Cloud sync helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _workspace_audit_lockfile_context(
    workspace_dir: _api.Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    inventory: tuple[dict[str, object], ...],
) -> dict[str, object] | None:
    if not lockfile_paths:
        return None
    lockfile_path = _api.resolve_path_within_workspace(workspace_dir, lockfile_paths[0])
    if lockfile_path is None or not lockfile_path.exists():
        return None
    lockfile_text = _api._read_workspace_audit_text(workspace_dir, lockfile_paths[0])
    if lockfile_text is None:
        return None
    manifest_hash = None
    if manifest_paths:
        manifest_bytes = _api.read_bytes_within_workspace(workspace_dir, manifest_paths[0])
        if manifest_bytes is not None and not _api._is_audit_sensitive_basename(_api.Path(manifest_paths[0]).name):
            manifest_hash = _api.stable_digest_hex(manifest_bytes)
    return {
        "dependencyCount": len(inventory),
        "fileName": lockfile_path.name,
        "lockfileHash": _api.stable_digest_hex(lockfile_text.encode("utf-8")),
        "manifestHash": manifest_hash,
    }


def _workspace_audit_fingerprint(
    *,
    workspace_id: str,
    workspace_dir: _api.Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    policy_version: str,
) -> str:
    manifest_hashes = _api._hash_existing_paths(workspace_dir, manifest_paths)
    lockfile_hashes = _api._hash_existing_paths(workspace_dir, lockfile_paths)
    return _api.stable_digest_hex(
        _api.json.dumps(
            {
                "workspace_id": workspace_id,
                "workspace_name": workspace_dir.name,
                "manifest_hashes": manifest_hashes,
                "lockfile_hashes": lockfile_hashes,
                "policy_version": policy_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
    )


def _hash_existing_paths(workspace_dir: _api.Path, relative_paths: _api.Sequence[str]) -> list[str]:
    hashes: list[str] = []
    for relative_path in relative_paths:
        payload = _api.read_bytes_within_workspace(workspace_dir, relative_path)
        if payload is None:
            continue
        hashes.append(_api.stable_digest_hex(payload))
    return hashes


def _normalize_cloud_audit_response(response: dict[str, object]) -> dict[str, object]:
    return {
        "decision": str(response.get("decision") or "monitor"),
        "packages": list(_api._dict_items(response.get("packages"))),
        "reasons": list(_api._dict_items(response.get("reasons"))),
        "enforcement": str(response.get("enforcement") or "premium_cloud"),
        "entitlement_state": str(response.get("entitlementState") or "premium"),
        "cache_status": str(response.get("cacheStatus") or "miss"),
        "processed_count": _api._int_value(response.get("processedCount")) or 0,
        "total_packages": _api._int_value(response.get("totalPackages")) or 0,
        "status": str(response.get("status") or "completed"),
        "workspace_id": str(response.get("workspaceId") or ""),
    }


def _ci_gate_result(evaluation: dict[str, object], *, threshold: str) -> dict[str, object]:
    threshold_rank = _api._SEVERITY_RANK.get(threshold, _api._SEVERITY_RANK["high"])
    matched_packages: list[str] = []
    packages = evaluation.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict):
                continue
            if _api._package_severity_rank(package) < threshold_rank:
                continue
            package_name = package.get("name")
            if isinstance(package_name, str) and package_name:
                matched_packages.append(package_name)
    return {
        "matched": bool(matched_packages),
        "matched_packages": matched_packages,
        "threshold": threshold,
    }


def _package_severity_rank(package: dict[str, object]) -> int:
    normalized_severity = package.get("normalized_severity")
    if isinstance(normalized_severity, str):
        return _api._SEVERITY_RANK.get(normalized_severity, _api._SEVERITY_RANK["unknown"])
    reasons = package.get("reasons")
    if not isinstance(reasons, list):
        return _api._SEVERITY_RANK["unknown"]
    highest = _api._SEVERITY_RANK["unknown"]
    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        severity = reason.get("severity")
        if not isinstance(severity, str):
            continue
        highest = max(highest, _api._SEVERITY_RANK.get(severity, _api._SEVERITY_RANK["unknown"]))
    return highest


def _inventory_summary(inventory: tuple[dict[str, object], ...]) -> dict[str, int]:
    direct_count = sum(1 for item in inventory if bool(item.get("direct")))
    transitive_count = len(inventory) - direct_count
    sbom_count = sum(1 for item in inventory if not bool(item.get("direct")))
    return {
        "direct_package_count": direct_count,
        "sbom_package_count": sbom_count,
        "total_packages": len(inventory),
        "transitive_package_count": transitive_count,
    }


def sync_managed_workspace_audits(
    store: _api.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    workspace_dir: _api.Path | None = None,
) -> dict[str, object]:
    runner = _api._runtime_runner_module()
    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    workspace_id = store.get_cloud_workspace_id()
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        raise runner.GuardSyncNotConfiguredError(
            "Guard Cloud is not connected yet. Run `hol-guard connect` to sign in and pair this machine, "
            "or use `hol-guard login` as a compatibility alias for the same browser flow."
        )
    synced_at = _api.datetime.now(_api.timezone.utc).isoformat()
    workspaces_payload: list[dict[str, object]] = []
    completed_jobs = 0
    failed_jobs = 0
    incomplete_jobs = 0
    queued_jobs = 0
    skipped_workspaces = 0
    for candidate in _api._managed_workspace_audit_candidates(store, workspace_dir=workspace_dir):
        workspace_label = candidate.name or str(candidate)
        try:
            manifest_paths, lockfile_paths, _sbom_paths, inventory = _api._workspace_audit_inventory(
                candidate,
                sbom_paths=(),
            )
            if not inventory:
                skipped_workspaces += 1
                workspaces_payload.append(
                    {
                        "workspace": workspace_label,
                        "status": "skipped",
                        "message": "No supported package inventory was detected for workspace audit sync.",
                        "package_count": 0,
                    }
                )
                continue
            request_payload = _api._build_cloud_audit_payload(
                workspace_dir=candidate,
                workspace_id=workspace_id,
                store=store,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                inventory=inventory,
                mode="job",
                page_size=min(_api._CLOUD_AUDIT_SYNC_PAGE_SIZE, max(len(inventory), 1)),
            )
            enqueue_response = _api._enqueue_cloud_workspace_audit_job(
                auth_context=resolved_auth_context,
                request_payload=request_payload,
                workspace_id=workspace_id,
            )
            job_id = str(enqueue_response.get("jobId") or "").strip()
            final_response = _api._poll_cloud_workspace_audit_job(
                auth_context=resolved_auth_context,
                job_id=job_id,
                workspace_id=workspace_id,
            )
            final_status = (
                str(final_response.get("status") or enqueue_response.get("status") or "queued").strip().lower()
            )
            cloud_visible_count = _api._int_value(final_response.get("totalPackages"))
            cloud_processed_count = _api._int_value(final_response.get("processedCount"))
            incomplete_cloud_projection = (
                final_status == "completed" and cloud_visible_count is not None and cloud_visible_count < len(inventory)
            )
            if incomplete_cloud_projection:
                incomplete_jobs += 1
                workspace_status = "partial"
            else:
                workspace_status = final_status
                if final_status == "completed":
                    completed_jobs += 1
                elif final_status == "failed":
                    failed_jobs += 1
                else:
                    queued_jobs += 1
            message = final_response.get("error")
            if incomplete_cloud_projection:
                message = (
                    "Guard Cloud accepted fewer package rows than hol-guard discovered "
                    f"({cloud_visible_count} of {len(inventory)} visible)."
                )
            workspaces_payload.append(
                {
                    "workspace": workspace_label,
                    "workspace_fingerprint": request_payload.get("workspaceFingerprint"),
                    "job_id": job_id,
                    "status": workspace_status,
                    "package_count": len(inventory),
                    "cloud_processed_count": cloud_processed_count,
                    "cloud_visible_count": cloud_visible_count,
                    "manifest_paths": list(manifest_paths),
                    "lockfile_paths": list(lockfile_paths),
                    "message": message,
                }
            )
        except (
            runner.GuardSyncAuthorizationExpiredError,
            runner.GuardSyncNotAvailableError,
            runner.GuardSyncNotConfiguredError,
        ):
            raise
        except (OSError, RuntimeError, ValueError) as error:
            failed_jobs += 1
            workspaces_payload.append(
                {
                    "workspace": workspace_label,
                    "status": "failed",
                    "message": str(error),
                    "package_count": 0,
                }
            )
    if failed_jobs > 0 and completed_jobs == 0 and queued_jobs == 0 and incomplete_jobs == 0:
        status = "failed"
    elif failed_jobs > 0 or incomplete_jobs > 0:
        status = "partial"
    elif completed_jobs > 0 or queued_jobs > 0:
        status = "synced"
    else:
        status = "idle"
    summary: dict[str, object] = {
        "synced_at": synced_at,
        "status": status,
        "workspace_count": len(workspaces_payload),
        "completed_jobs": completed_jobs,
        "queued_jobs": queued_jobs,
        "failed_jobs": failed_jobs,
        "incomplete_jobs": incomplete_jobs,
        "skipped_workspaces": skipped_workspaces,
        "workspaces": workspaces_payload,
    }
    store.set_sync_payload("workspace_audits_sync_summary", summary, synced_at)
    return summary


def sync_supply_chain_cloud_state(
    store: _api.GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    workspace_dir: _api.Path | None = None,
) -> dict[str, object]:
    resolved_auth_context = auth_context if auth_context is not None else _api._resolve_guard_sync_auth_context(store)
    bundle_summary = _api._call_sync_with_optional_auth_context(
        _api.sync_supply_chain_bundle,
        store=store,
        auth_context=resolved_auth_context,
    )
    payload = dict(bundle_summary) if isinstance(bundle_summary, dict) else {}
    workspace_audits = _api.sync_managed_workspace_audits(
        store,
        auth_context=resolved_auth_context,
        workspace_dir=workspace_dir,
    )
    payload["workspace_audits"] = workspace_audits
    payload.setdefault("synced_at", workspace_audits.get("synced_at"))
    return payload


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402

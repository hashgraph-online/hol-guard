"""Workspace supply-chain audit, scan and explain payloads for the CLI and daemon control routes."""

from __future__ import annotations

import os
import shlex
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots, resolves_within_root

from . import local_supply_chain as _lsc
from . import supply_chain_cloud_audit as _cloud_audit
from .config import GuardConfig
from .native_package_audit_projection import (
    NativePackageAuditProjectionError,
    native_advisory_aliases,
    native_audit_receipt_metadata,
    native_ci_gate_result,
    native_cloud_audit_payload,
    native_empty_audit_outcome,
    native_normalize_cloud_audit_response,
)
from .native_workspace_inventory import NativeWorkspaceInventoryError, native_workspace_inventory
from .runtime.package_intent_common import (
    PackageIntent,
    PackageIntentTarget,
    build_package_request_artifact,
)
from .runtime.package_protect_projection import (
    LOCAL_SUPPLY_CHAIN_HARNESS as _LOCAL_SUPPLY_CHAIN_HARNESS,
)


def resolve_supply_chain_audit_workspace_dir(
    *,
    workspace_dir_value: object,
    workspace_value: object,
    allowed_roots: tuple[Path, ...],
    managed_workspace_dirs: Sequence[str] | None = None,
    reject_invalid_explicit: bool = False,
) -> Path | None:
    for candidate in (workspace_dir_value, workspace_value):
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        resolved = resolve_path_within_allowed_roots(
            candidate,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None:
            return resolved
        if reject_invalid_explicit:
            raise ValueError("workspace_dir_invalid")
    cursor_project = os.environ.get("CURSOR_PROJECT_DIR", "").strip()
    if cursor_project:
        resolved = resolve_path_within_allowed_roots(
            cursor_project,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None and _lsc._workspace_has_project_markers(resolved):
            return resolved
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        cwd = None
    if cwd is not None and _lsc._workspace_has_project_markers(cwd):
        for root in allowed_roots:
            if resolves_within_root(root, cwd, require_exists=True):
                return cwd
    for managed_workspace in managed_workspace_dirs or ():
        resolved = resolve_path_within_allowed_roots(
            managed_workspace,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None and _lsc._workspace_has_project_markers(resolved):
            return resolved
    return None


def audit_receipt_metadata(
    result: dict[str, object],
    *,
    workspace_dir: Path | None = None,
    store: Any | None = None,
) -> dict[str, object]:
    return native_audit_receipt_metadata(result, workspace_dir=workspace_dir, store=store)


def _enrich_evaluation_packages_with_advisory_aliases(
    evaluation: dict[str, object],
    store: Any,
) -> dict[str, object]:
    packages = evaluation.get("packages")
    if not isinstance(packages, list):
        return evaluation
    aliases = native_advisory_aliases(packages, store=store)
    enriched_packages: list[dict[str, object]] = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            continue
        enriched_packages.append({**package, "advisoryAliases": aliases[index]} if index in aliases else package)
    return {**evaluation, "packages": enriched_packages}


def build_workspace_scan_payload(
    *,
    store: Any,
    config: GuardConfig,
    workspace_dir: Path,
    now: str,
) -> tuple[dict[str, object], int]:
    return build_workspace_audit_payload(
        store=store,
        config=config,
        workspace_dir=workspace_dir,
        now=now,
        command_name="scan",
        sbom_paths=(),
    )


def build_workspace_audit_payload(
    *,
    store: Any,
    config: GuardConfig,
    workspace_dir: Path,
    now: str,
    command_name: str,
    sbom_paths: Sequence[str],
    ci: bool = False,
    fail_on: str = "high",
    before_workspace_dir: Path | None = None,
    after_workspace_dir: Path | None = None,
) -> tuple[dict[str, object], int]:
    runner = _lsc._runtime_runner_module()

    target_workspace_dir = after_workspace_dir or workspace_dir
    posture = _lsc.build_local_supply_chain_posture(store, config, now=now)
    diff_summary: dict[str, object] | None = None
    effective_before_dir = (
        before_workspace_dir if before_workspace_dir is not None and after_workspace_dir is not None else None
    )
    workspace_inventory = native_workspace_inventory(
        store,
        target_workspace_dir,
        sbom_paths=sbom_paths,
        before_workspace_dir=effective_before_dir,
        include_lockfile_warnings=True,
    )
    manifest_paths = workspace_inventory.manifest_paths
    lockfile_paths = workspace_inventory.lockfile_paths
    resolved_sbom_paths = workspace_inventory.sbom_paths
    inventory = workspace_inventory.inventory
    diff_summary = workspace_inventory.diff
    if not inventory:
        audit_outcome, message = native_empty_audit_outcome(
            manifest_paths=manifest_paths,
            lockfile_paths=lockfile_paths,
            posture=posture,
            store=store,
        )
        return (
            {
                "generated_at": now,
                "mode": command_name,
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "sbom_paths": list(resolved_sbom_paths),
                "audit_outcome": audit_outcome,
                "audit_status": "incomplete",
                "message": message,
                "supply_chain": posture,
            },
            1,
        )
    evaluation: dict[str, object]
    source = "local"
    fallback_reason: dict[str, object] | None = None
    if _cloud_audit._should_use_cloud_workspace_audit(store=store, posture=posture):
        try:
            auth_context = _lsc._resolve_guard_sync_auth_context(store)
            workspace_id = store.get_cloud_workspace_id()
            assert workspace_id is not None
            request_payload = native_cloud_audit_payload(
                store,
                workspace_dir=target_workspace_dir,
                workspace_id=workspace_id,
                inventory_digest=workspace_inventory.inventory_digest,
                sbom_paths=sbom_paths,
                before_workspace_dir=effective_before_dir,
                include_lockfile_warnings=True,
            )
            cloud_response, fallback_reason = _cloud_audit._run_cloud_workspace_audit(
                store=store,
                request_payload=request_payload,
                auth_context=auth_context,
                workspace_id=workspace_id,
            )
            if cloud_response is not None:
                evaluation = native_normalize_cloud_audit_response(store, cloud_response)
                source = "cloud"
            else:
                evaluation = _workspace_local_evaluation(
                    store=store,
                    workspace_dir=target_workspace_dir,
                    sbom_paths=sbom_paths,
                    before_workspace_dir=effective_before_dir,
                    manifest_paths=manifest_paths,
                    lockfile_paths=lockfile_paths,
                    command_name=command_name,
                    inventory_digest=workspace_inventory.inventory_digest,
                    now=now,
                )
        except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncNotConfiguredError, RuntimeError) as error:
            fallback_reason = (
                {
                    "code": "native_projection_unavailable",
                    "message": "Guard could not build or read the Cloud audit natively, so Guard fell back locally.",
                }
                if isinstance(error, NativePackageAuditProjectionError)
                else {
                    "code": "cloud_auth_error",
                    "message": "Guard cloud authorization could not be refreshed, so Guard fell back locally.",
                }
            )
            evaluation = _workspace_local_evaluation(
                store=store,
                workspace_dir=target_workspace_dir,
                sbom_paths=sbom_paths,
                before_workspace_dir=effective_before_dir,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                command_name=command_name,
                inventory_digest=workspace_inventory.inventory_digest,
                now=now,
            )
    else:
        evaluation = _workspace_local_evaluation(
            store=store,
            workspace_dir=target_workspace_dir,
            sbom_paths=sbom_paths,
            before_workspace_dir=effective_before_dir,
            manifest_paths=manifest_paths,
            lockfile_paths=lockfile_paths,
            command_name=command_name,
            inventory_digest=workspace_inventory.inventory_digest,
            now=now,
        )
    evaluation = _enrich_evaluation_packages_with_advisory_aliases(evaluation, store)
    payload: dict[str, object] = {
        "generated_at": now,
        "mode": command_name,
        "source": source,
        "manifest_paths": list(manifest_paths),
        "lockfile_paths": list(lockfile_paths),
        "sbom_paths": list(resolved_sbom_paths),
        "inventory": _inventory_summary(inventory),
        "evaluation": evaluation,
        "supply_chain": posture,
    }
    lockfile_warnings = workspace_inventory.lockfile_warnings
    if lockfile_warnings:
        payload["lockfile_warnings"] = list(lockfile_warnings)
    if diff_summary is not None:
        payload["diff"] = diff_summary
    if fallback_reason is not None:
        payload["fallback_reason"] = fallback_reason
    exit_code = _evaluation_exit_code(str(evaluation.get("decision") or "monitor"))
    if ci:
        ci_result = native_ci_gate_result(evaluation, threshold=fail_on, store=store)
        payload["ci"] = ci_result
        if ci_result["matched"]:
            exit_code = 3
    return (payload, exit_code)


def _workspace_local_evaluation(
    *,
    store: Any,
    workspace_dir: Path,
    sbom_paths: Sequence[str],
    before_workspace_dir: Path | None,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    command_name: str,
    inventory_digest: str,
    now: str,
) -> dict[str, object]:
    # The targets walk repeats the audit's inventory options so its snapshot
    # digest is comparable; a workspace that changed in between is rejected
    # instead of scoring a different package set than the one reported.
    scanned = native_workspace_inventory(
        store,
        workspace_dir,
        sbom_paths=sbom_paths,
        before_workspace_dir=before_workspace_dir,
        include_lockfile_warnings=True,
        targets_only=True,
    )
    if scanned.inventory_digest != inventory_digest:
        raise NativeWorkspaceInventoryError("Native workspace_inventory snapshot changed during audit")
    targets = scanned.scan_targets
    intent = _workspace_scan_intent(
        command_name=command_name,
        targets=targets,
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
    )
    assert intent is not None
    artifact = build_package_request_artifact(
        _LOCAL_SUPPLY_CHAIN_HARNESS,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = _lsc.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    return evaluation.to_dict()


def build_supply_chain_explain_payload(
    *,
    store: Any,
    config: GuardConfig,
    workspace_dir: Path,
    package_spec: str,
    ecosystem: str,
    now: str,
) -> tuple[dict[str, object], int]:
    posture = _lsc.build_local_supply_chain_posture(store, config, now=now)
    workspace_files = native_workspace_inventory(
        store, workspace_dir, files_only=True, package_spec=(ecosystem, package_spec)
    )
    manifest_paths, lockfile_paths = workspace_files.manifest_paths, workspace_files.lockfile_paths
    explained_target = workspace_files.package_target
    assert explained_target is not None
    intent = PackageIntent(
        package_manager=_lsc._PACKAGE_MANAGER_BY_ECOSYSTEM.get(ecosystem, ecosystem),
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", "explain", package_spec),
        redacted_command=shlex.join(("hol-guard", "supply-chain", "explain", package_spec)),
        targets=(explained_target,),
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
    )
    artifact = build_package_request_artifact(
        _LOCAL_SUPPLY_CHAIN_HARNESS,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = _lsc.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    payload: dict[str, object] = {
        "generated_at": now,
        "request": {
            "package": package_spec,
            "ecosystem": ecosystem,
            "manifest_paths": list(intent.manifest_paths),
            "lockfile_paths": list(intent.lockfile_paths),
        },
        "evaluation": evaluation.to_dict(),
        "supply_chain": posture,
    }
    return (payload, _evaluation_exit_code(evaluation.decision))


def _workspace_scan_intent(
    *,
    command_name: str,
    targets: tuple[PackageIntentTarget, ...],
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
) -> PackageIntent | None:
    resolved_manifest_paths, resolved_lockfile_paths = manifest_paths, lockfile_paths
    if not targets and not resolved_manifest_paths and not resolved_lockfile_paths:
        return None
    package_manager = _lsc._package_manager_for_scan(resolved_manifest_paths)
    return PackageIntent(
        package_manager=package_manager,
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", command_name),
        redacted_command=f"hol-guard supply-chain {command_name}",
        targets=targets,
        manifest_paths=resolved_manifest_paths,
        lockfile_paths=resolved_lockfile_paths,
    )


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


def _evaluation_exit_code(decision: str) -> int:
    return 2 if decision in {"block", "ask"} else 0

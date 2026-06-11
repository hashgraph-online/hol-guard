"""Shared local supply-chain posture and CLI helpers."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots, resolves_within_root

from .adapters.base import HarnessContext
from .config import GuardConfig, resolve_risk_action
from .models import GuardArtifact
from .package_firewall_entitlement import resolve_package_firewall_entitlement
from .receipts import build_receipt
from .redaction import redact_text
from .runtime.package_intent_common import (
    PackageIntent,
    PackageIntentTarget,
    build_package_request_artifact,
    composer_target,
    coordinate_target,
    existing_relative_paths,
    js_target,
    python_target,
    version_target,
)
from .runtime.package_manifest_diff import parse_manifest_dependencies, parse_manifest_dependency_changes
from .runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotAvailableError,
    GuardSyncNotConfiguredError,
    _guard_sync_headers,
    _resolve_guard_sync_auth_context,
    sync_local_guard_cloud_proof,
    sync_supply_chain_bundle,
)
from .runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
    evaluate_package_request_artifact,
)
from .runtime.supply_chain_support import ecosystem_support_matrix
from .shims import package_shim_status, package_shim_supported_managers
from .stable_digest import stable_digest_hex
from .store import GuardStore

_LOCAL_SUPPLY_CHAIN_HARNESS = "guard-cli"
_MANIFEST_CANDIDATES = (
    "package.json",
    "requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
)
_LOCKFILE_CANDIDATES = (
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "gradle.lockfile",
    "composer.lock",
    "Gemfile.lock",
)
_PACKAGE_MANAGER_BY_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "pip",
    "cargo": "cargo",
    "go": "go",
    "maven": "maven",
    "packagist": "composer",
    "rubygems": "bundle",
    "docker": "docker",
    "system": "system",
    "unsupported": "unsupported",
}
_ECOSYSTEM_BY_MANIFEST = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "constraints.txt": "pypi",
    "pyproject.toml": "pypi",
    "Pipfile": "pypi",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "composer.json": "packagist",
    "Gemfile": "rubygems",
}
_DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS = 15 * 60
_STALE_REFRESH_GRACE_SECONDS = 5 * 60
_CLOUD_AUDIT_TIMEOUT_SECONDS = 20
_CLOUD_AUDIT_PAGE_SIZE = 500
_CLOUD_AUDIT_MAX_PAGES = 100
_MAX_SBOM_BYTES = 10 * 1024 * 1024
_ECOSYSTEM_BY_LOCKFILE = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm",
    "yarn.lock": "npm",
    "bun.lock": "npm",
    "bun.lockb": "npm",
    "poetry.lock": "pypi",
    "uv.lock": "pypi",
    "Pipfile.lock": "pypi",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "gradle.lockfile": "maven",
    "composer.lock": "packagist",
    "Gemfile.lock": "rubygems",
}
_ECOSYSTEM_BY_PURL = {
    "cargo": "cargo",
    "composer": "packagist",
    "gem": "rubygems",
    "golang": "go",
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
}
_SEVERITY_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS = 300.0
_PACKAGE_FIREWALL_REFRESH_STATE_FILE = "package-firewall-refresh.json"
_PACKAGE_FIREWALL_REFRESH_LOCK = threading.Lock()
_AUDIT_SENSITIVE_BASENAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.test",
        ".envrc",
    }
)
_KNOWN_UNSUPPORTED_LOCKFILE_BASENAMES = frozenset({"bun.lockb"})


def _package_firewall_refresh_state_path(guard_home: Path) -> Path:
    return guard_home / _PACKAGE_FIREWALL_REFRESH_STATE_FILE


def _read_package_firewall_refresh_state(guard_home: Path) -> dict[str, object]:
    path = _package_firewall_refresh_state_path(guard_home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_package_firewall_refresh_state(guard_home: Path, last_attempt: float) -> None:
    path = _package_firewall_refresh_state_path(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        tmp_path.write_text(
            json.dumps({"last_refresh_attempt_at": last_attempt}, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(path)
    finally:
        if tmp_path.exists():
            with suppress(OSError):
                tmp_path.unlink()


def build_local_supply_chain_posture(
    store: GuardStore,
    config: GuardConfig,
    *,
    now: str | None = None,
) -> dict[str, object]:
    snapshot_now = _parse_timestamp(now) or datetime.now(timezone.utc)
    workspace_id = store.get_cloud_workspace_id()
    cloud_profile = store.get_cloud_sync_profile()
    summary = _dict_payload(store.get_sync_payload("supply_chain_bundle_summary"))
    entitlement = _dict_payload(store.get_sync_payload("supply_chain_bundle_entitlement"))
    remote_policy = _dict_payload(store.get_sync_payload("policy"))
    team_policy_pack = _dict_payload(store.get_sync_payload("team_policy_pack"))
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id else None
    bundle_payload = _dict_payload(cached_bundle.get("bundle")) if isinstance(cached_bundle, dict) else {}
    expires_at_text = _string_value(bundle_payload.get("expiresAt"))
    expires_at = _parse_timestamp(expires_at_text)
    status = _posture_status(
        credentials_present=cloud_profile is not None,
        workspace_id=workspace_id,
        summary=summary,
        bundle_payload=bundle_payload,
        expires_at=expires_at,
        snapshot_now=snapshot_now,
    )
    synced_at = _string_value(summary.get("synced_at"))
    next_refresh_at = _resolve_next_refresh_at(
        summary=summary,
        synced_at=synced_at,
    )
    health_status = _posture_health_status(
        status=status,
        next_refresh_at=next_refresh_at,
        snapshot_now=snapshot_now,
    )
    support = summary.get("ecosystem_support")
    supported_ecosystems = support if isinstance(support, list) and support else list(ecosystem_support_matrix())
    bundle_version = (
        _string_value(summary.get("bundle_version"))
        or _string_value(entitlement.get("bundle_version"))
        or _string_value(bundle_payload.get("bundleVersion"))
    )
    tier = (
        _string_value(summary.get("tier"))
        or _string_value(entitlement.get("tier"))
        or _string_value(bundle_payload.get("tier"))
    )
    remote_package_script_action = _string_value(remote_policy.get("packageScriptAction")) or _string_value(
        remote_policy.get("package_script_action")
    )
    remote_cloud_advisory_action = _string_value(remote_policy.get("cloudAdvisoryAction")) or _string_value(
        remote_policy.get("cloud_advisory_action")
    )
    managed_by_cloud = bool(remote_policy or team_policy_pack)
    managed_label = _string_value(team_policy_pack.get("name")) or ("Guard Cloud sync" if managed_by_cloud else None)
    managed_updated_at = _string_value(team_policy_pack.get("updatedAt")) or _string_value(
        remote_policy.get("updatedAt")
    )
    return {
        "status": status,
        "health_status": health_status,
        "detail": _posture_detail(status),
        "connection": {
            "logged_in": cloud_profile is not None,
            "paired": workspace_id is not None,
            "workspace_id": workspace_id,
        },
        "bundle": {
            "bundle_version": bundle_version,
            "feed_snapshot_hash": _string_value(summary.get("feed_snapshot_hash"))
            or _string_value(bundle_payload.get("feedSnapshotHash")),
            "policy_hash": _string_value(summary.get("policy_hash"))
            or _string_value(entitlement.get("policy_hash"))
            or _string_value(bundle_payload.get("policyHash")),
            "synced_at": synced_at,
            "next_refresh_at": next_refresh_at,
            "expires_at": expires_at_text,
            "tier": tier,
            "workspace_id": _string_value(summary.get("workspace_id"))
            or _string_value(entitlement.get("workspace_id"))
            or workspace_id,
            "advisory_count": _int_value(summary.get("advisory_count")),
            "package_count": _int_value(summary.get("package_count")),
        },
        "policy": {
            "security_level": config.security_level,
            "cloud_advisory_action": remote_cloud_advisory_action
            or resolve_risk_action(config, "cloud_advisory", harness=None),
            "package_script_action": remote_package_script_action
            or resolve_risk_action(config, "package_script", harness=None),
            "managed_by_cloud": managed_by_cloud,
            "remote_policy_active": bool(remote_policy),
            "team_policy_active": bool(team_policy_pack),
            "managed_label": managed_label,
            "managed_updated_at": managed_updated_at,
        },
        "supported_ecosystems": supported_ecosystems,
        "package_manager_protection": _build_package_manager_protection(store),
    }


def build_supply_chain_status_payload(
    *,
    store: GuardStore,
    config: GuardConfig,
    now: str,
) -> dict[str, object]:
    posture = build_local_supply_chain_posture(store, config, now=now)
    return {
        "generated_at": now,
        "mode": "status",
        "executed": False,
        "dry_run": True,
        "supply_chain": posture,
    }


def resolve_package_firewall_entitlement_with_refresh(store: GuardStore) -> dict[str, object]:
    """Resolve package-firewall access and opportunistically heal stale cloud state."""

    entitlement = resolve_package_firewall_entitlement(store)
    if bool(entitlement.get("allowed")):
        return entitlement
    if store.get_cloud_sync_profile() is None:
        return entitlement
    if str(entitlement.get("reason") or "") not in {
        "guard_cloud_connect_required",
        "guard_cloud_reconnect_required",
        "paid_guard_cloud_required",
    }:
        return entitlement
    now_iso = datetime.now(timezone.utc).isoformat()
    now = time.time()
    with _PACKAGE_FIREWALL_REFRESH_LOCK:
        state = _read_package_firewall_refresh_state(store.guard_home)
        last_refresh_at = state.get("last_refresh_attempt_at")
        if (
            isinstance(last_refresh_at, (int, float))
            and (now - float(last_refresh_at)) < _PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS
        ):
            return entitlement
        _write_package_firewall_refresh_state(store.guard_home, now)
    for refresh in (sync_local_guard_cloud_proof, sync_supply_chain_bundle):
        try:
            refresh(store)
        except GuardSyncAuthorizationExpiredError as error:
            if str(entitlement.get("reason") or "") == "guard_cloud_connect_required":
                store.record_latest_guard_connect_sync_result(
                    status="retry_required",
                    milestone="first_sync_failed",
                    now=now_iso,
                    reason=str(error),
                )
            break
        except (GuardSyncNotAvailableError, GuardSyncNotConfiguredError, OSError, RuntimeError):
            continue
    return resolve_package_firewall_entitlement(store)


def _is_audit_sensitive_basename(name: str) -> bool:
    lowered = name.lower()
    return lowered in _AUDIT_SENSITIVE_BASENAMES or lowered.startswith(".env.")


def _read_workspace_audit_text(workspace_dir: Path, relative_path: str) -> str | None:
    if _is_audit_sensitive_basename(Path(relative_path).name):
        return None
    disk_path = workspace_dir / relative_path
    try:
        return disk_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _workspace_has_project_markers(workspace_dir: Path) -> bool:
    try:
        resolved = workspace_dir.resolve()
    except OSError:
        return False
    return any((resolved / marker).exists() for marker in _MANIFEST_CANDIDATES)


def resolve_supply_chain_audit_workspace_dir(
    *,
    workspace_dir_value: object,
    workspace_value: object,
    allowed_roots: tuple[Path, ...],
) -> Path | None:
    for candidate in (workspace_dir_value, workspace_value):
        if isinstance(candidate, str):
            resolved = resolve_path_within_allowed_roots(
                candidate,
                allowed_roots,
                require_exists=True,
            )
            if resolved is not None:
                return resolved
    cursor_project = os.environ.get("CURSOR_PROJECT_DIR", "").strip()
    if cursor_project:
        resolved = resolve_path_within_allowed_roots(
            cursor_project,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None and _workspace_has_project_markers(resolved):
            return resolved
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return None
    if not _workspace_has_project_markers(cwd):
        return None
    for root in allowed_roots:
        if resolves_within_root(root, cwd, require_exists=True):
            return cwd
    return None


def _audit_lockfile_warnings(
    workspace_dir: Path,
    lockfile_paths: tuple[str, ...],
) -> tuple[dict[str, object], ...]:
    warnings: list[dict[str, object]] = []
    for lockfile_path in lockfile_paths:
        lockfile_name = Path(lockfile_path).name
        disk_path = workspace_dir / lockfile_path
        if not disk_path.exists():
            continue
        if lockfile_name in _KNOWN_UNSUPPORTED_LOCKFILE_BASENAMES:
            warnings.append(
                {
                    "code": "bun_lockfile_binary_fallback",
                    "message": (
                        "Guard detected bun.lockb but Bun stores it as a binary lockfile, so audit "
                        "fell back to manifest-only monitoring."
                    ),
                    "path": lockfile_path,
                }
            )
            continue
        if lockfile_name not in _ECOSYSTEM_BY_LOCKFILE:
            continue
        lockfile_text = _read_workspace_audit_text(workspace_dir, lockfile_path)
        if lockfile_text is None:
            warnings.append(
                {
                    "code": "lockfile_unreadable",
                    "message": f"Guard could not read {lockfile_name} for workspace audit.",
                    "path": lockfile_path,
                }
            )
            continue
        dependency_map = parse_manifest_dependencies(path=lockfile_path, text=lockfile_text)
        if not dependency_map:
            warnings.append(
                {
                    "code": "lockfile_parse_warning",
                    "message": f"Guard could not parse {lockfile_name} for workspace audit.",
                    "path": lockfile_path,
                }
            )
    return tuple(warnings)


def _audit_package_findings_for_receipt(
    package_items: list[dict[str, object]],
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    decision_rank_map = {"block": 4, "ask": 3, "warn": 2, "monitor": 1, "allow": 0}
    ranked: list[tuple[int, int, dict[str, object]]] = []
    for item in package_items:
        decision = str(item.get("decision") or "monitor")
        if decision in {"allow", "monitor"} and not item.get("reasons"):
            continue
        severity_rank = _package_severity_rank(item)
        decision_rank = decision_rank_map.get(decision, 0)
        ranked.append((decision_rank, severity_rank, item))
    ranked.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
    return [item for _, _, item in ranked[:limit]]


def workspace_audit_path_hashes(
    workspace_dir: Path | None,
    manifest_paths: Sequence[str],
    lockfile_paths: Sequence[str],
) -> dict[str, list[str]]:
    if workspace_dir is None:
        return {"manifest_hashes": [], "lockfile_hashes": []}
    return {
        "manifest_hashes": _hash_existing_paths(workspace_dir, manifest_paths),
        "lockfile_hashes": _hash_existing_paths(workspace_dir, lockfile_paths),
    }


def audit_receipt_metadata(
    result: dict[str, object],
    *,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    evaluation = result.get("evaluation")
    if not isinstance(evaluation, dict):
        return {}
    decision = str(evaluation.get("decision") or "monitor")
    packages = evaluation.get("packages")
    package_items = [item for item in packages if isinstance(item, dict)] if isinstance(packages, list) else []
    blocked_packages = [item for item in package_items if str(item.get("decision") or "") == "block"]
    package_findings = _audit_package_findings_for_receipt(package_items)
    policy_decision = "allow"
    if decision == "block":
        policy_decision = "block"
    elif decision == "ask":
        policy_decision = "ask"
    inventory = result.get("inventory")
    inventory_summary = inventory if isinstance(inventory, dict) else {}
    manifest_paths = [str(path) for path in result.get("manifest_paths") or () if isinstance(path, str)]
    lockfile_paths = [str(path) for path in result.get("lockfile_paths") or () if isinstance(path, str)]
    path_hashes = workspace_audit_path_hashes(workspace_dir, manifest_paths, lockfile_paths)
    return {
        "policy_decision": policy_decision,
        "capabilities_summary": (
            f"Workspace audit completed with {decision} decision across "
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
            "package_findings": package_findings,
        },
    }


def build_workspace_scan_payload(
    *,
    store: GuardStore,
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
    store: GuardStore,
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
    target_workspace_dir = after_workspace_dir or workspace_dir
    posture = build_local_supply_chain_posture(store, config, now=now)
    diff_summary: dict[str, object] | None = None
    if before_workspace_dir is not None and after_workspace_dir is not None:
        manifest_paths, lockfile_paths, resolved_sbom_paths, inventory, diff_summary = _workspace_diff_audit_inventory(
            before_workspace_dir=before_workspace_dir,
            after_workspace_dir=after_workspace_dir,
            sbom_paths=sbom_paths,
        )
    else:
        manifest_paths, lockfile_paths, resolved_sbom_paths, inventory = _workspace_audit_inventory(
            target_workspace_dir,
            sbom_paths=sbom_paths,
        )
    if not inventory:
        return (
            {
                "generated_at": now,
                "mode": command_name,
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "sbom_paths": list(resolved_sbom_paths),
                "message": "No supported manifests or lockfiles found in this workspace.",
                "supply_chain": posture,
            },
            1,
        )
    evaluation: dict[str, object]
    source = "local"
    fallback_reason: dict[str, object] | None = None
    if _should_use_cloud_workspace_audit(store=store, posture=posture):
        try:
            auth_context = _resolve_guard_sync_auth_context(store)
            workspace_id = store.get_cloud_workspace_id()
            assert workspace_id is not None
            request_payload = _build_cloud_audit_payload(
                workspace_dir=target_workspace_dir,
                workspace_id=workspace_id,
                store=store,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                inventory=inventory,
            )
            cloud_response, fallback_reason = _run_cloud_workspace_audit(
                request_payload=request_payload,
                auth_context=auth_context,
                workspace_id=workspace_id,
            )
            if cloud_response is not None:
                evaluation = _normalize_cloud_audit_response(cloud_response)
                source = "cloud"
            else:
                evaluation = _workspace_local_evaluation(
                    store=store,
                    workspace_dir=target_workspace_dir,
                    inventory=inventory,
                    manifest_paths=manifest_paths,
                    lockfile_paths=lockfile_paths,
                    command_name=command_name,
                    now=now,
                )
        except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError, RuntimeError):
            fallback_reason = {
                "code": "cloud_auth_error",
                "message": "Guard cloud authorization could not be refreshed, so Guard fell back locally.",
            }
            evaluation = _workspace_local_evaluation(
                store=store,
                workspace_dir=target_workspace_dir,
                inventory=inventory,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                command_name=command_name,
                now=now,
            )
    else:
        evaluation = _workspace_local_evaluation(
            store=store,
            workspace_dir=target_workspace_dir,
            inventory=inventory,
            manifest_paths=manifest_paths,
            lockfile_paths=lockfile_paths,
            command_name=command_name,
            now=now,
        )
    payload = {
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
    lockfile_warnings = _audit_lockfile_warnings(target_workspace_dir, lockfile_paths)
    if lockfile_warnings:
        payload["lockfile_warnings"] = list(lockfile_warnings)
    if diff_summary is not None:
        payload["diff"] = diff_summary
    if fallback_reason is not None:
        payload["fallback_reason"] = fallback_reason
    exit_code = _evaluation_exit_code(str(evaluation.get("decision") or "monitor"))
    if ci:
        ci_result = _ci_gate_result(evaluation, threshold=fail_on)
        payload["ci"] = ci_result
        if ci_result["matched"]:
            exit_code = 3
    return (payload, exit_code)


def _workspace_local_evaluation(
    *,
    store: GuardStore,
    workspace_dir: Path,
    inventory: tuple[dict[str, object], ...],
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    command_name: str,
    now: str,
) -> dict[str, object]:
    intent = _workspace_scan_intent(
        workspace_dir,
        command_name=command_name,
        inventory=inventory,
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
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    return evaluation.to_dict()


def build_supply_chain_explain_payload(
    *,
    store: GuardStore,
    config: GuardConfig,
    workspace_dir: Path,
    package_spec: str,
    ecosystem: str,
    now: str,
) -> tuple[dict[str, object], int]:
    posture = build_local_supply_chain_posture(store, config, now=now)
    manifest_paths, lockfile_paths = _workspace_files(workspace_dir)
    intent = PackageIntent(
        package_manager=_PACKAGE_MANAGER_BY_ECOSYSTEM.get(ecosystem, ecosystem),
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", "explain", package_spec),
        redacted_command=shlex.join(("hol-guard", "supply-chain", "explain", package_spec)),
        targets=(_target_for_package_spec(ecosystem, package_spec),),
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
    )
    artifact = build_package_request_artifact(
        _LOCAL_SUPPLY_CHAIN_HARNESS,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    payload = {
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


def build_package_protect_payload(
    *,
    command: Sequence[str],
    store: GuardStore,
    workspace_dir: Path,
    dry_run: bool,
    allow_saved_approval_execution: bool = False,
    now: str,
    config: GuardConfig | None,
    unsafe_raw_output: bool,
    timeout_seconds: int,
) -> tuple[dict[str, object], int] | None:
    from .runtime.package_intent_parser import parse_package_intent

    intent = parse_package_intent(shlex.join(command), workspace=workspace_dir)
    if intent is None:
        return None
    sanitized_intent = replace(intent, redacted_command=shlex.join(redacted_command_tokens(command)))
    artifact = build_package_request_artifact(
        _LOCAL_SUPPLY_CHAIN_HARNESS,
        sanitized_intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    artifact_hash = _package_request_artifact_hash(artifact, workspace_dir=workspace_dir)
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    evaluation = _apply_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
    )
    verdict_action = _protect_action_for_decision(evaluation.decision)
    risk_signals = tuple(_evaluation_risk_signals(evaluation))
    receipt_policy_metadata = {
        "matched_rule_id": evaluation.matched_rule_id,
        "package_manager": sanitized_intent.package_manager,
        "package_targets": [target.raw_spec for target in sanitized_intent.targets],
        "policy_version": evaluation.policy_version,
        "redacted_command": sanitized_intent.redacted_command,
    }
    if evaluation.bundle_version is not None:
        receipt_policy_metadata["bundle_version"] = evaluation.bundle_version
    receipt = build_receipt(
        harness=_LOCAL_SUPPLY_CHAIN_HARNESS,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=verdict_action,
        capabilities_summary=evaluation.user_copy.summary,
        changed_capabilities=[target.package_name or target.raw_spec for target in sanitized_intent.targets],
        provenance_summary=evaluation.user_copy.harness_message,
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
    )
    receipt_payload = {
        **receipt.to_dict(),
        "action_envelope_json": receipt_policy_metadata,
    }
    payload: dict[str, object] = {
        "generated_at": now,
        "request": {
            "command": list(redacted_command_tokens(command)),
            "redacted_command": sanitized_intent.redacted_command,
            "install_kind": sanitized_intent.intent_kind,
            "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
            "package_manager": sanitized_intent.package_manager,
            "harness": _LOCAL_SUPPLY_CHAIN_HARNESS,
            "targets": [target.to_dict() for target in sanitized_intent.targets],
            "manifest_paths": list(sanitized_intent.manifest_paths),
            "lockfile_paths": list(sanitized_intent.lockfile_paths),
        },
        "targets": [_protect_target_payload(target) for target in sanitized_intent.targets],
        "verdict": {
            "action": verdict_action,
            "reason": evaluation.user_copy.summary,
            "risk_signals": list(risk_signals),
            "matched_advisories": _matched_advisories(evaluation),
            "blocking": evaluation.decision in {"block", "ask"},
        },
        "executed": False,
        "dry_run": dry_run,
        "receipt": receipt_payload,
        "matched_advisories": _matched_advisories(evaluation),
        "supply_chain_evaluation": evaluation.to_dict(),
    }
    if config is not None:
        payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=now)
    effective_dry_run = dry_run and not (
        allow_saved_approval_execution and _evaluation_uses_saved_package_approval(evaluation)
    )
    if evaluation.decision in {"block", "ask"} or effective_dry_run:
        store.add_receipt(receipt)
        store.set_receipt_action_envelope(receipt.receipt_id, receipt_policy_metadata)
        store.add_event(
            f"install_time_{verdict_action}",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
                "install_kind": sanitized_intent.intent_kind,
                "action": verdict_action,
                "risk_signals": list(risk_signals),
            },
            now,
        )
        return (payload, _evaluation_exit_code(evaluation.decision))
    payload["executed"] = True
    try:
        execution = subprocess.run(
            list(command),
            cwd=workspace_dir,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        payload["execution"] = _build_command_execution_payload(
            stdout=_coerce_command_output(getattr(error, "stdout", None)),
            stderr=_coerce_command_error_output(error),
            returncode=-1,
            unsafe_raw_output=unsafe_raw_output,
        )
        store.add_event(
            "install_time_execution_failed",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
                "install_kind": sanitized_intent.intent_kind,
                "action": verdict_action,
                "error": type(error).__name__,
                "risk_signals": list(risk_signals),
            },
            now,
        )
        return (payload, 1)
    payload["execution"] = _build_command_execution_payload(
        stdout=execution.stdout,
        stderr=execution.stderr,
        returncode=execution.returncode,
        unsafe_raw_output=unsafe_raw_output,
    )
    if execution.returncode == 0:
        store.add_receipt(receipt)
        store.set_receipt_action_envelope(receipt.receipt_id, receipt_policy_metadata)
        store.add_event(
            "install_time_allow",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
                "install_kind": sanitized_intent.intent_kind,
                "action": verdict_action,
                "risk_signals": list(risk_signals),
            },
            now,
        )
    else:
        store.add_event(
            "install_time_execution_failed",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
                "install_kind": sanitized_intent.intent_kind,
                "action": verdict_action,
                "returncode": execution.returncode,
                "risk_signals": list(risk_signals),
            },
            now,
        )
    return (payload, int(execution.returncode))


def _apply_stored_package_policy_override(
    evaluation: PackageRequestEvaluation,
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
) -> PackageRequestEvaluation:
    decision = store.resolve_policy_decision(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash,
        str(workspace_dir),
        artifact.publisher,
        now,
    )
    if not isinstance(decision, dict):
        return evaluation
    action = decision.get("action")
    if action == "allow":
        return _package_policy_override_evaluation(
            evaluation,
            decision="allow",
            policy_action="allow",
            title="Allowed by saved approval",
            summary="HOL Guard reused your saved approval for this package request.",
            harness_message=(
                "HOL Guard reused your saved approval for this package request and let the install continue."
            ),
            reason_code="saved_package_approval",
            reason_message="HOL Guard reused your saved approval for this package request.",
        )
    if action == "block":
        return _package_policy_override_evaluation(
            evaluation,
            decision="block",
            policy_action="block",
            title="Blocked by saved policy",
            summary="HOL Guard kept this package blocked because a saved package policy already exists.",
            harness_message="HOL Guard kept this package blocked because a saved package policy already exists.",
            reason_code="saved_package_block",
            reason_message="HOL Guard kept this package blocked because a saved package policy already exists.",
        )
    return evaluation


def _package_request_artifact_hash(artifact: GuardArtifact, *, workspace_dir: Path) -> str:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    targets = metadata.get("targets")
    if isinstance(targets, list) and any(isinstance(item, dict) for item in targets):
        return stable_digest_hex(artifact.artifact_id.encode("utf-8"))
    manifest_paths = tuple(str(item) for item in metadata.get("manifest_paths", []) if isinstance(item, str))
    lockfile_paths = tuple(str(item) for item in metadata.get("lockfile_paths", []) if isinstance(item, str))
    if not manifest_paths and not lockfile_paths:
        return stable_digest_hex(artifact.artifact_id.encode("utf-8"))
    return stable_digest_hex(
        json.dumps(
            {
                "artifact_id": artifact.artifact_id,
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "manifest_hashes": _hash_existing_paths(workspace_dir, manifest_paths),
                "lockfile_hashes": _hash_existing_paths(workspace_dir, lockfile_paths),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _evaluation_uses_saved_package_approval(evaluation: PackageRequestEvaluation) -> bool:
    return any(reason.get("code") == "saved_package_approval" for reason in evaluation.reasons)


def _package_policy_override_evaluation(
    evaluation: PackageRequestEvaluation,
    *,
    decision: str,
    policy_action: str,
    title: str,
    summary: str,
    harness_message: str,
    reason_code: str,
    reason_message: str,
) -> PackageRequestEvaluation:
    reason = {
        "code": reason_code,
        "message": reason_message,
        "severity": "low",
        "source": "guard-local",
    }
    packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    return replace(
        evaluation,
        decision=decision,
        policy_action=policy_action,
        reasons=(reason, *tuple(item for item in evaluation.reasons if item != reason)),
        packages=packages,
        risk_summary=harness_message,
        user_copy=SupplyChainUserCopy(
            title=title,
            summary=summary,
            next_step=None,
            dashboard_url=None,
            harness_message=harness_message,
        ),
        record_monitor_evidence=False,
    )


def redacted_command_tokens(command: Sequence[str]) -> tuple[str, ...]:
    return tuple(_redact_command_token(str(token)) for token in command)


def _build_command_execution_payload(
    *,
    stdout: str,
    stderr: str,
    returncode: int,
    unsafe_raw_output: bool,
) -> dict[str, object]:
    redacted_stdout = redact_text(stdout)
    redacted_stderr = redact_text(stderr)
    return {
        "returncode": returncode,
        "stdout": stdout if unsafe_raw_output else redacted_stdout.text,
        "stderr": stderr if unsafe_raw_output else redacted_stderr.text,
        "stdout_redactions": redacted_stdout.to_dict(),
        "stderr_redactions": redacted_stderr.to_dict(),
        "raw_output_enabled": unsafe_raw_output,
    }


def _coerce_command_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return ""


def _coerce_command_error_output(error: subprocess.TimeoutExpired | OSError) -> str:
    parts = [_coerce_command_output(getattr(error, "stderr", None))]
    message = str(error).strip()
    if message:
        parts.append(message)
    return "\n".join(part for part in parts if part)


def _build_package_manager_protection(store: GuardStore) -> dict[str, object]:
    context = HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
    status = package_shim_status(context)
    shim_dir = Path(str(status.get("shim_dir") or store.guard_home / "package-shims" / "bin"))
    installed_managers = sorted({str(item) for item in status.get("installed_managers", []) if isinstance(item, str)})
    active_managers = sorted({str(item) for item in status.get("active_managers", []) if isinstance(item, str)})
    missing_shims = sorted({str(item) for item in status.get("missing_managers", []) if isinstance(item, str)})
    supported_managers = list(package_shim_supported_managers())
    protected_managers = sorted({str(item) for item in status.get("protected_managers", []) if isinstance(item, str)})
    protected_set = set(protected_managers)
    path_status = str(status.get("path_status") or "missing_from_path")
    staged_managers = set(installed_managers) if path_status == "restart_required" else set()
    unprotected_managers = [
        manager for manager in supported_managers if manager not in protected_set and manager not in staged_managers
    ]
    return {
        "path_status": path_status,
        "path_contains_shim_dir": bool(status.get("path_contains_shim_dir")),
        "restart_shell_required": bool(status.get("restart_shell_required")),
        "shell_profile_configured": bool(status.get("shell_profile_configured")),
        "shell_profile_path": status.get("shell_profile_path"),
        "shim_dir": str(shim_dir),
        "supported_managers": supported_managers,
        "installed_managers": installed_managers,
        "active_managers": active_managers,
        "missing_shims": missing_shims,
        "protected_managers": protected_managers,
        "unprotected_managers": unprotected_managers,
    }


def _workspace_scan_intent(
    workspace_dir: Path,
    *,
    command_name: str,
    inventory: tuple[dict[str, object], ...] | None = None,
    manifest_paths: tuple[str, ...] | None = None,
    lockfile_paths: tuple[str, ...] | None = None,
) -> PackageIntent | None:
    resolved_manifest_paths, resolved_lockfile_paths = (
        _workspace_files(workspace_dir)
        if manifest_paths is None or lockfile_paths is None
        else (manifest_paths, lockfile_paths)
    )
    if inventory is None:
        inventory = _workspace_inventory_from_paths(workspace_dir, resolved_manifest_paths, resolved_lockfile_paths)
    if not inventory and not resolved_manifest_paths and not resolved_lockfile_paths:
        return None
    targets = tuple(_target_from_inventory_item(item) for item in inventory)
    package_manager = _package_manager_for_scan(resolved_manifest_paths)
    return PackageIntent(
        package_manager=package_manager,
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", command_name),
        redacted_command=f"hol-guard supply-chain {command_name}",
        targets=targets,
        manifest_paths=resolved_manifest_paths,
        lockfile_paths=resolved_lockfile_paths,
    )


def _workspace_files(workspace_dir: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        existing_relative_paths(workspace_dir, _MANIFEST_CANDIDATES),
        existing_relative_paths(workspace_dir, _LOCKFILE_CANDIDATES),
    )


def _targets_from_workspace_manifests(
    workspace_dir: Path,
    manifest_paths: Sequence[str],
) -> tuple[PackageIntentTarget, ...]:
    seen: set[tuple[str, str | None, str, str | None]] = set()
    targets: list[PackageIntentTarget] = []
    for manifest_path in manifest_paths:
        disk_path = workspace_dir / manifest_path
        try:
            manifest_text = disk_path.read_text(encoding="utf-8")
        except OSError:
            continue
        dependency_map = parse_manifest_dependencies(path=manifest_path, text=manifest_text)
        ecosystem = _ECOSYSTEM_BY_MANIFEST.get(Path(manifest_path).name)
        if ecosystem is None:
            continue
        for package_name, version in dependency_map.items():
            target = _target_from_manifest_dependency(ecosystem, package_name, version)
            fingerprint = (target.ecosystem, target.package_name, target.raw_spec, target.source_url)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            targets.append(target)
    return tuple(targets)


def _workspace_audit_inventory(
    workspace_dir: Path,
    *,
    sbom_paths: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[dict[str, object], ...]]:
    manifest_paths, lockfile_paths = _workspace_files(workspace_dir)
    normalized_sbom_paths = _resolve_sbom_paths(workspace_dir, sbom_paths)
    inventory = _workspace_inventory_from_paths(workspace_dir, manifest_paths, lockfile_paths)
    inventory_map = {_inventory_key(item): dict(item) for item in inventory}
    for sbom_path in normalized_sbom_paths:
        disk_path = workspace_dir / sbom_path
        sbom_text = _read_sbom_text(disk_path)
        if sbom_text is None:
            continue
        try:
            parsed_items = _inventory_from_sbom_text(sbom_text)
        except ValueError:
            continue
        for item in parsed_items:
            _merge_inventory_item(inventory_map, item)
    return (manifest_paths, lockfile_paths, normalized_sbom_paths, tuple(inventory_map.values()))


def _workspace_diff_audit_inventory(
    *,
    before_workspace_dir: Path,
    after_workspace_dir: Path,
    sbom_paths: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[dict[str, object], ...], dict[str, object]]:
    manifest_paths, lockfile_paths = _workspace_files(after_workspace_dir)
    normalized_sbom_paths = _resolve_sbom_paths(after_workspace_dir, sbom_paths)
    inventory_map: dict[tuple[str, str | None, str], dict[str, object]] = {}
    changed_paths: list[str] = []
    changed_packages: list[str] = []
    for relative_path in (*manifest_paths, *lockfile_paths):
        before_path = before_workspace_dir / relative_path
        after_path = after_workspace_dir / relative_path
        before_text = before_path.read_text(encoding="utf-8") if before_path.exists() else None
        after_text = after_path.read_text(encoding="utf-8") if after_path.exists() else None
        if before_text is None and after_text is None:
            continue
        change_result = parse_manifest_dependency_changes(
            path=relative_path,
            before_text=before_text,
            after_text=after_text,
        )
        if not change_result.changes:
            continue
        changed_paths.append(relative_path)
        ecosystem = _ECOSYSTEM_BY_MANIFEST.get(Path(relative_path).name) or _ECOSYSTEM_BY_LOCKFILE.get(
            Path(relative_path).name
        )
        if ecosystem is None:
            continue
        direct = Path(relative_path).name in _ECOSYSTEM_BY_MANIFEST
        for change in change_result.changes:
            if change.after is None:
                continue
            namespace, name = _split_namespace_name(change.package_name)
            changed_packages.append(change.package_name)
            _merge_inventory_item(
                inventory_map,
                {
                    "ecosystem": ecosystem,
                    "namespace": namespace,
                    "name": name,
                    "direct": direct,
                    "range": change.after if direct else None,
                    "version": None if direct else change.after,
                },
            )
    for sbom_path in normalized_sbom_paths:
        disk_path = after_workspace_dir / sbom_path
        sbom_text = _read_sbom_text(disk_path)
        if sbom_text is None:
            continue
        try:
            parsed_items = _inventory_from_sbom_text(sbom_text)
        except ValueError:
            continue
        for item in parsed_items:
            _merge_inventory_item(inventory_map, item)
    summary = {
        "changed_package_count": len({item for item in changed_packages}),
        "changed_paths": changed_paths,
    }
    return (manifest_paths, lockfile_paths, normalized_sbom_paths, tuple(inventory_map.values()), summary)


def _workspace_inventory_from_paths(
    workspace_dir: Path,
    manifest_paths: Sequence[str],
    lockfile_paths: Sequence[str],
) -> tuple[dict[str, object], ...]:
    inventory_map: dict[tuple[str, str | None, str], dict[str, object]] = {}
    for manifest_path in manifest_paths:
        ecosystem = _ECOSYSTEM_BY_MANIFEST.get(Path(manifest_path).name)
        if ecosystem is None:
            continue
        manifest_text = _read_workspace_audit_text(workspace_dir, manifest_path)
        if manifest_text is None:
            continue
        for package_name, version in parse_manifest_dependencies(path=manifest_path, text=manifest_text).items():
            namespace, name = _split_namespace_name(package_name)
            _merge_inventory_item(
                inventory_map,
                {
                    "ecosystem": ecosystem,
                    "namespace": namespace,
                    "name": name,
                    "direct": True,
                    "range": version.strip() or None,
                    "version": None,
                },
            )
    for lockfile_path in lockfile_paths:
        ecosystem = _ECOSYSTEM_BY_LOCKFILE.get(Path(lockfile_path).name)
        if ecosystem is None:
            continue
        lockfile_text = _read_workspace_audit_text(workspace_dir, lockfile_path)
        if lockfile_text is None:
            continue
        for package_name, version in parse_manifest_dependencies(path=lockfile_path, text=lockfile_text).items():
            namespace, name = _split_namespace_name(package_name)
            _merge_inventory_item(
                inventory_map,
                {
                    "ecosystem": ecosystem,
                    "namespace": namespace,
                    "name": name,
                    "direct": False,
                    "range": None,
                    "version": version.strip() or None,
                },
            )
    return tuple(inventory_map.values())


def _merge_inventory_item(
    inventory_map: dict[tuple[str, str | None, str], dict[str, object]],
    item: dict[str, object],
) -> None:
    key = _inventory_key(item)
    existing = inventory_map.get(key)
    if existing is None:
        inventory_map[key] = {
            "ecosystem": str(item["ecosystem"]),
            "namespace": item.get("namespace"),
            "name": str(item["name"]),
            "direct": bool(item.get("direct")),
            "range": item.get("range"),
            "version": item.get("version"),
        }
        return
    existing["direct"] = bool(existing.get("direct")) or bool(item.get("direct"))
    if existing.get("range") is None and item.get("range") is not None:
        existing["range"] = item["range"]
    if existing.get("version") is None and item.get("version") is not None:
        existing["version"] = item["version"]


def _inventory_key(item: dict[str, object]) -> tuple[str, str | None, str]:
    namespace = item.get("namespace")
    return (str(item["ecosystem"]), namespace if isinstance(namespace, str) else None, str(item["name"]))


def _split_namespace_name(package_name: str) -> tuple[str | None, str]:
    cleaned = package_name.strip()
    if cleaned.startswith("@") and "/" in cleaned:
        namespace, _, name = cleaned.partition("/")
        return (namespace, name)
    return (None, cleaned)


def _target_from_inventory_item(item: dict[str, object]) -> PackageIntentTarget:
    qualified_name = (
        f"{item['namespace']}/{item['name']}" if isinstance(item.get("namespace"), str) else str(item["name"])
    )
    version = item.get("version")
    version_range = item.get("range")
    ecosystem = str(item["ecosystem"])
    if ecosystem == "npm":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}@{suffix}"
        return js_target(spec)
    if ecosystem == "pypi":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}{suffix}"
        return python_target(spec)
    if ecosystem == "maven":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}:{suffix}"
        return coordinate_target(ecosystem, spec)
    if ecosystem == "packagist":
        suffix = str(version) if isinstance(version, str) else str(version_range or "")
        spec = qualified_name if not suffix else f"{qualified_name}:{suffix}"
        return composer_target(spec)
    suffix = str(version) if isinstance(version, str) else str(version_range or "")
    spec = qualified_name if not suffix else f"{qualified_name}@{suffix}"
    return version_target(ecosystem, spec)


def _resolve_sbom_paths(workspace_dir: Path, sbom_paths: Sequence[str]) -> tuple[str, ...]:
    resolved: list[str] = []
    for raw_path in sbom_paths:
        candidate = Path(raw_path)
        disk_path = candidate if candidate.is_absolute() else workspace_dir / candidate
        if not disk_path.exists():
            continue
        try:
            normalized = str(disk_path.relative_to(workspace_dir))
        except ValueError:
            normalized = disk_path.name
        if normalized not in resolved:
            resolved.append(normalized)
    return tuple(resolved)


def _inventory_from_sbom_text(text: str) -> tuple[dict[str, object], ...]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("SBOM payload must be an object")
    if payload.get("bomFormat") == "CycloneDX":
        return _inventory_from_cyclonedx(payload)
    if payload.get("spdxVersion"):
        return _inventory_from_spdx(payload)
    raise ValueError("Unsupported SBOM format")


def _read_sbom_text(disk_path: Path) -> str | None:
    try:
        if disk_path.stat().st_size > _MAX_SBOM_BYTES:
            return None
        return disk_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _inventory_from_cyclonedx(payload: dict[str, object]) -> tuple[dict[str, object], ...]:
    components = payload.get("components")
    if not isinstance(components, list):
        return ()
    inventory: dict[tuple[str, str | None, str], dict[str, object]] = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        item = _inventory_item_from_sbom_component(
            name=component.get("name"),
            version=component.get("version"),
            purl=component.get("purl"),
        )
        if item is None:
            continue
        _merge_inventory_item(inventory, item)
    return tuple(inventory.values())


def _inventory_from_spdx(payload: dict[str, object]) -> tuple[dict[str, object], ...]:
    packages = payload.get("packages")
    if not isinstance(packages, list):
        return ()
    inventory: dict[tuple[str, str | None, str], dict[str, object]] = {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        purl = None
        external_refs = package.get("externalRefs")
        if isinstance(external_refs, list):
            for external_ref in external_refs:
                if not isinstance(external_ref, dict):
                    continue
                if str(external_ref.get("referenceType") or "").lower() != "purl":
                    continue
                locator = external_ref.get("referenceLocator")
                if isinstance(locator, str) and locator:
                    purl = locator
                    break
        item = _inventory_item_from_sbom_component(
            name=package.get("name"),
            version=package.get("versionInfo"),
            purl=purl,
        )
        if item is None:
            continue
        _merge_inventory_item(inventory, item)
    return tuple(inventory.values())


def _inventory_item_from_sbom_component(
    *,
    name: object,
    version: object,
    purl: object,
) -> dict[str, object] | None:
    purl_values = _inventory_from_purl(purl if isinstance(purl, str) else None)
    if purl_values is None and not isinstance(name, str):
        return None
    ecosystem = purl_values["ecosystem"] if purl_values is not None else "unsupported"
    namespace = purl_values["namespace"] if purl_values is not None else None
    package_name = purl_values["name"] if purl_values is not None else str(name).strip()
    package_version = (
        purl_values["version"]
        if purl_values is not None
        else (str(version).strip() if isinstance(version, str) else None)
    )
    if not package_name:
        return None
    return {
        "ecosystem": ecosystem,
        "namespace": namespace,
        "name": package_name,
        "direct": False,
        "range": None,
        "version": package_version,
    }


def _inventory_from_purl(purl: str | None) -> dict[str, object] | None:
    if purl is None or not purl.startswith("pkg:"):
        return None
    without_prefix = purl[4:]
    package_type, _, remainder = without_prefix.partition("/")
    ecosystem = _ECOSYSTEM_BY_PURL.get(package_type)
    if ecosystem is None or not remainder:
        return None
    package_ref = remainder.split("?", 1)[0].split("#", 1)[0]
    package_path, _, package_version = package_ref.partition("@")
    if not package_path:
        return None
    if "/" in package_path:
        namespace, _, name = package_path.rpartition("/")
        return {
            "ecosystem": ecosystem,
            "namespace": urllib.parse.unquote(namespace) if namespace else None,
            "name": urllib.parse.unquote(name),
            "version": urllib.parse.unquote(package_version) if package_version else None,
        }
    return {
        "ecosystem": ecosystem,
        "namespace": None,
        "name": urllib.parse.unquote(package_path),
        "version": urllib.parse.unquote(package_version) if package_version else None,
    }


def _should_use_cloud_workspace_audit(
    *,
    store: GuardStore,
    posture: dict[str, object],
) -> bool:
    if store.get_cloud_sync_profile() is None or store.get_cloud_workspace_id() is None:
        return False
    bundle = posture.get("bundle")
    if not isinstance(bundle, dict):
        return False
    return str(bundle.get("tier") or "").strip().lower() == "premium"


def _run_cloud_workspace_audit(
    *,
    request_payload: dict[str, object],
    auth_context: dict[str, object] | None = None,
    sync_url: str | None = None,
    token: str | None = None,
    workspace_id: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    resolved_auth_context = auth_context
    if resolved_auth_context is None:
        if not isinstance(sync_url, str) or not sync_url or not isinstance(token, str) or not token:
            raise TypeError("auth_context or sync_url/token is required")
        request_url = _normalized_supply_chain_batch_url(sync_url, workspace_id)
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
    else:
        request_url = _normalized_supply_chain_batch_url(str(resolved_auth_context["sync_url"]), workspace_id)
        request_headers = _guard_sync_headers(resolved_auth_context, request_url=request_url, method="POST")
    aggregated_packages: list[dict[str, object]] = []
    aggregated_reasons: list[dict[str, object]] = []
    cursor: str | None = None
    last_response: dict[str, object] | None = None
    for _ in range(_CLOUD_AUDIT_MAX_PAGES):
        page_payload = dict(request_payload)
        if cursor is not None:
            page_payload["cursor"] = cursor
        request = urllib.request.Request(
            request_url,
            data=json.dumps(page_payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=_CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
                response_payload = json.load(response)
        except urllib.error.HTTPError as error:
            return (
                None,
                {
                    "code": "cloud_http_error",
                    "message": f"Guard cloud evaluation returned HTTP {error.code}, so Guard fell back locally.",
                },
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return (
                None,
                {
                    "code": "cloud_timeout",
                    "message": "Guard cloud evaluation timed out, so Guard fell back locally.",
                },
            )
        if not isinstance(response_payload, dict):
            return (
                None,
                {
                    "code": "cloud_invalid_response",
                    "message": "Guard cloud evaluation returned an invalid response, so Guard fell back locally.",
                },
            )
        last_response = response_payload
        response_packages = response_payload.get("packages")
        if isinstance(response_packages, list):
            aggregated_packages.extend(item for item in response_packages if isinstance(item, dict))
        response_reasons = response_payload.get("reasons")
        if isinstance(response_reasons, list):
            aggregated_reasons.extend(item for item in response_reasons if isinstance(item, dict))
        next_cursor = response_payload.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            break
        cursor = next_cursor
    else:
        return (
            None,
            {
                "code": "cloud_page_limit",
                "message": "Guard cloud evaluation exceeded the maximum page count, so Guard fell back locally.",
            },
        )
    if last_response is None:
        return (None, None)
    merged_response = dict(last_response)
    merged_response["packages"] = aggregated_packages
    merged_response["reasons"] = aggregated_reasons
    return (merged_response, None)


def _build_cloud_audit_payload(
    *,
    workspace_dir: Path,
    workspace_id: str,
    store: GuardStore,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    inventory: tuple[dict[str, object], ...],
) -> dict[str, object]:
    summary = store.get_sync_payload("supply_chain_bundle_summary")
    policy_version = "local:none"
    if isinstance(summary, dict):
        policy_hash = summary.get("policy_hash")
        if isinstance(policy_hash, str) and policy_hash:
            policy_version = policy_hash
    workspace_fingerprint = _workspace_audit_fingerprint(
        workspace_id=workspace_id,
        workspace_dir=workspace_dir,
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
        policy_version=policy_version,
    )
    payload: dict[str, object] = {
        "commandShape": {
            "argCount": 3,
            "flags": [],
            "packageManager": _package_manager_for_scan(manifest_paths),
            "redacted": True,
            "verb": "audit",
        },
        "harness": _LOCAL_SUPPLY_CHAIN_HARNESS,
        "lockfileContext": _workspace_audit_lockfile_context(workspace_dir, manifest_paths, lockfile_paths, inventory),
        "mode": "paged",
        "pageSize": min(_CLOUD_AUDIT_PAGE_SIZE, max(len(inventory), 1)),
        "packages": [
            {
                "direct": bool(item.get("direct")),
                "ecosystem": str(item["ecosystem"]),
                "name": str(item["name"]),
                "namespace": item.get("namespace"),
                **({"version": str(item["version"])} if isinstance(item.get("version"), str) else {}),
                **({"range": str(item["range"])} if isinstance(item.get("range"), str) else {}),
            }
            for item in inventory
        ],
        "policyVersion": policy_version,
        "workspaceFingerprint": workspace_fingerprint,
    }
    if payload["lockfileContext"] is None:
        payload.pop("lockfileContext")
    return payload


def _workspace_audit_lockfile_context(
    workspace_dir: Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    inventory: tuple[dict[str, object], ...],
) -> dict[str, object] | None:
    if not lockfile_paths:
        return None
    lockfile_path = workspace_dir / lockfile_paths[0]
    if not lockfile_path.exists():
        return None
    lockfile_text = _read_workspace_audit_text(workspace_dir, lockfile_paths[0])
    if lockfile_text is None:
        return None
    manifest_hash = None
    if manifest_paths:
        manifest_path = workspace_dir / manifest_paths[0]
        try:
            manifest_bytes = manifest_path.read_bytes()
        except OSError:
            manifest_bytes = None
        if manifest_bytes is not None and not _is_audit_sensitive_basename(manifest_path.name):
            manifest_hash = stable_digest_hex(manifest_bytes)
    return {
        "dependencyCount": len(inventory),
        "fileName": lockfile_path.name,
        "lockfileHash": stable_digest_hex(lockfile_text.encode("utf-8")),
        "manifestHash": manifest_hash,
    }


def _workspace_audit_fingerprint(
    *,
    workspace_id: str,
    workspace_dir: Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    policy_version: str,
) -> str:
    manifest_hashes = _hash_existing_paths(workspace_dir, manifest_paths)
    lockfile_hashes = _hash_existing_paths(workspace_dir, lockfile_paths)
    return stable_digest_hex(
        json.dumps(
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


def _hash_existing_paths(workspace_dir: Path, relative_paths: Sequence[str]) -> list[str]:
    hashes: list[str] = []
    for relative_path in relative_paths:
        disk_path = workspace_dir / relative_path
        if not disk_path.exists():
            continue
        try:
            hashes.append(stable_digest_hex(disk_path.read_bytes()))
        except OSError:
            continue
    return hashes


def _normalize_cloud_audit_response(response: dict[str, object]) -> dict[str, object]:
    return {
        "decision": str(response.get("decision") or "monitor"),
        "packages": [item for item in response.get("packages", []) if isinstance(item, dict)],
        "reasons": [item for item in response.get("reasons", []) if isinstance(item, dict)],
        "enforcement": str(response.get("enforcement") or "premium_cloud"),
        "entitlement_state": str(response.get("entitlementState") or "premium"),
        "cache_status": str(response.get("cacheStatus") or "miss"),
        "processed_count": int(response.get("processedCount") or 0),
        "total_packages": int(response.get("totalPackages") or 0),
        "status": str(response.get("status") or "completed"),
        "workspace_id": str(response.get("workspaceId") or ""),
    }


def _ci_gate_result(evaluation: dict[str, object], *, threshold: str) -> dict[str, object]:
    threshold_rank = _SEVERITY_RANK.get(threshold, _SEVERITY_RANK["high"])
    matched_packages: list[str] = []
    packages = evaluation.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict):
                continue
            if _package_severity_rank(package) < threshold_rank:
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
        return _SEVERITY_RANK.get(normalized_severity, _SEVERITY_RANK["unknown"])
    reasons = package.get("reasons")
    if not isinstance(reasons, list):
        return _SEVERITY_RANK["unknown"]
    highest = _SEVERITY_RANK["unknown"]
    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        severity = reason.get("severity")
        if not isinstance(severity, str):
            continue
        highest = max(highest, _SEVERITY_RANK.get(severity, _SEVERITY_RANK["unknown"]))
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


def _normalized_supply_chain_batch_url(sync_url: str, workspace_id: str) -> str:
    parsed = urllib.parse.urlsplit(sync_url)
    if parsed.path.rstrip("/") == "/api/guard/receipts/sync":
        next_path = "/api/guard/supply-chain/evaluate/batch"
    elif parsed.path.rstrip("/") == "/guard/receipts/sync":
        next_path = "/guard/supply-chain/evaluate/batch"
    else:
        next_path = parsed.path.rstrip("/") + "/supply-chain/evaluate/batch"
    query_pairs = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "workspaceId"
    ]
    query_pairs.append(("workspaceId", workspace_id))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            next_path,
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _target_from_manifest_dependency(ecosystem: str, package_name: str, version: str) -> PackageIntentTarget:
    clean_name = package_name.strip()
    clean_version = version.strip()
    if ecosystem == "npm":
        spec = clean_name if not clean_version else f"{clean_name}@{clean_version}"
        return js_target(spec)
    if ecosystem == "pypi":
        spec = clean_name if not clean_version else f"{clean_name}{clean_version}"
        return python_target(spec)
    if ecosystem == "maven":
        spec = clean_name if not clean_version else f"{clean_name}:{clean_version}"
        return coordinate_target(ecosystem, spec)
    if ecosystem == "packagist":
        spec = clean_name if not clean_version else f"{clean_name}:{clean_version}"
        return composer_target(spec)
    spec = clean_name if not clean_version else f"{clean_name}@{clean_version}"
    return version_target(ecosystem, spec)


def _target_for_package_spec(ecosystem: str, package_spec: str) -> PackageIntentTarget:
    if ecosystem == "npm":
        return js_target(package_spec)
    if ecosystem == "pypi":
        return python_target(package_spec)
    if ecosystem == "maven":
        return coordinate_target(ecosystem, package_spec)
    if ecosystem == "packagist":
        return composer_target(package_spec)
    return version_target(ecosystem, package_spec)


def _package_manager_for_scan(manifest_paths: Sequence[str]) -> str:
    for manifest_path in manifest_paths:
        ecosystem = _ECOSYSTEM_BY_MANIFEST.get(Path(manifest_path).name)
        if ecosystem is not None:
            return _PACKAGE_MANAGER_BY_ECOSYSTEM.get(ecosystem, ecosystem)
    return "workspace"


def _evaluation_exit_code(decision: str) -> int:
    return 2 if decision in {"block", "ask"} else 0


def _protect_action_for_decision(decision: str) -> str:
    if decision == "block":
        return "block"
    if decision == "ask":
        return "review"
    if decision == "warn":
        return "warn"
    return "allow"


def _evaluation_risk_signals(evaluation: object) -> list[str]:
    if not hasattr(evaluation, "reasons"):
        return []
    reasons = evaluation.reasons
    if not isinstance(reasons, tuple):
        return []
    signals: list[str] = []
    for item in reasons:
        if not isinstance(item, dict):
            continue
        message = item.get("message")
        if isinstance(message, str) and message:
            signals.append(message)
    if signals:
        return signals
    summary = getattr(evaluation, "risk_summary", None)
    return [summary] if isinstance(summary, str) and summary else []


def _matched_advisories(evaluation: object) -> list[dict[str, object]]:
    packages = getattr(evaluation, "packages", ())
    if not isinstance(packages, tuple):
        return []
    advisories: list[dict[str, object]] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        advisory_ids = item.get("related_advisory_ids")
        if not isinstance(advisory_ids, list):
            continue
        for advisory_id in advisory_ids:
            if not isinstance(advisory_id, str):
                continue
            advisories.append(
                {
                    "advisory_id": advisory_id,
                    "package_name": item.get("name"),
                    "version": item.get("version"),
                    "decision": item.get("decision"),
                }
            )
    return advisories


def _protect_target_payload(target: PackageIntentTarget) -> dict[str, object]:
    return {
        "artifact_id": f"{target.ecosystem}:{target.package_name or target.raw_spec}",
        "artifact_name": target.package_name or target.raw_spec,
        "artifact_type": "package_request",
        "ecosystem": target.ecosystem,
        "package_name": target.package_name,
        "package_url": None,
        "raw_spec": target.raw_spec,
        "version": target.requested_specifier,
        "source_url": target.source_url,
        "harness": _LOCAL_SUPPLY_CHAIN_HARNESS,
    }


def _redact_command_token(token: str) -> str:
    if "=" in token:
        key, _, _ = token.partition("=")
        if any(fragment in key.lower() for fragment in ("token", "secret", "api_key", "api-key", "password")):
            return f"{key}=*****"
    if ":" in token:
        key, _, _ = token.partition(":")
        if any(fragment in key.lower() for fragment in ("token", "secret", "api_key", "api-key", "password")):
            return f"{key}: *****"
    return redact_text(token).text


def _posture_status(
    *,
    credentials_present: bool,
    workspace_id: str | None,
    summary: dict[str, object],
    bundle_payload: dict[str, object],
    expires_at: datetime | None,
    snapshot_now: datetime,
) -> str:
    if not credentials_present:
        return "not_connected"
    if workspace_id is None:
        return "workspace_required"
    if not summary and not bundle_payload:
        return "sync_required"
    if expires_at is not None and expires_at <= snapshot_now:
        return "expired"
    summary_status = _string_value(summary.get("status"))
    if summary_status:
        return summary_status
    if bundle_payload:
        return "synced"
    return "degraded"


def _posture_detail(status: str) -> str:
    details = {
        "not_connected": "Connect Guard Cloud to fetch signed supply-chain bundles.",
        "workspace_required": "Finish Guard Cloud pairing to fetch workspace-specific supply-chain bundles.",
        "sync_required": "Run `hol-guard supply-chain sync` to fetch the latest signed bundle.",
        "expired": "The cached signed bundle expired. Run `hol-guard supply-chain sync` before the next install.",
        "synced": "Signed supply-chain bundle is ready for local install protection.",
        "degraded": "Supply-chain protection is degraded. Refresh the signed bundle before trusting new installs.",
    }
    return details.get(status, "Supply-chain protection status is available.")


def _posture_health_status(
    *,
    status: str,
    next_refresh_at: str | None,
    snapshot_now: datetime,
) -> str:
    if status == "expired":
        return "stale"
    if status in {"not_connected", "workspace_required", "sync_required", "degraded"}:
        return "degraded"
    next_refresh_timestamp = _parse_timestamp(next_refresh_at)
    if (
        status == "synced"
        and next_refresh_timestamp is not None
        and next_refresh_timestamp + timedelta(seconds=_STALE_REFRESH_GRACE_SECONDS) <= snapshot_now
    ):
        return "stale"
    if status == "synced":
        return "protected"
    return "degraded"


def _resolve_next_refresh_at(
    *,
    summary: dict[str, object],
    synced_at: str | None,
) -> str | None:
    explicit_next_refresh = _parse_timestamp(_string_value(summary.get("next_refresh_at")))
    if explicit_next_refresh is not None:
        return explicit_next_refresh.isoformat()
    synced_timestamp = _parse_timestamp(synced_at)
    if synced_timestamp is None:
        return None
    return (synced_timestamp + timedelta(seconds=_DEFAULT_BUNDLE_REFRESH_INTERVAL_SECONDS)).isoformat()


def _dict_payload(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _int_value(value: object) -> int | None:
    if isinstance(value, int):
        return value
    return None


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

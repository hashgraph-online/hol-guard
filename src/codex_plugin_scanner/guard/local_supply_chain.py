"""Shared local supply-chain posture and CLI helpers."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import os
import shlex
import socket
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, TypeGuard, cast
from uuid import uuid4

from codex_plugin_scanner.path_support import resolve_path_within_allowed_roots, resolves_within_root

from .action_lattice import most_restrictive_guard_action, normalize_guard_action
from .adapters.base import HarnessContext
from .advisory_model import ProtectTargetIdentity, advisory_matches_target, build_package_url
from .approval_scope_support import package_request_runtime_workspace_scope
from .config import GuardConfig, resolve_risk_action
from .mdm.network import managed_urlopen
from .models import GuardAction, GuardArtifact, GuardReceipt
from .package_execution_context import PackageExecutionContext, build_package_execution_context
from .redaction import redact_local_path, redact_text
from .runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_runtime_launch_identity,
    resolved_runtime_launch_argv,
    runtime_launch_identity_is_reusable,
)
from .runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from .runtime.lockfile_parse_result import LOCKFILE_PARSER_VERSION
from .runtime.package_execution_policy import is_execution_permitted
from .runtime.package_intent_common import (
    PackageIntent,
    PackageIntentTarget,
    build_package_request_artifact,
    composer_target,
    coordinate_target,
    existing_relative_paths,
    js_target,
    python_target,
    redact_package_request_token,
    version_target,
)
from .runtime.package_manifest_diff import parse_manifest_dependencies, parse_manifest_dependency_changes
from .runtime.restricted_archive_download import RestrictedArchiveDownload
from .runtime.supply_chain_support import ecosystem_support_matrix
from .runtime.workspace_path_guard import (
    read_bytes_within_workspace,
    read_text_within_workspace,
    resolve_path_within_workspace,
)
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
_WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        "dist",
        "build",
        ".next",
        "target",
        ".guard",
        ".worktrees",
        "worktrees",
    }
)
_WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH = 3
_MANIFEST_CANDIDATE_SET = frozenset(_MANIFEST_CANDIDATES)
_LOCKFILE_CANDIDATE_SET = frozenset(_LOCKFILE_CANDIDATES)
_INFORMATIONAL_REASON_CODES = frozenset({"unknown_package", "no_cached_match"})
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
_CLOUD_AUDIT_JOB_PAGE_SIZE = 1
_CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS = 0.5
_CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS = 20
_CLOUD_AUDIT_SYNC_PAGE_SIZE = 25
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


def _runtime_runner_module():
    return importlib.import_module(".runtime.runner", __package__)


_LAZY_RUNTIME_RUNNER_EXPORTS = frozenset(
    {
        "GuardSyncAuthorizationExpiredError",
        "GuardSyncNotAvailableError",
        "GuardSyncNotConfiguredError",
    }
)


def __getattr__(name: str) -> Any:
    if name in _LAZY_RUNTIME_RUNNER_EXPORTS:
        return getattr(_runtime_runner_module(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _package_firewall_entitlement_module():
    return importlib.import_module(".package_firewall_entitlement", __package__)


def _package_intent_parser_module():
    return importlib.import_module(".runtime.package_intent_parser", __package__)


def _supply_chain_package_eval_module():
    return importlib.import_module(".runtime.supply_chain_package_eval", __package__)


def sync_local_guard_cloud_proof(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return _runtime_runner_module().sync_local_guard_cloud_proof(store, auth_context=auth_context)


def sync_supply_chain_bundle(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    return _runtime_runner_module().sync_supply_chain_bundle(store, auth_context=auth_context)


def _resolve_guard_sync_auth_context(store: GuardStore):
    return _runtime_runner_module()._resolve_guard_sync_auth_context(store)


def evaluate_package_request_artifact(*args: object, **kwargs: object):
    return _supply_chain_package_eval_module().evaluate_package_request_artifact(*args, **kwargs)


def _is_package_request_evaluation(value: object) -> TypeGuard[Any]:
    return isinstance(value, _supply_chain_package_eval_module().PackageRequestEvaluation)


def _build_guard_receipt(
    *,
    harness: str,
    artifact_id: str,
    artifact_hash: str,
    policy_decision: GuardAction,
    capabilities_summary: str,
    changed_capabilities: list[str],
    provenance_summary: str,
    artifact_name: str | None,
    source_scope: str | None,
    scanner_evidence: tuple[dict[str, object], ...] = (),
) -> GuardReceipt:
    sample = ", ".join(changed_capabilities[:3])
    suffix = " ..." if len(changed_capabilities) > 3 else ""
    diff_summary = f"{len(changed_capabilities)} change(s): {sample}{suffix}" if changed_capabilities else None
    return GuardReceipt(
        receipt_id=f"guard-receipt-{uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=policy_decision,
        capabilities_summary=capabilities_summary,
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        artifact_name=artifact_name,
        source_scope=source_scope,
        diff_summary=diff_summary,
        scanner_evidence=scanner_evidence,
    )


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
    store: Any,
    config: GuardConfig,
    *,
    now: str | None = None,
) -> dict[str, object]:
    from .synced_policy import synced_policy_payload

    snapshot_now = _parse_timestamp(now) or datetime.now(timezone.utc)
    workspace_id = store.get_cloud_workspace_id()
    cloud_profile = store.get_cloud_sync_profile()
    summary = _dict_payload(store.get_sync_payload("supply_chain_bundle_summary"))
    entitlement = _dict_payload(store.get_sync_payload("supply_chain_bundle_entitlement"))
    remote_policy = _dict_payload(synced_policy_payload(store))
    # Legacy team-policy siblings are not signed policy-bundle content and
    # therefore cannot contribute enforcement or managed-policy status.
    team_policy_pack: dict[str, object] = {}
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
    store: Any,
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


def _call_sync_with_optional_auth_context(
    refresh: Any,
    *,
    store: Any,
    auth_context: dict[str, object],
) -> dict[str, object]:
    try:
        parameters = inspect.signature(refresh).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "auth_context" in parameters:
        return refresh(store, auth_context=auth_context)
    return refresh(store)


def resolve_package_firewall_entitlement_with_refresh(store: Any) -> dict[str, object]:
    """Resolve package-firewall access and opportunistically heal stale cloud state."""

    entitlement_module = _package_firewall_entitlement_module()
    runner = _runtime_runner_module()

    entitlement = entitlement_module.resolve_package_firewall_entitlement(store)
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
    auth_context: dict[str, object] | None = None
    try:
        auth_context = _resolve_guard_sync_auth_context(store)
    except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncNotAvailableError):
        auth_context = None
    except (runner.GuardSyncNotConfiguredError, OSError, RuntimeError):
        auth_context = None
    for refresh in (sync_local_guard_cloud_proof, sync_supply_chain_bundle):
        try:
            if auth_context is None:
                refresh(store)
            else:
                _call_sync_with_optional_auth_context(
                    refresh,
                    store=store,
                    auth_context=auth_context,
                )
        except runner.GuardSyncAuthorizationExpiredError as error:
            if str(entitlement.get("reason") or "") == "guard_cloud_connect_required":
                store.record_latest_guard_connect_sync_result(
                    status="retry_required",
                    milestone="first_sync_failed",
                    now=now_iso,
                    reason=str(error),
                )
            break
        except (runner.GuardSyncNotAvailableError, runner.GuardSyncNotConfiguredError, OSError, RuntimeError):
            continue
    return entitlement_module.resolve_package_firewall_entitlement(store)


def _is_audit_sensitive_basename(name: str) -> bool:
    lowered = name.lower()
    return lowered in _AUDIT_SENSITIVE_BASENAMES or lowered.startswith(".env.")


def _read_workspace_audit_text(workspace_dir: Path, relative_path: str) -> str | None:
    if _is_audit_sensitive_basename(Path(relative_path).name):
        return None
    return read_text_within_workspace(workspace_dir, relative_path)


def _workspace_has_project_markers(workspace_dir: Path) -> bool:
    try:
        resolved = workspace_dir.resolve()
    except OSError:
        return False
    return any((resolved / marker).exists() for marker in _MANIFEST_CANDIDATES)


def managed_install_audit_workspace_dirs(store: Any) -> tuple[str, ...]:
    installs = store.list_managed_installs()
    ordered = sorted(
        installs,
        key=lambda item: (
            1 if bool(item.get("active")) else 0,
            str(item.get("updated_at") or ""),
        ),
        reverse=True,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for install in ordered:
        workspace = install.get("workspace")
        if not isinstance(workspace, str):
            continue
        normalized = workspace.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)
    return tuple(candidates)


def _managed_workspace_audit_candidates(
    store: Any,
    *,
    workspace_dir: Path | None = None,
) -> tuple[Path, ...]:
    candidates: list[Path] = []
    seen: set[str] = set()
    raw_candidates: list[Path] = []
    if workspace_dir is not None:
        raw_candidates.append(workspace_dir)
    raw_candidates.extend(Path(entry).expanduser() for entry in managed_install_audit_workspace_dirs(store))
    for candidate in raw_candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        normalized = str(resolved)
        if normalized in seen or not resolved.exists() or not resolved.is_dir():
            continue
        if not _workspace_has_project_markers(resolved):
            continue
        seen.add(normalized)
        candidates.append(resolved)
    return tuple(candidates)


def resolve_supply_chain_audit_workspace_dir(
    *,
    workspace_dir_value: object,
    workspace_value: object,
    allowed_roots: tuple[Path, ...],
    managed_workspace_dirs: Sequence[str] | None = None,
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
        cwd = None
    if cwd is not None and _workspace_has_project_markers(cwd):
        for root in allowed_roots:
            if resolves_within_root(root, cwd, require_exists=True):
                return cwd
    for managed_workspace in managed_workspace_dirs or ():
        resolved = resolve_path_within_allowed_roots(
            managed_workspace,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None and _workspace_has_project_markers(resolved):
            return resolved
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


def _package_advisory_ids(package: dict[str, object]) -> list[str]:
    advisory_ids: list[str] = []
    seen: set[str] = set()

    def add_id(value: object) -> None:
        if not isinstance(value, str):
            return
        trimmed = value.strip()
        if not trimmed or trimmed in seen:
            return
        seen.add(trimmed)
        advisory_ids.append(trimmed)

    for key in ("advisoryIds", "advisory_ids", "relatedAdvisoryIds", "related_advisory_ids"):
        raw = package.get(key)
        if isinstance(raw, list):
            for entry in raw:
                add_id(entry)
    add_id(package.get("advisoryId"))
    add_id(package.get("advisory_id"))
    reasons = package.get("reasons")
    if isinstance(reasons, list):
        for reason in reasons:
            if not isinstance(reason, dict):
                continue
            add_id(reason.get("advisoryId"))
            add_id(reason.get("advisory_id"))
    return advisory_ids


def _cached_supply_chain_bundle_payload(store: Any) -> dict[str, object] | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached_bundle, dict):
        return None
    bundle_payload = cached_bundle.get("bundle")
    if isinstance(bundle_payload, dict):
        return bundle_payload
    return None


def _resolve_advisory_aliases_from_bundle(
    bundle: dict[str, object] | None,
    advisory_ids: list[str],
) -> list[str]:
    aliases: list[str] = []
    seen: set[str] = set()
    lookup: dict[str, tuple[str, ...]] = {}
    if isinstance(bundle, dict):
        advisories = bundle.get("advisories")
        if isinstance(advisories, list):
            for advisory in advisories:
                if not isinstance(advisory, dict):
                    continue
                advisory_id = advisory.get("advisoryId")
                if not isinstance(advisory_id, str) or not advisory_id.strip():
                    continue
                raw_aliases = advisory.get("aliases")
                alias_tuple: tuple[str, ...] = (advisory_id,)
                if isinstance(raw_aliases, list):
                    alias_tuple = (
                        advisory_id,
                        *[alias for alias in raw_aliases if isinstance(alias, str) and alias.strip()],
                    )
                upper_tuple = tuple(alias.upper() for alias in alias_tuple)
                lookup[advisory_id.upper()] = upper_tuple
                for alias in alias_tuple:
                    lookup.setdefault(alias.upper(), upper_tuple)

    def add_alias(value: str) -> None:
        trimmed = value.strip().upper()
        if not trimmed or trimmed in seen:
            return
        seen.add(trimmed)
        aliases.append(trimmed)

    for advisory_id in advisory_ids:
        add_alias(advisory_id)
        resolved = lookup.get(advisory_id.upper())
        if resolved is None:
            continue
        for alias in resolved:
            add_alias(alias)
    return aliases


def _enrich_package_with_advisory_aliases(
    package: dict[str, object],
    *,
    bundle: dict[str, object] | None,
) -> dict[str, object]:
    existing_aliases = package.get("advisoryAliases")
    if isinstance(existing_aliases, list) and existing_aliases:
        return package
    advisory_ids = _package_advisory_ids(package)
    if not advisory_ids:
        return package
    aliases = _resolve_advisory_aliases_from_bundle(bundle, advisory_ids)
    if not aliases:
        return package
    enriched = dict(package)
    enriched["advisoryAliases"] = aliases
    return enriched


def _enrich_evaluation_packages_with_advisory_aliases(
    evaluation: dict[str, object],
    store: Any,
) -> dict[str, object]:
    packages = evaluation.get("packages")
    if not isinstance(packages, list):
        return evaluation
    bundle = _cached_supply_chain_bundle_payload(store)
    enriched_packages: list[dict[str, object]] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        enriched_packages.append(_enrich_package_with_advisory_aliases(package, bundle=bundle))
    return {**evaluation, "packages": enriched_packages}


def _package_reason_codes(item: dict[str, object]) -> frozenset[str]:
    reasons = item.get("reasons")
    if not isinstance(reasons, list):
        return frozenset()
    codes: set[str] = set()
    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        code = str(reason.get("code") or "").strip()
        if code:
            codes.add(code)
    return frozenset(codes)


def _is_actionable_package_finding(item: dict[str, object]) -> bool:
    decision = str(item.get("decision") or "monitor")
    if decision in {"block", "ask", "warn"}:
        return True
    reason_codes = _package_reason_codes(item)
    if not reason_codes:
        return decision not in {"allow", "monitor"}
    return not reason_codes.issubset(_INFORMATIONAL_REASON_CODES)


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
    return [_enrich_package_with_advisory_aliases(item, bundle=bundle) for item in ranked[:limit]]


def _audit_package_findings_for_receipt(
    package_items: list[dict[str, object]],
    *,
    limit: int = 100,
    bundle: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    decision_rank_map = {"block": 4, "ask": 3, "warn": 2, "monitor": 1, "allow": 0}
    ranked: list[tuple[int, int, dict[str, object]]] = []
    for item in package_items:
        if not _is_actionable_package_finding(item):
            continue
        decision = str(item.get("decision") or "monitor")
        severity_rank = _package_severity_rank(item)
        decision_rank = decision_rank_map.get(decision, 0)
        ranked.append((decision_rank, severity_rank, item))
    ranked.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
    return [_enrich_package_with_advisory_aliases(item, bundle=bundle) for _, _, item in ranked[:limit]]


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


def _resolve_empty_audit_outcome(
    *,
    manifest_paths: Sequence[str],
    lockfile_paths: Sequence[str],
    posture: dict[str, object],
) -> tuple[str, str]:
    supply_status = str(posture.get("status") or "")
    supply_detail = str(posture.get("detail") or _posture_detail(supply_status))
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
    workspace_dir: Path | None = None,
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
    path_hashes = workspace_audit_path_hashes(workspace_dir, manifest_paths, lockfile_paths)
    policy_decision: GuardAction = (
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
    workspace_dir: Path | None = None,
    store: Any | None = None,
) -> dict[str, object]:
    evaluation = result.get("evaluation")
    if not isinstance(evaluation, dict):
        return _incomplete_audit_receipt_metadata(result, workspace_dir=workspace_dir)
    decision = str(evaluation.get("decision") or "monitor")
    packages = evaluation.get("packages")
    package_items = [item for item in packages if isinstance(item, dict)] if isinstance(packages, list) else []
    blocked_packages = [item for item in package_items if str(item.get("decision") or "") == "block"]
    bundle = _cached_supply_chain_bundle_payload(store) if store is not None else None
    package_findings = _audit_package_findings_for_receipt(package_items, bundle=bundle)
    package_inventory = _audit_package_inventory_for_receipt(package_items, bundle=bundle)
    policy_decision: GuardAction = "allow"
    if decision == "block":
        policy_decision = "block"
    elif decision == "ask":
        policy_decision = "review"
    elif decision == "warn":
        policy_decision = "warn"
    inventory = result.get("inventory")
    inventory_summary = inventory if isinstance(inventory, dict) else {}
    manifest_paths = list(_string_items(result.get("manifest_paths")))
    lockfile_paths = list(_string_items(result.get("lockfile_paths")))
    path_hashes = workspace_audit_path_hashes(workspace_dir, manifest_paths, lockfile_paths)
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
    runner = _runtime_runner_module()

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
        audit_outcome, message = _resolve_empty_audit_outcome(
            manifest_paths=manifest_paths,
            lockfile_paths=lockfile_paths,
            posture=posture,
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
        except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncNotConfiguredError, RuntimeError):
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
    store: Any,
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
    store: Any,
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


@dataclass(frozen=True, slots=True)
class _PackageProtectAuthority:
    intent: PackageIntent
    artifact: GuardArtifact
    evaluation: Any
    current_action: GuardAction
    execution_context: PackageExecutionContext
    artifact_hash: str
    launch_identity: dict[str, object]
    launch_cwd: Path
    launch_environment: Mapping[str, str]
    additional_current_action: object | None
    additional_policy_context: dict[str, object] | None


_PackageApprovalClaimDisposition = Literal["consumed", "retained"]


@dataclass(frozen=True, slots=True)
class _StoredPackagePolicyResolution:
    evaluation: Any
    approval_reuse_decision: Mapping[str, object] | None = None
    claim_disposition: _PackageApprovalClaimDisposition | None = None


@dataclass(frozen=True, slots=True)
class _PackageProtectProjection:
    receipt: GuardReceipt
    receipt_policy_metadata: dict[str, object]
    verdict_action: GuardAction
    risk_signals: tuple[str, ...]


def _external_archive_downloads(evaluation: object) -> tuple[RestrictedArchiveDownload, ...]:
    value = getattr(evaluation, "external_archive_downloads", ())
    if not isinstance(value, tuple):
        return ()
    return tuple(item for item in value if isinstance(item, RestrictedArchiveDownload))


def _cleanup_external_archive_downloads(evaluation: object) -> None:
    for download in _external_archive_downloads(evaluation):
        download.cleanup()


def _package_evaluation_requires_external_archive_binding(evaluation: object) -> bool:
    source_hashes = getattr(evaluation, "external_archive_source_hashes", ())
    if isinstance(source_hashes, (list, tuple)) and any(
        isinstance(item, str) and len(item) == 64 for item in source_hashes
    ):
        return True
    reasons = getattr(evaluation, "reasons", ())
    if isinstance(reasons, (list, tuple)) and any(
        isinstance(reason, Mapping) and reason.get("code") == "external_tarball_source" for reason in reasons
    ):
        return True
    packages = getattr(evaluation, "packages", ())
    if not isinstance(packages, (list, tuple)):
        return False
    return any(
        isinstance(package, Mapping)
        and isinstance(package_reasons := package.get("reasons"), (list, tuple))
        and any(
            isinstance(reason, Mapping) and reason.get("code") == "external_tarball_source"
            for reason in package_reasons
        )
        for package in packages
    )


def _verified_external_archive_replacements(evaluation: object) -> dict[str, str] | None:
    replacements: dict[str, str] = {}
    for download in _external_archive_downloads(evaluation):
        descriptor = -1
        try:
            path_stat = download.path.lstat()
            descriptor = os.open(
                download.path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(path_stat.st_mode)
                or not stat.S_ISREG(file_stat.st_mode)
                or path_stat.st_dev != file_stat.st_dev
                or path_stat.st_ino != file_stat.st_ino
                or file_stat.st_nlink != 1
                or file_stat.st_size != download.size
                or stat.S_IMODE(file_stat.st_mode) & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            ):
                return None
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(descriptor, "rb", closefd=True) as archive_file:
                descriptor = -1
                while True:
                    chunk = archive_file.read(min(64 * 1024, download.size - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > download.size:
                        return None
                    digest.update(chunk)
        except OSError:
            return None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if size != download.size or digest.hexdigest() != download.sha256:
            return None
        replacements[download.source_url] = str(download.path)
    return replacements


def _bound_external_archive_launch_command(
    launch_command: Sequence[str],
    *,
    evaluation: object,
) -> list[str] | None:
    replacements = _verified_external_archive_replacements(evaluation)
    if replacements is None:
        return None
    if not replacements:
        return None if _package_evaluation_requires_external_archive_binding(evaluation) else list(launch_command)
    bound_command = [str(item) for item in launch_command]
    for source_url, replacement in replacements.items():
        replacement_count = 0
        for index, argument in enumerate(bound_command):
            if source_url not in argument:
                continue
            bound_command[index] = argument.replace(source_url, replacement)
            replacement_count += 1
        if replacement_count == 0:
            return None
    return bound_command


def _build_package_protect_authority(
    *,
    command: Sequence[str],
    store: Any,
    workspace_dir: Path,
    now: str,
    config: GuardConfig | None,
    additional_current_action: object | None,
    additional_policy_context: dict[str, object] | None,
    external_archive_network_authorized: bool = False,
) -> _PackageProtectAuthority | None:
    try:
        launch_cwd = workspace_dir.expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("package workspace must resolve to an existing directory") from None
    if not launch_cwd.is_dir():
        raise ValueError("package workspace must resolve to an existing directory")
    launch_environment = dict(os.environ)
    intent = _package_intent_parser_module().parse_package_intent(shlex.join(command), workspace=launch_cwd)
    if intent is None:
        return None
    sanitized_intent = replace(intent, redacted_command=shlex.join(redacted_command_tokens(command)))
    artifact = build_package_request_artifact(
        _LOCAL_SUPPLY_CHAIN_HARNESS,
        sanitized_intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=launch_cwd,
        now=now,
        external_archive_network_authorized=external_archive_network_authorized,
        retain_external_archive_blob=external_archive_network_authorized,
    )
    try:
        current_action = compose_current_package_policy_action(
            artifact=artifact,
            evaluation=evaluation,
            config=config,
            additional_current_action=additional_current_action,
        )
        executable = sanitized_intent.command_tokens[0] if sanitized_intent.command_tokens else None
        executable_args = sanitized_intent.command_tokens[1:] if executable is not None else ()
        if sanitized_intent.command_tokens and ";" in sanitized_intent.command_tokens:
            executable = None
            executable_args = ()
        execution_context = build_package_execution_context(
            workspace_dir=launch_cwd,
            artifact=artifact,
            executable=executable,
            executable_args=executable_args,
            environment=launch_environment,
        )
        launch_identity = build_runtime_launch_identity(
            str(command[0]) if command else None,
            args=tuple(str(item) for item in command[1:]),
            structured_command=True,
            direct_executable=True,
            cwd=launch_cwd,
            launch_env=launch_environment,
        )
        if command and executable is not None and str(command[0]) != executable:
            launch_identity["wrapper_resolution"] = {
                "reason": "package_command_wrapper_unresolved",
                "reuse_nonce": uuid4().hex,
                "status": "unproven",
            }
        artifact_hash = _package_request_artifact_hash(
            artifact,
            workspace_dir=launch_cwd,
            store=store,
            evaluation=evaluation,
            execution_context=execution_context,
            launch_identity=launch_identity,
            config=config,
            additional_current_action=additional_current_action,
            additional_policy_context=additional_policy_context,
        )
        return _PackageProtectAuthority(
            intent=sanitized_intent,
            artifact=artifact,
            evaluation=evaluation,
            current_action=current_action,
            execution_context=execution_context,
            artifact_hash=artifact_hash,
            launch_identity=launch_identity,
            launch_cwd=launch_cwd,
            launch_environment=launch_environment,
            additional_current_action=additional_current_action,
            additional_policy_context=additional_policy_context,
        )
    except BaseException:
        _cleanup_external_archive_downloads(evaluation)
        raise


def _final_package_protect_authority(
    *,
    initial: _PackageProtectAuthority,
    saved_approval_claimed: bool,
    saved_approval_claim_disposition: _PackageApprovalClaimDisposition | None,
    command: Sequence[str],
    store: Any,
    workspace_dir: Path,
    now: str,
    config: GuardConfig | None,
    current_config_provider: Callable[[], GuardConfig] | None,
    additional_authority_provider: Callable[[], tuple[object | None, dict[str, object] | None]] | None,
) -> tuple[_PackageProtectAuthority, Any]:
    """Rebuild all current authority after a claim and immediately before spawn."""

    additional_action: object | None = initial.additional_current_action
    additional_context: dict[str, object] | None = initial.additional_policy_context
    current_config = config
    config_refresh_failed = False
    if current_config_provider is not None:
        try:
            current_config = current_config_provider()
            if not isinstance(current_config, GuardConfig):
                raise TypeError("current config provider returned an invalid value")
        except Exception:
            config_refresh_failed = True
    if additional_authority_provider is not None:
        try:
            additional_action, additional_context = additional_authority_provider()
        except Exception as error:
            additional_action = "block"
            additional_context = {
                "available": False,
                "error": type(error).__name__,
                "status": "authority_refresh_failed",
                "version": 1,
            }
    if config_refresh_failed:
        additional_action = most_restrictive_guard_action(
            additional_action,
            "block",
            unknown_action="block",
        )
        additional_context = {
            "additional": additional_context,
            "available": False,
            "reason_code": "package_config_refresh_failed",
            "status": "authority_refresh_failed",
            "version": 1,
        }
    current = _build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=current_config,
        additional_current_action=additional_action,
        additional_policy_context=additional_context,
        external_archive_network_authorized=saved_approval_claimed,
    )
    if current is None:
        reuse = evaluate_approval_reuse(
            "review",
            "allow",
            saved_decision_present=True,
            validation_reason="approval_reuse_identity_changed",
        )
        return initial, _package_evaluation_with_rejected_reuse(initial.evaluation, reuse)
    validation_reason: ApprovalReuseValidationFailure | None
    if current.artifact.artifact_id != initial.artifact.artifact_id:
        validation_reason = "approval_reuse_identity_changed"
    else:
        validation_reason = cast(
            ApprovalReuseValidationFailure | None,
            approval_context_tokens_validation_reason(initial.artifact_hash, current.artifact_hash),
        )
    current_evaluation = _package_evaluation_with_current_policy_action(
        current.evaluation,
        current_action=current.current_action,
    )
    if saved_approval_claimed:
        if validation_reason is not None:
            reuse = evaluate_approval_reuse(
                current.current_action,
                "allow",
                saved_decision_present=True,
                validation_reason=validation_reason,
            )
            return current, _package_evaluation_with_rejected_reuse(current_evaluation, reuse)
        refreshed_saved_policy = _apply_stored_package_policy_override(
            current_evaluation,
            store=store,
            artifact=current.artifact,
            artifact_hash=current.artifact_hash,
            workspace_dir=workspace_dir,
            now=now,
            execution_context=current.execution_context,
            current_action=current.current_action,
            claim_saved_approval=False,
        )
        if _evaluation_uses_saved_package_approval(refreshed_saved_policy):
            # Persistent and explicitly reusable approvals must still exist
            # and match at the final boundary. The fresh resolver has already
            # composed any newly inserted block or integrity failure.
            return current, refreshed_saved_policy
        if _package_approval_reuse_evidence(refreshed_saved_policy):
            # A fresh saved-policy result exists but is no longer an accepted
            # exact allow (for example, a new block or tampered authority).
            return current, refreshed_saved_policy
        if saved_approval_claim_disposition != "consumed":
            # Retained package local-once and persistent policy grants remain
            # authoritative after a successful claim. Their disappearance is
            # a post-claim revocation, never evidence of one-shot consumption.
            reuse = evaluate_approval_reuse(
                current.current_action,
                "allow",
                saved_decision_present=True,
                validation_reason=APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
            )
            return current, _package_evaluation_with_rejected_reuse(current_evaluation, reuse)
        # Only a consuming one-shot is expected to disappear at claim time.
        # Carry its atomic proof after the fresh lookup establishes that no
        # newer saved authority applies and every current context still matches.
        reuse = evaluate_approval_reuse(
            current.current_action,
            "allow",
            saved_decision_present=True,
        )
        if reuse.accepted and reuse.saved_action == "allow":
            return current, _package_policy_override_evaluation(
                current_evaluation,
                decision="allow",
                policy_action="allow",
                title="Allowed by saved approval",
                summary="HOL Guard reused your saved approval for this package request.",
                harness_message=(
                    "HOL Guard revalidated the repository, package manager, dependency files, settings, "
                    "registry environment, and current advisory authority after atomically claiming approval."
                ),
                reason_code="saved_package_approval",
                reason_message="HOL Guard reused your saved approval for this package request.",
                approval_reuse=reuse,
            )
        return current, _package_evaluation_with_rejected_reuse(current_evaluation, reuse)
    if validation_reason is not None:
        reuse = evaluate_approval_reuse(
            current.current_action,
            "require-reapproval",
            saved_decision_present=True,
            validation_reason=validation_reason,
        )
        return current, _package_evaluation_with_rejected_reuse(current_evaluation, reuse)
    resolved = _apply_stored_package_policy_override(
        current_evaluation,
        store=store,
        artifact=current.artifact,
        artifact_hash=current.artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=current.execution_context,
        current_action=current.current_action,
        claim_saved_approval=False,
    )
    if _evaluation_uses_saved_package_approval(resolved):
        reuse = evaluate_approval_reuse(
            current.current_action,
            "allow",
            saved_decision_present=True,
            validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
        )
        resolved = _package_evaluation_with_rejected_reuse(current_evaluation, reuse)
    return current, resolved


def _apply_package_protect_projection(
    *,
    payload: dict[str, object],
    authority: _PackageProtectAuthority,
    evaluation: Any,
    command: Sequence[str],
    blocking: bool,
    executed: bool,
) -> _PackageProtectProjection:
    """Project one authority/evaluation pair into every user and audit surface."""

    intent = authority.intent
    public_targets = [target.to_dict() for target in intent.targets]
    artifact = authority.artifact
    artifact_hash = authority.artifact_hash
    verdict_action = _protect_action_for_policy_action(evaluation.policy_action)
    risk_signals = tuple(_evaluation_risk_signals(evaluation))
    approval_reuse_evidence = _package_approval_reuse_evidence(evaluation)
    receipt_policy_metadata: dict[str, object] = {
        "matched_rule_id": evaluation.matched_rule_id,
        "package_execution_context": authority.execution_context.to_evidence(),
        "package_manager": intent.package_manager,
        "package_targets": [str(target.get("raw_spec") or "") for target in public_targets],
        "policy_action": verdict_action,
        "policy_version": evaluation.policy_version,
        "redacted_command": intent.redacted_command,
    }
    if evaluation.bundle_version is not None:
        receipt_policy_metadata["bundle_version"] = evaluation.bundle_version
    if authority.additional_policy_context is not None:
        receipt_policy_metadata["additional_policy_context"] = authority.additional_policy_context
    if approval_reuse_evidence:
        receipt_policy_metadata["approval_reuse"] = list(approval_reuse_evidence)
    receipt = _build_guard_receipt(
        harness=_LOCAL_SUPPLY_CHAIN_HARNESS,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=verdict_action,
        capabilities_summary=evaluation.user_copy.summary,
        changed_capabilities=[
            target.package_name or str(public_target.get("raw_spec") or "")
            for target, public_target in zip(intent.targets, public_targets, strict=True)
        ],
        provenance_summary=evaluation.user_copy.harness_message,
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
        scanner_evidence=approval_reuse_evidence,
    )
    matched_advisories = _matched_advisories(evaluation)
    payload["request"] = {
        "command": shlex.split(intent.redacted_command),
        "redacted_command": intent.redacted_command,
        "install_kind": intent.intent_kind,
        "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
        "package_manager": intent.package_manager,
        "harness": _LOCAL_SUPPLY_CHAIN_HARNESS,
        "targets": public_targets,
        "manifest_paths": list(intent.manifest_paths),
        "lockfile_paths": list(intent.lockfile_paths),
        "package_execution_context": authority.execution_context.to_evidence(),
    }
    payload["targets"] = [_protect_target_payload(target) for target in intent.targets]
    payload["verdict"] = {
        "action": verdict_action,
        "reason": evaluation.user_copy.summary,
        "risk_signals": list(risk_signals),
        "matched_advisories": matched_advisories,
        "blocking": blocking,
    }
    payload["receipt"] = {
        **receipt.to_dict(),
        "action_envelope_json": receipt_policy_metadata,
    }
    payload["matched_advisories"] = matched_advisories
    payload["supply_chain_evaluation"] = evaluation.to_dict()
    payload["executed"] = executed
    return _PackageProtectProjection(
        receipt=receipt,
        receipt_policy_metadata=receipt_policy_metadata,
        verdict_action=verdict_action,
        risk_signals=risk_signals,
    )


def _package_protect_denied_after_final_boundary(
    *,
    payload: dict[str, object],
    authority: _PackageProtectAuthority,
    evaluation: Any,
    command: Sequence[str],
    store: Any,
    now: str,
) -> tuple[dict[str, object], int]:
    projection = _apply_package_protect_projection(
        payload=payload,
        authority=authority,
        evaluation=evaluation,
        command=command,
        blocking=True,
        executed=False,
    )
    store.add_receipt(projection.receipt)
    store.set_receipt_action_envelope(
        projection.receipt.receipt_id,
        projection.receipt_policy_metadata,
    )
    store.add_event(
        f"install_time_{projection.verdict_action}",
        {
            "artifact_id": authority.artifact.artifact_id,
            "artifact_name": authority.artifact.name,
            "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
            "install_kind": authority.intent.intent_kind,
            "action": projection.verdict_action,
            "risk_signals": list(projection.risk_signals),
        },
        now,
    )
    return payload, _package_execution_exit_code(evaluation.policy_action)


def build_package_protect_payload(
    *,
    command: Sequence[str],
    store: Any,
    workspace_dir: Path,
    dry_run: bool,
    allow_saved_approval_execution: bool = False,
    now: str,
    config: GuardConfig | None,
    unsafe_raw_output: bool,
    timeout_seconds: int,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
    current_config_provider: Callable[[], GuardConfig] | None = None,
    additional_authority_provider: Callable[[], tuple[object | None, dict[str, object] | None]] | None = None,
) -> tuple[dict[str, object], int] | None:
    authority = _build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=config,
        additional_current_action=additional_current_action,
        additional_policy_context=additional_policy_context,
    )
    if authority is None:
        return None
    sanitized_intent = authority.intent
    artifact = authority.artifact
    evaluation = authority.evaluation
    current_evaluation = evaluation
    current_action = authority.current_action
    package_execution_context = authority.execution_context
    artifact_hash = authority.artifact_hash
    initial_policy_resolution = _resolve_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=package_execution_context,
        current_action=current_action,
        claim_saved_approval=False,
    )
    evaluation = initial_policy_resolution.evaluation
    effective_dry_run = dry_run and not (
        allow_saved_approval_execution and _evaluation_uses_saved_package_approval(evaluation)
    )
    execution_permitted = is_execution_permitted(evaluation.policy_action)
    payload: dict[str, object] = {
        "generated_at": now,
        "executed": False,
        "dry_run": dry_run,
    }
    projection = _apply_package_protect_projection(
        payload=payload,
        authority=authority,
        evaluation=evaluation,
        command=command,
        blocking=not execution_permitted,
        executed=False,
    )
    if config is not None:
        payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=now)
    if not execution_permitted or effective_dry_run:
        store.add_receipt(projection.receipt)
        store.set_receipt_action_envelope(
            projection.receipt.receipt_id,
            projection.receipt_policy_metadata,
        )
        store.add_event(
            f"install_time_{projection.verdict_action}",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "executor": str(command[0]) if command else _LOCAL_SUPPLY_CHAIN_HARNESS,
                "install_kind": sanitized_intent.intent_kind,
                "action": projection.verdict_action,
                "risk_signals": list(projection.risk_signals),
            },
            now,
        )
        return (payload, _package_execution_exit_code(evaluation.policy_action))
    saved_approval_claimed = _evaluation_uses_saved_package_approval(evaluation)
    saved_approval_claim_disposition: _PackageApprovalClaimDisposition | None = None
    if saved_approval_claimed:
        # Claim the one-shot first, then rebuild every current input. Mutations
        # performed while the store claim is in flight cannot inherit the old
        # authorization at the subsequent launch boundary.
        claimed_resolution = _resolve_stored_package_policy_override(
            current_evaluation,
            store=store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            workspace_dir=workspace_dir,
            now=now,
            execution_context=package_execution_context,
            current_action=current_action,
            claim_saved_approval=True,
        )
        claimed_evaluation = claimed_resolution.evaluation
        if not is_execution_permitted(claimed_evaluation.policy_action):
            return _package_protect_denied_after_final_boundary(
                payload=payload,
                authority=authority,
                evaluation=claimed_evaluation,
                command=command,
                store=store,
                now=now,
            )
        saved_approval_claim_disposition = claimed_resolution.claim_disposition
    final_authority, final_evaluation = _final_package_protect_authority(
        initial=authority,
        saved_approval_claimed=saved_approval_claimed,
        saved_approval_claim_disposition=saved_approval_claim_disposition,
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
        config=config,
        current_config_provider=current_config_provider,
        additional_authority_provider=additional_authority_provider,
    )
    if not is_execution_permitted(final_evaluation.policy_action):
        denied = _package_protect_denied_after_final_boundary(
            payload=payload,
            authority=final_authority,
            evaluation=final_evaluation,
            command=command,
            store=store,
            now=now,
        )
        _cleanup_external_archive_downloads(final_evaluation)
        return denied
    launch_command = resolved_runtime_launch_argv(
        final_authority.launch_identity,
        args=tuple(str(item) for item in command[1:]),
    )
    if launch_command is None or not runtime_launch_identity_is_reusable(final_authority.launch_identity):
        reuse = evaluate_approval_reuse(
            final_authority.current_action,
            "require-reapproval",
            saved_decision_present=True,
            validation_reason="approval_reuse_identity_changed",
        )
        denied_evaluation = _package_evaluation_with_rejected_reuse(final_authority.evaluation, reuse)
        denied = _package_protect_denied_after_final_boundary(
            payload=payload,
            authority=final_authority,
            evaluation=denied_evaluation,
            command=command,
            store=store,
            now=now,
        )
        _cleanup_external_archive_downloads(final_evaluation)
        return denied
    bound_launch_command = _bound_external_archive_launch_command(
        launch_command,
        evaluation=final_evaluation,
    )
    if bound_launch_command is None:
        denied_evaluation = _package_policy_override_evaluation(
            final_evaluation,
            decision="block",
            policy_action="block",
            title="External archive blocked",
            summary="The inspected external archive could not be bound to the installer launch.",
            harness_message="HOL Guard blocked an external archive whose digest-bound blob was unavailable.",
            reason_code="external_archive_digest_mismatch",
            reason_message="The inspected external archive changed or was not present in the installer command.",
        )
        denied = _package_protect_denied_after_final_boundary(
            payload=payload,
            authority=final_authority,
            evaluation=denied_evaluation,
            command=command,
            store=store,
            now=now,
        )
        _cleanup_external_archive_downloads(final_evaluation)
        return denied
    authority = final_authority
    sanitized_intent = authority.intent
    artifact = authority.artifact
    evaluation = final_evaluation
    final_projection = _apply_package_protect_projection(
        payload=payload,
        authority=authority,
        evaluation=evaluation,
        command=command,
        blocking=False,
        executed=True,
    )
    verdict_action = final_projection.verdict_action
    risk_signals = final_projection.risk_signals
    try:
        execution = subprocess.run(
            bound_launch_command,
            cwd=authority.launch_cwd,
            env=authority.launch_environment,
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
        _cleanup_external_archive_downloads(final_evaluation)
        return (payload, 1)
    payload["execution"] = _build_command_execution_payload(
        stdout=execution.stdout,
        stderr=execution.stderr,
        returncode=execution.returncode,
        unsafe_raw_output=unsafe_raw_output,
    )
    if execution.returncode == 0:
        store.add_receipt(final_projection.receipt)
        store.set_receipt_action_envelope(
            final_projection.receipt.receipt_id,
            final_projection.receipt_policy_metadata,
        )
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
    _cleanup_external_archive_downloads(final_evaluation)
    return (payload, int(execution.returncode))


def apply_stored_package_policy_override(
    evaluation: Any,
    *,
    store: Any,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    execution_context: PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> Any:
    """Apply a saved package approval when the content hash still matches."""

    return _apply_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=execution_context,
        current_action=current_action,
        claim_saved_approval=claim_saved_approval,
    )


def _apply_stored_package_policy_override(
    evaluation: Any,
    *,
    store: Any,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    execution_context: PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> Any:
    return _resolve_stored_package_policy_override(
        evaluation,
        store=store,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        now=now,
        execution_context=execution_context,
        current_action=current_action,
        claim_saved_approval=claim_saved_approval,
    ).evaluation


def _resolve_stored_package_policy_override(
    evaluation: Any,
    *,
    store: Any,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    now: str,
    execution_context: PackageExecutionContext | None = None,
    current_action: object | None = None,
    claim_saved_approval: bool = True,
) -> _StoredPackagePolicyResolution:
    effective_current_action = (
        evaluation.policy_action
        if current_action is None
        else most_restrictive_guard_action(evaluation.policy_action, current_action, unknown_action="block")
    )
    current_evaluation = _package_evaluation_with_current_policy_action(
        evaluation,
        current_action=effective_current_action,
    )
    resolved_execution_context = execution_context or build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    decision = None
    ignored_integrity = None
    policy_workspaces = _package_policy_workspace_candidates(
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace_dir=workspace_dir,
        execution_context=resolved_execution_context,
    )
    for policy_workspace in policy_workspaces:
        lookup = store.resolve_policy_decision_lookup(
            artifact.harness,
            artifact.artifact_id,
            artifact_hash,
            policy_workspace,
            artifact.publisher,
            now,
            consume_one_shot=False,
        )
        decision = lookup["decision"]
        ignored_integrity = lookup["ignored_local_integrity"]
        if isinstance(decision, dict):
            break
        if ignored_integrity is not None:
            break
    diagnosed_reason: ApprovalReuseValidationFailure | None = None
    if not isinstance(decision, dict) and ignored_integrity is None:
        for policy_workspace in policy_workspaces:
            raw_diagnosed_reason = store.approval_reuse_validation_reason(
                artifact.harness,
                artifact.artifact_id,
                artifact_hash,
                policy_workspace,
                artifact.publisher,
                now,
            )
            if raw_diagnosed_reason is not None:
                diagnosed_reason = cast(ApprovalReuseValidationFailure, raw_diagnosed_reason)
                break
        if diagnosed_reason is None:
            return _StoredPackagePolicyResolution(current_evaluation)
    if isinstance(decision, dict) and _stored_package_policy_is_stale_policy_bundle_family(decision, store=store):
        return _StoredPackagePolicyResolution(current_evaluation)
    action = (
        decision.get("action")
        if isinstance(decision, dict)
        else ("require-reapproval" if ignored_integrity is not None else "allow")
    )
    validation_reason: ApprovalReuseValidationFailure | None = (
        "approval_reuse_integrity_failure"
        if ignored_integrity is not None
        else (
            cast(
                ApprovalReuseValidationFailure,
                package_saved_allow_validation_reason(decision, artifact_hash=artifact_hash),
            )
            if isinstance(decision, dict)
            else diagnosed_reason
        )
    )
    reuse = evaluate_approval_reuse(
        effective_current_action,
        action,
        saved_decision_present=True,
        validation_reason=validation_reason,
    )
    claim_disposition: _PackageApprovalClaimDisposition | None = None
    disposition_resolver = getattr(store, "approval_reuse_claim_disposition", None)
    if isinstance(decision, dict) and callable(disposition_resolver):
        raw_disposition = disposition_resolver(decision)
        if raw_disposition in {"consumed", "retained"}:
            claim_disposition = cast(_PackageApprovalClaimDisposition, raw_disposition)
    if (
        claim_saved_approval
        and reuse.should_claim
        and isinstance(decision, dict)
        and not store.claim_approval_reuse_decision(decision, now=now)
    ):
        reuse = evaluate_approval_reuse(
            effective_current_action,
            action,
            saved_decision_present=True,
            validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
        )
    if reuse.accepted and reuse.saved_action == "allow":
        if not isinstance(decision, dict) or decision.get("action") != "allow":
            failed_reuse = evaluate_approval_reuse(
                most_restrictive_guard_action(
                    effective_current_action,
                    "require-reapproval",
                    unknown_action="block",
                ),
                "allow",
                saved_decision_present=True,
                validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
            )
            return _StoredPackagePolicyResolution(
                _package_evaluation_with_rejected_reuse(current_evaluation, failed_reuse)
            )
        return _StoredPackagePolicyResolution(
            _package_policy_override_evaluation(
                current_evaluation,
                decision="allow",
                policy_action="allow",
                title="Allowed by saved approval",
                summary="HOL Guard reused your saved approval for this package request.",
                harness_message=(
                    "HOL Guard verified the same repository, package manager, dependency files, settings, and "
                    "registry environment before reusing your saved approval."
                ),
                reason_code="saved_package_approval",
                reason_message="HOL Guard reused your saved approval for this package request.",
                approval_reuse=reuse,
            ),
            approval_reuse_decision=decision,
            claim_disposition=claim_disposition,
        )
    if reuse.saved_action == "block":
        assert isinstance(decision, dict)
        clear_command = _saved_package_policy_clear_command(
            artifact=artifact,
            artifact_hash=artifact_hash,
            matched_policy=decision,
            workspace_dir=workspace_dir,
        )
        return _StoredPackagePolicyResolution(
            _package_policy_override_evaluation(
                current_evaluation,
                decision="block",
                policy_action="block",
                title="Blocked by saved policy",
                summary="HOL Guard kept this package blocked because a saved package policy already exists.",
                harness_message=(
                    "HOL Guard kept this package blocked because a saved package policy already exists. "
                    f"To reconsider, run `{clear_command}`, then retry the install."
                ),
                next_step=clear_command,
                reason_code="saved_package_block",
                reason_message="HOL Guard kept this package blocked because a saved package policy already exists.",
                approval_reuse=reuse,
            )
        )
    return _StoredPackagePolicyResolution(_package_evaluation_with_rejected_reuse(current_evaluation, reuse))


def package_saved_allow_validation_reason(
    decision: dict[str, object],
    *,
    artifact_hash: str,
) -> str | None:
    """Validate that local saved package ``allow`` evidence is exact.

    Broad policy scopes are matches for lookup only, not proof that this exact
    package request was previously reviewed. Every stored ``allow``—regardless
    of scope or source—must bind the current package/context digest before it
    can satisfy review.
    """

    if decision.get("action") != "allow":
        return None
    # A matching legacy digest is still missing workspace, executable,
    # capability, policy, and sandbox bindings. Require two valid v1 tokens.
    return approval_context_tokens_validation_reason(decision.get("artifact_hash"), artifact_hash)


def _package_evaluation_with_current_policy_action(
    evaluation: Any,
    *,
    current_action: GuardAction,
) -> Any:
    """Apply current package policy before consulting remembered user state."""

    if current_action == evaluation.policy_action:
        return evaluation
    decision = _package_decision_for_action(current_action)
    rewritten_packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    action_label = {
        "block": "blocks",
        "sandbox-required": "requires sandbox enforcement for",
        "require-reapproval": "requires fresh approval for",
        "review": "requires review for",
        "warn": "warns about",
        "allow": "allows",
    }[current_action]
    package_label = "this package request"
    package_label_entries = getattr(evaluation, "packages", ())
    if (
        isinstance(package_label_entries, tuple)
        and package_label_entries
        and isinstance(package_label_entries[0], dict)
    ):
        primary_package = package_label_entries[0]
        package_name = primary_package.get("name")
        package_version = primary_package.get("requestedVersion") or primary_package.get("resolvedVersion")
        if isinstance(package_name, str) and package_name:
            package_ref = (
                f"{package_name}@{package_version}"
                if isinstance(package_version, str) and package_version
                else package_name
            )
            package_label = f"`{package_ref}`"
    summary = f"HOL Guard's current package policy {action_label} {package_label}."
    reason = {
        "code": "current_package_policy",
        "message": summary,
        "severity": "high" if current_action in {"block", "sandbox-required"} else "medium",
        "source": "guard-local",
        "policy_action": current_action,
    }
    needs_review = current_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return replace(
        evaluation,
        decision=decision,
        policy_action=current_action,
        reasons=(reason, *tuple(item for item in evaluation.reasons if item.get("code") != reason["code"])),
        packages=rewritten_packages,
        risk_summary=summary,
        user_copy=_supply_chain_package_eval_module().SupplyChainUserCopy(
            title="Current package policy",
            summary=summary,
            next_step="Review the current package request in HOL Guard, then retry." if needs_review else None,
            dashboard_url=None,
            harness_message=summary,
        ),
        record_monitor_evidence=False,
    )


def _package_evaluation_with_rejected_reuse(
    evaluation: Any,
    reuse: ApprovalReuseDecision,
) -> Any:
    """Retain current package evidence while recording rejected saved state."""

    reason = {
        "code": reuse.reason_code,
        "message": _approval_reuse_reason_message(reuse),
        "severity": "high" if reuse.status == "rejected" else "low",
        "source": "guard-local",
        "approval_reuse": reuse.to_evidence(),
    }
    reasons = (reason, *tuple(item for item in evaluation.reasons if item.get("code") != reuse.reason_code))
    if reuse.action == evaluation.policy_action:
        return replace(evaluation, reasons=reasons)
    decision = _package_decision_for_action(reuse.action)
    packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    summary = _approval_reuse_reason_message(reuse)
    return replace(
        evaluation,
        decision=decision,
        policy_action=reuse.action,
        reasons=reasons,
        packages=packages,
        risk_summary=summary,
        user_copy=_supply_chain_package_eval_module().SupplyChainUserCopy(
            title="Saved approval not reusable",
            summary=summary,
            next_step="Review the current package request in HOL Guard, then retry.",
            dashboard_url=None,
            harness_message=summary,
        ),
        record_monitor_evidence=False,
    )


def _approval_reuse_reason_message(reuse: ApprovalReuseDecision) -> str:
    messages = {
        "approval_reuse_current_block": (
            "Saved approval was rejected because current package policy blocks this request."
        ),
        "approval_reuse_sandbox_required": (
            "Saved approval was rejected because current package policy requires sandbox enforcement."
        ),
        "approval_reuse_reapproval_required": (
            "Saved approval was rejected because current package policy requires fresh approval."
        ),
        "approval_reuse_integrity_failure": (
            "Saved approval was rejected because its integrity could not be verified."
        ),
        "approval_reuse_identity_changed": (
            "Saved approval was rejected because the current package identity or scope changed."
        ),
        "approval_reuse_content_changed": (
            "Saved approval was rejected because the current package content or execution context changed."
        ),
        "approval_reuse_claim_failed": (
            "Saved approval was rejected because it changed, expired, or was already consumed."
        ),
        "approval_reuse_context_changed_after_claim": (
            "Saved approval was rejected because retained authority changed after it was claimed."
        ),
        "approval_reuse_saved_action_unknown": (
            "Saved approval was rejected because its action is unknown or malformed."
        ),
    }
    return messages.get(
        reuse.reason_code,
        f"Saved package policy was not reused ({reuse.reason_code}).",
    )


def _package_decision_for_action(action: GuardAction) -> str:
    if action == "block":
        return "block"
    if action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if action == "warn":
        return "warn"
    return "allow"


def _package_policy_workspace_candidates(
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace_dir: Path,
    execution_context: PackageExecutionContext | None = None,
) -> tuple[str, ...]:
    resolved_execution_context = execution_context or build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    runtime_workspace = package_request_runtime_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        artifact_type=artifact.artifact_type,
        execution_context=resolved_execution_context,
    )
    return (runtime_workspace,) if runtime_workspace is not None else ()


def _stored_package_policy_is_stale_policy_bundle_family(decision: dict[str, object], *, store: Any) -> bool:
    """Ignore package family rows only when the current bundle proves they are stale."""

    if not (
        _string_value(decision.get("source")) == "policy-bundle"
        and _string_value(decision.get("artifact_id")) == "family:package-request"
        and decision.get("artifact_hash") is None
        and _string_value(decision.get("scope")) in {"harness", "global"}
    ):
        return False
    owner = _string_value(decision.get("owner"))
    if owner is None:
        return False
    get_sync_payload = getattr(store, "get_sync_payload", None)
    if not callable(get_sync_payload):
        return False
    from .synced_policy import validated_synced_policy_bundle

    bundle = validated_synced_policy_bundle(store)
    if bundle is None:
        return False
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        return False
    matching_rules = [rule for rule in rules if isinstance(rule, dict) and _string_value(rule.get("ruleId")) == owner]
    if not matching_rules:
        return True
    from .policy_bundle_decisions import policy_bundle_rule_saved_decision_families

    return not any("package-request" in policy_bundle_rule_saved_decision_families(rule) for rule in matching_rules)


def _stored_package_policy_evaluation_requires_review(evaluation: Any) -> bool:
    policy_action = _string_value(getattr(evaluation, "policy_action", None))
    decision = _string_value(getattr(evaluation, "decision", None))
    return policy_action in {"block", "require-reapproval"} or decision in {"block", "ask"}


def _saved_package_policy_clear_command(
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
    matched_policy: dict[str, object],
    workspace_dir: Path,
) -> str:
    scope = _string_value(matched_policy.get("scope")) or "artifact"
    command = [
        "hol-guard",
        "policies",
        "clear",
    ]
    decision_id = matched_policy.get("decision_id")
    if isinstance(decision_id, int):
        command.extend(("--decision-id", str(decision_id)))
    command.extend(("--harness", _string_value(matched_policy.get("harness")) or artifact.harness, "--scope", scope))
    artifact_id = _string_value(matched_policy.get("artifact_id"))
    if artifact_id is None and scope in {"artifact", "workspace", "harness", "global"}:
        artifact_id = artifact.artifact_id
    if artifact_id is not None:
        command.extend(("--artifact-id", artifact_id))
    matched_hash = _string_value(matched_policy.get("artifact_hash"))
    if matched_hash is not None:
        command.extend(("--artifact-hash", matched_hash))
    policy_workspace = _string_value(matched_policy.get("workspace"))
    if policy_workspace is None and scope in {"artifact", "workspace"}:
        policy_workspace = str(workspace_dir)
    if policy_workspace is not None:
        command.extend(("--policy-workspace", policy_workspace))
    publisher = _string_value(matched_policy.get("publisher"))
    if publisher is not None:
        command.extend(("--publisher", publisher))
    return shlex.join(command)


def recompute_package_protect_artifact_hash(
    command: Sequence[str],
    *,
    store: Any,
    workspace_dir: Path,
    now: str | None = None,
    config: GuardConfig | None = None,
) -> str | None:
    evaluation_timestamp = now or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    authority = _build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=evaluation_timestamp,
        config=config,
        additional_current_action=None,
        additional_policy_context=None,
    )
    return authority.artifact_hash if authority is not None else None


def _package_target_identities(artifact: GuardArtifact) -> tuple[ProtectTargetIdentity, ...]:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    targets = metadata.get("targets")
    if not isinstance(targets, list):
        return ()
    identities: list[ProtectTargetIdentity] = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "")
        package_name = item.get("package_name") if isinstance(item.get("package_name"), str) else None
        raw_spec = str(item.get("raw_spec") or package_name or "")
        version = item.get("requested_specifier") if isinstance(item.get("requested_specifier"), str) else None
        source_url = item.get("source_url") if isinstance(item.get("source_url"), str) else None
        artifact_id = f"{ecosystem}:{package_name or raw_spec}"
        artifact_name = package_name or raw_spec
        identities.append(
            ProtectTargetIdentity(
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                ecosystem=ecosystem,
                package_name=package_name,
                package_url=build_package_url(ecosystem, package_name, version),
                source_url=source_url,
            )
        )
    return tuple(identities)


def _package_matched_cached_advisory_ids(store: Any, artifact: GuardArtifact) -> tuple[str, ...]:
    advisories = store.list_cached_advisories(limit=None)
    identities = _package_target_identities(artifact)
    matched_ids: set[str] = set()
    for advisory in advisories:
        for identity in identities:
            if advisory_matches_target(advisory, identity):
                advisory_id = advisory.get("id")
                if isinstance(advisory_id, str) and advisory_id:
                    matched_ids.add(advisory_id)
                break
    return tuple(sorted(matched_ids))


def _package_feed_snapshot_hash(store: Any) -> str | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached_bundle, dict):
        return None
    bundle = cached_bundle.get("bundle")
    if not isinstance(bundle, dict):
        return None
    value = bundle.get("feedSnapshotHash")
    return value if isinstance(value, str) and value else None


def _package_policy_gate_context(
    store: Any,
    artifact: GuardArtifact,
    evaluation: Any,
) -> dict[str, object]:
    return {
        "bundle_version": evaluation.bundle_version,
        "decision": evaluation.decision,
        "enforcement": evaluation.enforcement,
        "entitlement_state": evaluation.entitlement_state,
        "exception_id": evaluation.exception_id,
        "feed_snapshot_hash": _package_feed_snapshot_hash(store),
        "matched_advisory_ids": list(_package_matched_cached_advisory_ids(store, artifact)),
        "matched_rule_id": evaluation.matched_rule_id,
        "packages": list(evaluation.packages),
        "policy_action": evaluation.policy_action,
        "policy_version": evaluation.policy_version,
        "reasons": list(evaluation.reasons),
    }


def _package_config_policy_context(
    *,
    artifact: GuardArtifact,
    config: GuardConfig | None,
) -> dict[str, object]:
    if config is None:
        return {"available": False}
    harness_package_script_action = (config.harness_risk_actions or {}).get(artifact.harness, {}).get("package_script")
    artifact_override = (config.artifact_actions or {}).get(artifact.artifact_id)
    publisher_override = (
        (config.publisher_actions or {}).get(artifact.publisher) if artifact.publisher is not None else None
    )
    harness_override = (config.harness_actions or {}).get(artifact.harness)
    return {
        "artifact_override": artifact_override,
        "available": True,
        "effective_package_script_action": resolve_risk_action(
            config,
            "package_script",
            harness=artifact.harness,
        ),
        "global_package_script_action": resolve_risk_action(config, "package_script", harness=None),
        "harness": artifact.harness,
        "harness_override": harness_override,
        "harness_package_script_action": harness_package_script_action,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "publisher_override": publisher_override,
        "resolved_override": config.resolve_action_override(
            artifact.harness,
            artifact.artifact_id,
            artifact.publisher,
        ),
        "security_level": config.security_level,
    }


def compose_current_package_policy_action(
    *,
    artifact: GuardArtifact,
    evaluation: Any,
    config: GuardConfig | None,
    additional_current_action: object | None = None,
) -> GuardAction:
    """Compose feed and effective Guard configuration before approval reuse."""

    actions: list[object] = [evaluation.policy_action]
    if additional_current_action is not None:
        actions.append(additional_current_action)
    if config is not None:
        config_policy = _package_config_policy_context(artifact=artifact, config=config)
        # Resolve specificity inside each configuration family first.  A
        # harness risk action replaces its global risk action, and an exact
        # artifact/publisher/harness action is one precedence chain.  The
        # resulting configuration actions remain independent of the package
        # feed/evaluator action and therefore cannot erase a feed block.
        for key in ("effective_package_script_action", "resolved_override"):
            action = config_policy.get(key)
            if action is not None:
                actions.append(action)
    return most_restrictive_guard_action(*actions, unknown_action="block")


def _package_current_policy_context(
    *,
    artifact: GuardArtifact,
    store: Any,
    evaluation: Any,
    config: GuardConfig | None,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "configuration": _package_config_policy_context(artifact=artifact, config=config),
        "current_action": compose_current_package_policy_action(
            artifact=artifact,
            evaluation=evaluation,
            config=config,
            additional_current_action=additional_current_action,
        ),
        "additional": additional_policy_context if additional_policy_context is not None else {"available": False},
        "feed": _package_policy_gate_context(store, artifact, evaluation),
        "version": 1,
    }


def _package_request_artifact_hash(
    artifact: GuardArtifact,
    *,
    workspace_dir: Path,
    store: Any,
    evaluation: Any,
    execution_context: PackageExecutionContext | None = None,
    launch_identity: Mapping[str, object] | None = None,
    config: GuardConfig | None = None,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
) -> str:
    policy_context = _package_current_policy_context(
        artifact=artifact,
        store=store,
        evaluation=evaluation,
        config=config,
        additional_current_action=additional_current_action,
        additional_policy_context=additional_policy_context,
    )
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    resolved_execution_context = execution_context or build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    approval_identity = _package_approval_identity(
        artifact=artifact,
        evaluation=evaluation,
        execution_context=resolved_execution_context,
    )
    manifest_paths = _string_items(metadata.get("manifest_paths"))
    lockfile_paths = _string_items(metadata.get("lockfile_paths"))
    content_material: dict[str, object] = {}
    if manifest_paths or lockfile_paths:
        content_material.update(
            {
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "manifest_hashes": _hash_existing_paths(workspace_dir, manifest_paths),
                "lockfile_hashes": _hash_existing_paths(workspace_dir, lockfile_paths),
            }
        )
    component_digests = {component.name: component.digest for component in resolved_execution_context.components}
    return build_approval_context_token(
        identity={
            "approval_identity": approval_identity,
            "artifact_id": artifact.artifact_id,
            "config_path": artifact.config_path,
            "exact_workspace": component_digests.get("exact_workspace"),
            "package_manager_executable": component_digests.get("package_manager_executable"),
            "package_launch_identity": _package_launch_approval_identity(launch_identity),
            "publisher": artifact.publisher,
            "repository_identity": component_digests.get("repository_identity"),
            "source_scope": artifact.source_scope,
            "workspace_identity": component_digests.get("workspace_identity"),
        },
        content={
            **content_material,
            "lockfile_parser_version": LOCKFILE_PARSER_VERSION,
            "manifests_and_lockfiles": component_digests.get("manifests_and_lockfiles"),
            "workspace_configuration": component_digests.get("workspace_configuration"),
        },
        capabilities={
            "environment_policy": component_digests.get("environment_policy"),
            "lifecycle_hooks_overrides_and_patches": component_digests.get("lifecycle_hooks_overrides_and_patches"),
            "registry_and_proxy_configuration": component_digests.get("registry_and_proxy_configuration"),
        },
        policy=policy_context,
        sandbox={
            "analysis": config.sandbox_analysis if config is not None else "unknown",
            "required": policy_context["current_action"] == "sandbox-required",
        },
    )


def _package_launch_approval_identity(launch_identity: Mapping[str, object] | None) -> dict[str, object]:
    """Bind the raw launch vector without duplicating non-portable paths.

    The package execution context already contains the normalized manager,
    shebang interpreter, code-loading, and cwd identity. This additional
    material binds the exact argv shape and forces wrapper launches to remain
    one-attempt-only without breaking linked-worktree portability.
    """

    if launch_identity is None:
        return {"available": False}
    wrapper_resolution = launch_identity.get("wrapper_resolution")
    return {
        "argv_sha256": launch_identity.get("argv_sha256"),
        "wrapper_resolution": (wrapper_resolution if isinstance(wrapper_resolution, Mapping) else {"status": "direct"}),
    }


def _package_approval_identity(
    *,
    artifact: GuardArtifact,
    evaluation: Any,
    execution_context: PackageExecutionContext,
) -> dict[str, object]:
    """Return the complete, secret-free preimage for a package approval."""

    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    raw_targets = metadata.get("targets")
    targets = (
        [
            {
                "alias": _string_value(target.get("alias")),
                "ecosystem": _string_value(target.get("ecosystem")),
                "package_name": _string_value(target.get("package_name")),
                "raw_spec": _string_value(target.get("raw_spec")),
                "raw_spec_hash": _string_value(target.get("raw_spec_hash")),
                "requested_specifier": _string_value(target.get("requested_specifier")),
                "source_url_hash": _string_value(target.get("source_url_hash"))
                or (
                    stable_digest_hex(source_url.encode("utf-8"))
                    if (source_url := _string_value(target.get("source_url"))) is not None
                    else None
                ),
            }
            for target in raw_targets
            if isinstance(target, dict)
        ]
        if isinstance(raw_targets, list)
        else []
    )
    raw_packages = getattr(evaluation, "packages", ())
    packages = (
        [
            {
                "dependency_path": _string_value(package.get("dependencyPath")),
                "ecosystem": _string_value(package.get("ecosystem")),
                "name": _string_value(package.get("name")),
                "namespace": _string_value(package.get("namespace")),
                "package_manager": _string_value(package.get("packageManager")),
                "requested_version": _string_value(package.get("requestedVersion")),
                "resolved_version": _string_value(package.get("resolvedVersion")),
            }
            for package in raw_packages
            if isinstance(package, dict)
        ]
        if isinstance(raw_packages, (tuple, list))
        else []
    )
    return {
        "context_digest": execution_context.digest,
        "context_version": execution_context.version,
        "manager": _string_value(metadata.get("package_manager")),
        "packages": packages,
        "targets": targets,
        "version": 1,
    }


def package_request_policy_hash(
    *,
    artifact: GuardArtifact,
    store: Any,
    workspace_dir: Path,
    evaluation: Any,
    execution_context: PackageExecutionContext | None = None,
    config: GuardConfig | None = None,
) -> str:
    """Hash a package request using manifest and lockfile contents."""

    return _package_request_artifact_hash(
        artifact,
        workspace_dir=workspace_dir,
        store=store,
        evaluation=evaluation,
        execution_context=execution_context,
        config=config,
    )


def _evaluation_uses_saved_package_approval(evaluation: Any) -> bool:
    return any(reason.get("code") == "saved_package_approval" for reason in evaluation.reasons)


def _package_approval_reuse_evidence(evaluation: Any) -> tuple[dict[str, object], ...]:
    evidence_items: list[dict[str, object]] = []
    for reason in evaluation.reasons:
        reuse_evidence = reason.get("approval_reuse")
        if not isinstance(reuse_evidence, dict):
            continue
        evidence: dict[str, object] = {"source": "approval_reuse"}
        evidence.update({str(key): value for key, value in reuse_evidence.items()})
        evidence_items.append(evidence)
    return tuple(evidence_items)


def _package_policy_override_evaluation(
    evaluation: Any,
    *,
    decision: str,
    policy_action: str,
    title: str,
    summary: str,
    harness_message: str,
    next_step: str | None = None,
    reason_code: str,
    reason_message: str,
    approval_reuse: ApprovalReuseDecision | None = None,
) -> Any:
    reason: dict[str, object] = {
        "code": reason_code,
        "message": reason_message,
        "severity": "low",
        "source": "guard-local",
    }
    if approval_reuse is not None:
        reason["approval_reuse"] = approval_reuse.to_evidence()
    packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    return replace(
        evaluation,
        decision=decision,
        policy_action=policy_action,
        reasons=(reason, *tuple(item for item in evaluation.reasons if item != reason)),
        packages=packages,
        risk_summary=harness_message,
        user_copy=_supply_chain_package_eval_module().SupplyChainUserCopy(
            title=title,
            summary=summary,
            next_step=next_step,
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


def _build_package_manager_protection(store: Any) -> dict[str, object]:
    context = HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
    status = package_shim_status(context)
    shim_dir = Path(str(status.get("shim_dir") or store.guard_home / "package-shims" / "bin"))
    installed_managers = sorted(set(_string_items(status.get("installed_managers"))))
    active_managers = sorted(set(_string_items(status.get("active_managers"))))
    missing_shims = sorted(set(_string_items(status.get("missing_managers"))))
    supported_managers = list(package_shim_supported_managers())
    protected_managers = sorted(set(_string_items(status.get("protected_managers"))))
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


def _discover_workspace_audit_paths(workspace_dir: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    workspace_root = workspace_dir.expanduser().resolve()
    manifests: list[str] = []
    lockfiles: list[str] = []
    for dirpath, dirnames, filenames in os.walk(workspace_root, topdown=True):
        current = Path(dirpath)
        try:
            depth = len(current.relative_to(workspace_root).parts)
        except ValueError:
            continue
        if depth >= _WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = [name for name in dirnames if name not in _WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS]
        for filename in filenames:
            relative = (current / filename).relative_to(workspace_root).as_posix()
            if filename in _MANIFEST_CANDIDATE_SET and relative not in manifests:
                manifests.append(relative)
            elif filename in _LOCKFILE_CANDIDATE_SET and relative not in lockfiles:
                lockfiles.append(relative)
    return tuple(manifests), tuple(lockfiles)


def _workspace_files(workspace_dir: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    discovered = _discover_workspace_audit_paths(workspace_dir)
    if discovered[0] or discovered[1]:
        return discovered
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
    summary: dict[str, object] = {
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
    store: Any,
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
    runner = _runtime_runner_module()

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
    aggregated_packages: list[dict[str, object]] = []
    aggregated_processed_count = 0
    aggregated_reasons: list[dict[str, object]] = []
    aggregated_total_packages = 0
    cursor: str | None = None
    last_response: dict[str, object] | None = None
    for _ in range(_CLOUD_AUDIT_MAX_PAGES):
        page_payload = dict(request_payload)
        if cursor is not None:
            page_payload["cursor"] = cursor
        request_headers = (
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            if resolved_auth_context is None
            else runner._guard_sync_headers(resolved_auth_context, request_url=request_url, method="POST")
        )
        request = urllib.request.Request(
            request_url,
            data=json.dumps(page_payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        try:
            with managed_urlopen(request, timeout=_CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
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
        page_processed_count = _int_value(response_payload.get("processedCount"))
        page_total_packages = _int_value(response_payload.get("totalPackages"))
        if page_total_packages is not None:
            aggregated_total_packages = max(aggregated_total_packages, page_total_packages)
        if page_processed_count is not None:
            aggregated_processed_count += page_processed_count
        elif isinstance(response_packages, list):
            aggregated_processed_count += len(response_packages)
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
    merged_response["processedCount"] = aggregated_processed_count
    merged_response["totalPackages"] = max(aggregated_total_packages, len(aggregated_packages))
    merged_response["reasons"] = aggregated_reasons
    return (merged_response, None)


def _codebase_label_from_remote(remote: str) -> str | None:
    normalized_remote = remote.strip().rstrip("/")
    if not normalized_remote:
        return None
    if "://" in normalized_remote:
        parsed = urllib.parse.urlparse(normalized_remote)
        path = parsed.path.lstrip("/")
    elif ":" in normalized_remote:
        path = normalized_remote.split(":", 1)[1]
    else:
        path = normalized_remote
    label = path.strip("/")
    if not label:
        return None
    return label[:-4] if label.endswith(".git") else label


def _read_git_origin_codebase(workspace_dir: Path) -> str | None:
    config_path = workspace_dir / ".git" / "config"
    try:
        config_text = config_path.read_text(encoding="utf-8")
    except OSError:
        return None
    in_origin = False
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_origin = line == '[remote "origin"]'
            continue
        if not in_origin or not line.startswith("url") or "=" not in line:
            continue
        _key, _sep, value = line.partition("=")
        return _codebase_label_from_remote(value)
    return None


def _safe_machine_name() -> str | None:
    try:
        machine = socket.gethostname().strip()
    except OSError:
        return None
    return machine or None


def _redacted_workspace_folder_path(workspace_dir: Path) -> str:
    raw_path = str(workspace_dir)
    redacted = redact_local_path(raw_path)
    if redacted != raw_path or not workspace_dir.is_absolute():
        return redacted
    parts = [part for part in workspace_dir.parts if part not in {"", "/"}]
    if len(parts) >= 2:
        return f"…/{parts[-2]}/{parts[-1]}"
    return f"…/{workspace_dir.name}"


def _build_workspace_context_payload(
    workspace_dir: Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
) -> dict[str, object]:
    codebase = _read_git_origin_codebase(workspace_dir) or workspace_dir.name
    return {
        "agent": _LOCAL_SUPPLY_CHAIN_HARNESS,
        "codebase": codebase,
        "folderPath": _redacted_workspace_folder_path(workspace_dir),
        "lockfilePaths": list(lockfile_paths),
        "machine": _safe_machine_name(),
        "manifestPaths": list(manifest_paths),
        "packageManager": _package_manager_for_scan(manifest_paths),
        "workspaceName": workspace_dir.name,
    }


def _build_cloud_audit_payload(
    *,
    workspace_dir: Path,
    workspace_id: str,
    store: Any,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    inventory: tuple[dict[str, object], ...],
    mode: str = "paged",
    page_size: int | None = None,
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
        "mode": mode,
        "pageSize": min(_CLOUD_AUDIT_PAGE_SIZE, max(page_size or len(inventory), 1)),
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
        "workspaceContext": _build_workspace_context_payload(
            workspace_dir,
            manifest_paths,
            lockfile_paths,
        ),
        "workspaceFingerprint": workspace_fingerprint,
    }
    if payload["lockfileContext"] is None:
        payload.pop("lockfileContext")
    return payload


def _execute_cloud_workspace_audit_request(
    *,
    auth_context: dict[str, object],
    request_url: str,
    method: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    runner = _runtime_runner_module()
    request_headers = runner._guard_sync_headers(auth_context, request_url=request_url, method=method)
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        request_url,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers=request_headers,
        method=method,
    )
    try:
        with managed_urlopen(request, timeout=_CLOUD_AUDIT_TIMEOUT_SECONDS) as response:
            response_payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 403:
            is_plan_restricted, message = runner._check_plan_restriction_403(error)
            if is_plan_restricted:
                raise runner.GuardSyncNotAvailableError(message) from error
            raise RuntimeError(message) from error
        message, retryable = runner._guard_cloud_http_error_details(error)
        if retryable:
            raise runner.GuardSyncNotAvailableError(message, retryable=True) from error
        raise RuntimeError(message) from error
    except OSError as error:
        raise RuntimeError(runner._sync_url_error_message(error)) from error
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("Guard cloud workspace audit returned an invalid response.") from error
    if not isinstance(response_payload, dict):
        raise RuntimeError("Guard cloud workspace audit returned an invalid response.")
    return response_payload


def _normalized_supply_chain_batch_job_url(
    sync_url: str,
    workspace_id: str,
    job_id: str,
    *,
    page_size: int,
) -> str:
    batch_url = _normalized_supply_chain_batch_url(sync_url, workspace_id)
    parsed = urllib.parse.urlsplit(batch_url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs = [(key, value) for key, value in query_pairs if key not in {"cursor", "pageSize"}]
    query_pairs.append(("pageSize", str(max(page_size, 1))))
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"{parsed.path.rstrip('/')}/{urllib.parse.quote(job_id, safe='')}",
            urllib.parse.urlencode(query_pairs),
            "",
        )
    )


def _enqueue_cloud_workspace_audit_job(
    *,
    auth_context: dict[str, object],
    request_payload: dict[str, object],
    workspace_id: str,
) -> dict[str, object]:
    sync_url = str(auth_context["sync_url"])
    request_url = _normalized_supply_chain_batch_url(sync_url, workspace_id)
    response_payload = _execute_cloud_workspace_audit_request(
        auth_context=auth_context,
        request_url=request_url,
        method="POST",
        payload=request_payload,
    )
    job_id = response_payload.get("jobId")
    if not isinstance(job_id, str) or not job_id.strip():
        raise RuntimeError("Guard cloud workspace audit did not return a batch job id.")
    return response_payload


def _poll_cloud_workspace_audit_job(
    *,
    auth_context: dict[str, object],
    job_id: str,
    workspace_id: str,
) -> dict[str, object]:
    sync_url = str(auth_context["sync_url"])
    request_url = _normalized_supply_chain_batch_job_url(
        sync_url,
        workspace_id,
        job_id,
        page_size=_CLOUD_AUDIT_JOB_PAGE_SIZE,
    )
    deadline = time.monotonic() + _CLOUD_AUDIT_JOB_POLL_TIMEOUT_SECONDS
    last_response: dict[str, object] = {
        "jobId": job_id,
        "status": "queued",
        "workspaceId": workspace_id,
    }
    while time.monotonic() < deadline:
        response_payload = _execute_cloud_workspace_audit_request(
            auth_context=auth_context,
            request_url=request_url,
            method="GET",
        )
        status = str(response_payload.get("status") or "").strip().lower()
        last_response = response_payload
        if status in {"completed", "failed"}:
            return response_payload
        time.sleep(_CLOUD_AUDIT_JOB_POLL_INTERVAL_SECONDS)
    return last_response


def _workspace_audit_lockfile_context(
    workspace_dir: Path,
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    inventory: tuple[dict[str, object], ...],
) -> dict[str, object] | None:
    if not lockfile_paths:
        return None
    lockfile_path = resolve_path_within_workspace(workspace_dir, lockfile_paths[0])
    if lockfile_path is None or not lockfile_path.exists():
        return None
    lockfile_text = _read_workspace_audit_text(workspace_dir, lockfile_paths[0])
    if lockfile_text is None:
        return None
    manifest_hash = None
    if manifest_paths:
        manifest_bytes = read_bytes_within_workspace(workspace_dir, manifest_paths[0])
        if manifest_bytes is not None and not _is_audit_sensitive_basename(Path(manifest_paths[0]).name):
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
        payload = read_bytes_within_workspace(workspace_dir, relative_path)
        if payload is None:
            continue
        hashes.append(stable_digest_hex(payload))
    return hashes


def _normalize_cloud_audit_response(response: dict[str, object]) -> dict[str, object]:
    return {
        "decision": str(response.get("decision") or "monitor"),
        "packages": list(_dict_items(response.get("packages"))),
        "reasons": list(_dict_items(response.get("reasons"))),
        "enforcement": str(response.get("enforcement") or "premium_cloud"),
        "entitlement_state": str(response.get("entitlementState") or "premium"),
        "cache_status": str(response.get("cacheStatus") or "miss"),
        "processed_count": _int_value(response.get("processedCount")) or 0,
        "total_packages": _int_value(response.get("totalPackages")) or 0,
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
    sync_path = parsed.path.rstrip("/")
    if sync_path.endswith("/receipts/sync"):
        next_path = sync_path[: -len("/receipts/sync")] + "/supply-chain/evaluate/batch"
    else:
        next_path = sync_path + "/supply-chain/evaluate/batch"
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


def sync_managed_workspace_audits(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    runner = _runtime_runner_module()
    resolved_auth_context = auth_context if auth_context is not None else runner._resolve_guard_sync_auth_context(store)
    workspace_id = store.get_cloud_workspace_id()
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        raise runner.GuardSyncNotConfiguredError(
            "Guard Cloud is not connected yet. Run `hol-guard connect` to sign in and pair this machine, "
            "or use `hol-guard login` as a compatibility alias for the same browser flow."
        )
    synced_at = datetime.now(timezone.utc).isoformat()
    workspaces_payload: list[dict[str, object]] = []
    completed_jobs = 0
    failed_jobs = 0
    incomplete_jobs = 0
    queued_jobs = 0
    skipped_workspaces = 0
    for candidate in _managed_workspace_audit_candidates(store, workspace_dir=workspace_dir):
        workspace_label = candidate.name or str(candidate)
        try:
            manifest_paths, lockfile_paths, _sbom_paths, inventory = _workspace_audit_inventory(
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
            request_payload = _build_cloud_audit_payload(
                workspace_dir=candidate,
                workspace_id=workspace_id,
                store=store,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                inventory=inventory,
                mode="job",
                page_size=min(_CLOUD_AUDIT_SYNC_PAGE_SIZE, max(len(inventory), 1)),
            )
            enqueue_response = _enqueue_cloud_workspace_audit_job(
                auth_context=resolved_auth_context,
                request_payload=request_payload,
                workspace_id=workspace_id,
            )
            job_id = str(enqueue_response.get("jobId") or "").strip()
            final_response = _poll_cloud_workspace_audit_job(
                auth_context=resolved_auth_context,
                job_id=job_id,
                workspace_id=workspace_id,
            )
            final_status = (
                str(final_response.get("status") or enqueue_response.get("status") or "queued").strip().lower()
            )
            cloud_visible_count = _int_value(final_response.get("totalPackages"))
            cloud_processed_count = _int_value(final_response.get("processedCount"))
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
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    bundle_summary = _call_sync_with_optional_auth_context(
        sync_supply_chain_bundle,
        store=store,
        auth_context=resolved_auth_context,
    )
    payload = dict(bundle_summary) if isinstance(bundle_summary, dict) else {}
    workspace_audits = sync_managed_workspace_audits(
        store,
        auth_context=resolved_auth_context,
        workspace_dir=workspace_dir,
    )
    payload["workspace_audits"] = workspace_audits
    payload.setdefault("synced_at", workspace_audits.get("synced_at"))
    return payload


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


def _package_execution_exit_code(policy_action: object) -> int:
    return 0 if is_execution_permitted(policy_action) else 2


def _protect_action_for_policy_action(policy_action: object) -> GuardAction:
    return normalize_guard_action(policy_action, unknown_action="block")


def _evaluation_risk_signals(evaluation: object) -> list[str]:
    if not _is_package_request_evaluation(evaluation):
        return []
    reasons = evaluation.reasons
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
    if not _is_package_request_evaluation(evaluation):
        return []
    packages = evaluation.packages
    advisories: list[dict[str, object]] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        for advisory_id in _string_items(item.get("related_advisory_ids")):
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
    public_target = target.to_dict()
    raw_spec = str(public_target.get("raw_spec") or "")
    source_url = _string_value(public_target.get("source_url"))
    return {
        "artifact_id": f"{target.ecosystem}:{target.package_name or raw_spec}",
        "artifact_name": target.package_name or raw_spec,
        "artifact_type": "package_request",
        "ecosystem": target.ecosystem,
        "package_name": target.package_name,
        "package_url": None,
        "raw_spec": raw_spec,
        "version": target.requested_specifier,
        "source_url": source_url,
        "harness": _LOCAL_SUPPLY_CHAIN_HARNESS,
    }


def _redact_command_token(token: str) -> str:
    token = redact_package_request_token(token)
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


def _dict_items(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


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

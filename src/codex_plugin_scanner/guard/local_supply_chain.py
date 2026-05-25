"""Shared local supply-chain posture and CLI helpers."""

from __future__ import annotations

import hashlib
import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import GuardConfig, resolve_risk_action
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
from .runtime.package_manifest_diff import parse_manifest_dependencies
from .runtime.supply_chain_package_eval import evaluate_package_request_artifact
from .runtime.supply_chain_support import ecosystem_support_matrix
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


def build_local_supply_chain_posture(
    store: GuardStore,
    config: GuardConfig,
    *,
    now: str | None = None,
) -> dict[str, object]:
    snapshot_now = _parse_timestamp(now) or datetime.now(timezone.utc)
    workspace_id = store.get_cloud_workspace_id()
    credentials = store.get_sync_credentials()
    summary = _dict_payload(store.get_sync_payload("supply_chain_bundle_summary"))
    entitlement = _dict_payload(store.get_sync_payload("supply_chain_bundle_entitlement"))
    remote_policy = _dict_payload(store.get_sync_payload("policy"))
    team_policy_pack = _dict_payload(store.get_sync_payload("team_policy_pack"))
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id else None
    bundle_payload = _dict_payload(cached_bundle.get("bundle")) if isinstance(cached_bundle, dict) else {}
    expires_at_text = _string_value(bundle_payload.get("expiresAt"))
    expires_at = _parse_timestamp(expires_at_text)
    status = _posture_status(
        credentials_present=credentials is not None,
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
            "logged_in": credentials is not None,
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


def build_workspace_scan_payload(
    *,
    store: GuardStore,
    config: GuardConfig,
    workspace_dir: Path,
    now: str,
) -> tuple[dict[str, object], int]:
    posture = build_local_supply_chain_posture(store, config, now=now)
    intent = _workspace_scan_intent(workspace_dir)
    if intent is None:
        return (
            {
                "generated_at": now,
                "manifest_paths": [],
                "lockfile_paths": [],
                "message": "No supported manifests or lockfiles found in this workspace.",
                "supply_chain": posture,
            },
            0,
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
        "manifest_paths": list(intent.manifest_paths),
        "lockfile_paths": list(intent.lockfile_paths),
        "evaluation": evaluation.to_dict(),
        "supply_chain": posture,
    }
    return (payload, _evaluation_exit_code(evaluation.decision))


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
    now: str,
    config: GuardConfig | None,
    unsafe_raw_output: bool,
    timeout_seconds: int,
) -> tuple[dict[str, object], int] | None:
    from .runtime.package_intent_parser import parse_package_intent

    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached_bundle, dict):
        return None
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
    evaluation = evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    verdict_action = _protect_action_for_decision(evaluation.decision)
    risk_signals = tuple(_evaluation_risk_signals(evaluation))
    receipt = build_receipt(
        harness=_LOCAL_SUPPLY_CHAIN_HARNESS,
        artifact_id=artifact.artifact_id,
        artifact_hash=hashlib.sha256(artifact.artifact_id.encode("utf-8")).hexdigest(),
        policy_decision=verdict_action,
        capabilities_summary=evaluation.user_copy.summary,
        changed_capabilities=[target.package_name or target.raw_spec for target in sanitized_intent.targets],
        provenance_summary=evaluation.user_copy.harness_message,
        artifact_name=artifact.name,
        source_scope=artifact.source_scope,
    )
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
        "receipt": receipt.to_dict(),
        "matched_advisories": _matched_advisories(evaluation),
        "supply_chain_evaluation": evaluation.to_dict(),
    }
    if config is not None:
        payload["supply_chain"] = build_local_supply_chain_posture(store, config, now=now)
    if evaluation.decision in {"block", "ask"} or dry_run:
        store.add_receipt(receipt)
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


def _workspace_scan_intent(workspace_dir: Path) -> PackageIntent | None:
    manifest_paths, lockfile_paths = _workspace_files(workspace_dir)
    if not manifest_paths and not lockfile_paths:
        return None
    targets = _targets_from_workspace_manifests(workspace_dir, manifest_paths)
    package_manager = _package_manager_for_scan(manifest_paths)
    return PackageIntent(
        package_manager=package_manager,
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", "scan"),
        redacted_command="hol-guard supply-chain scan",
        targets=targets,
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
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

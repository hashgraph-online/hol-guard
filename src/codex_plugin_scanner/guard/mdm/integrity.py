"""Fail-honest, read-only local integrity snapshot construction."""

from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import cast, get_args

from ...version import __version__
from .contracts import (
    LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
    AssuranceLevel,
    IntegrityComponent,
    IntegrityReasonCode,
    IntegrityState,
    KeyProtectionStatus,
    LocalIntegritySnapshot,
    MachinePaths,
    ManagedPolicyState,
    RemediationClass,
    SnapshotComponents,
    SupervisorStatus,
    default_machine_paths,
)
from .lifecycle import load_trusted_keys
from .manifest import ManifestVerification, verify_release_manifest
from .native import NativeInstallVerification, verify_native_install
from .policy import load_managed_policy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _component(state: str, reason_code: str) -> IntegrityComponent:
    normalized = (
        state if state in {"healthy", "degraded", "absent", "tampered", "unsupported", "unknown"} else "unknown"
    )
    normalized_reason = reason_code if reason_code in get_args(IntegrityReasonCode) else "integrity_reason_unrecognized"
    return IntegrityComponent(
        cast(IntegrityState, normalized),
        cast(IntegrityReasonCode, normalized_reason),
    )


def _assurance_level(*, update_owner: str) -> AssuranceLevel:
    if update_owner == "mdm":
        return "mdm-managed-unverified"
    return "user-managed"


def _remediation_class(assurance_level: AssuranceLevel, states: list[str]) -> RemediationClass:
    if all(state == "healthy" for state in states):
        return "none"
    if "tampered" in states:
        return "administrator-action"
    if assurance_level != "user-managed":
        return "mdm-repair"
    return "user-reinstall"


def _bounded_file_hash(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _verify_manifest(paths: MachinePaths, trusted_keys: dict[str, bytes]) -> ManifestVerification:
    try:
        return verify_release_manifest(
            paths.manifest_path,
            paths.runtime_root,
            trusted_keys=trusted_keys,
            expected_platform={"Darwin": "macos", "Windows": "windows"}.get(platform.system()),
            expected_architecture=platform.machine().lower(),
            expected_owner_uid=0 if platform.system() != "Windows" else None,
        )
    except Exception:
        return ManifestVerification("unknown", "release_manifest_probe_failed")


def _verify_native(runtime_root: Path) -> NativeInstallVerification:
    try:
        return verify_native_install(runtime_root)
    except Exception:
        return NativeInstallVerification("unknown", "native_install_probe_failed", "unknown", "unknown")


def _load_policy() -> ManagedPolicyState:
    try:
        return load_managed_policy(write_cache=False)
    except Exception:
        return ManagedPolicyState("inaccessible", "native", reason_code="managed_policy_probe_failed")


def machine_integrity_snapshot() -> LocalIntegritySnapshot:
    """Return bounded machine evidence without trusting environment path overrides."""

    paths = default_machine_paths()
    runtime_root = paths.runtime_root
    trusted_keys = load_trusted_keys(runtime_root / "release-trusted-keys.json")
    manifest = _verify_manifest(paths, trusted_keys)
    native = _verify_native(runtime_root)
    policy = _load_policy()
    update_owner = policy.policy.install_owner if policy.policy is not None else "user"
    if policy.policy is None and policy.status in {"invalid", "inaccessible", "tampered"}:
        update_owner = "mdm"
    assurance_level = _assurance_level(update_owner=update_owner)

    manifest_component = _component(manifest.status, manifest.reason_code)
    native_component = _component(native.status, native.reason_code)
    policy_state = "healthy" if policy.status == "active" else policy.status
    if policy.reason_code == "managed_policy_profile_removed_cached":
        policy_state = "degraded"
    policy_component = _component(
        policy_state,
        policy.reason_code or ("managed_policy_active" if policy.status == "active" else "managed_policy_absent"),
    )
    ownership_acl = IntegrityComponent("unsupported", "ownership_acl_verification_unavailable")
    supervisor = SupervisorStatus("unsupported", "supervisor_verification_unavailable")
    device_key = KeyProtectionStatus("unsupported", "unavailable", "device_key_verification_unavailable")
    harness_coverage = IntegrityComponent("unsupported", "harness_coverage_verification_unavailable")
    installation_identity = IntegrityComponent("unsupported", "installation_identity_verification_unavailable")
    lease_continuity = IntegrityComponent("unsupported", "lease_continuity_verification_unavailable")
    daemon = IntegrityComponent("unsupported", "daemon_verification_unavailable")
    command_shadowing = IntegrityComponent("unsupported", "command_shadowing_verification_unavailable")
    update = IntegrityComponent("unsupported", "update_verification_unavailable")

    components: SnapshotComponents = {
        "manifest": manifest_component.to_dict(),
        "nativePackage": native_component.to_dict(),
        "managedPolicy": policy_component.to_dict(),
        "ownershipAndAcl": ownership_acl.to_dict(),
        "supervisor": supervisor.to_dict(),
        "deviceKey": device_key.to_dict(),
        "harnessCoverage": harness_coverage.to_dict(),
        "installationIdentity": installation_identity.to_dict(),
        "leaseContinuity": lease_continuity.to_dict(),
        "daemon": daemon.to_dict(),
        "commandShadowing": command_shadowing.to_dict(),
        "update": update.to_dict(),
    }
    states = [
        manifest_component.state,
        native_component.state,
        policy_component.state,
        ownership_acl.state,
        supervisor.state,
        device_key.state,
        harness_coverage.state,
        installation_identity.state,
        lease_continuity.state,
        daemon.state,
        command_shadowing.state,
        update.state,
    ]
    component_results = (
        manifest_component,
        native_component,
        policy_component,
        ownership_acl,
        supervisor,
        device_key,
        harness_coverage,
        installation_identity,
        lease_continuity,
        daemon,
        command_shadowing,
        update,
    )
    reason_codes = cast(
        list[IntegrityReasonCode],
        sorted({component.reason_code for component in component_results if not component.healthy}),
    )
    healthy = all(state == "healthy" for state in states)
    return {
        "schemaVersion": LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
        "generatedAt": _now(),
        "scope": "machine",
        "healthy": healthy,
        "assuranceLevel": assurance_level,
        "installOwner": update_owner,
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "identifiers": {
            "workspaceId": None,
            "deviceId": None,
            "machineInstallationId": None,
            "installationGeneration": None,
        },
        "product": {
            "version": (
                manifest.version
                if manifest.healthy and manifest.version is not None
                else native.version
                if native.healthy and native.version is not None
                else __version__
            ),
            "buildId": manifest.build_id if manifest.healthy else None,
            "sourceCommit": None,
            "packageIdentity": native.package_identity,
            "manifestHash": _bounded_file_hash(paths.manifest_path),
            "policyHash": policy.policy.content_hash if policy.policy is not None else None,
        },
        "components": components,
        "harnessCoverage": {"required": None, "protected": None, "degraded": None, "missing": None},
        "continuity": {
            "monotonicUptimeSeconds": None,
            "sequence": None,
            "previousLeaseDigest": None,
            "bootSessionId": None,
        },
        "reasonCodes": reason_codes,
        "remediationClass": _remediation_class(assurance_level, states),
    }


__all__ = ["machine_integrity_snapshot"]

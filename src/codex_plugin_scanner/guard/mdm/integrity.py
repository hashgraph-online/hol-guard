"""Fail-honest, read-only local integrity snapshot construction."""

from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import cast, get_args

from ...version import __version__
from .acl import OwnershipAclVerification, verify_protected_ownership_and_acl
from .continuity import ContinuityVerification, verify_installation_continuity
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
from .device_key import verify_machine_device_key
from .manifest import ManifestVerification, verify_release_manifest
from .native import NativeInstallVerification, verify_native_install
from .policy import load_managed_policy
from .supervisor import verify_machine_supervisor


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


def _remediation_class(assurance_level: AssuranceLevel, healthy: bool, states: list[str]) -> RemediationClass:
    if healthy:
        return "none"
    if "tampered" in states:
        return "administrator-action"
    if assurance_level != "user-managed":
        return "mdm-repair"
    return "user-reinstall"


def _trusted_product_version(
    manifest: ManifestVerification,
    native: NativeInstallVerification,
) -> str:
    """Return public installed-version metadata only after its verification boundary passes."""

    if manifest.healthy and manifest.version is not None:
        return manifest.version
    if native.healthy and native.version is not None:
        return native.version
    return __version__


def _bounded_file_hash(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _verify_manifest(
    paths: MachinePaths,
    native: NativeInstallVerification,
    minimum_version: str | None,
    trusted_public_keys: dict[str, bytes],
) -> ManifestVerification:
    try:
        return verify_release_manifest(
            paths.manifest_path,
            paths.runtime_root,
            trusted_keys=trusted_public_keys,
            expected_platform={"Darwin": "macos", "Windows": "windows"}.get(platform.system()),
            expected_architecture=platform.machine().lower(),
            expected_owner_uid=0 if platform.system() != "Windows" else None,
            expected_installer_identity=(
                native.package_identity
                if native.healthy
                else {"Darwin": "org.hol.guard", "Windows": "HOLGuardMachine"}.get(platform.system())
            ),
            expected_native_version=native.version if native.healthy else None,
            minimum_version=minimum_version,
        )
    except Exception:
        return ManifestVerification("unknown", "release_manifest_probe_failed")


def _verify_native(
    runtime_root: Path,
    *,
    macos_team_id: str | None,
    windows_signer_thumbprints: tuple[str, ...],
) -> NativeInstallVerification:
    try:
        return verify_native_install(
            runtime_root,
            macos_team_id=macos_team_id,
            windows_signer_thumbprints=windows_signer_thumbprints,
        )
    except Exception:
        return NativeInstallVerification("unknown", "native_install_probe_failed", "unknown", "unknown")


def _load_policy() -> ManagedPolicyState:
    try:
        return load_managed_policy(write_cache=False)
    except Exception:
        return ManagedPolicyState("inaccessible", "native", reason_code="managed_policy_probe_failed")


def _verify_ownership_acl(paths: MachinePaths) -> OwnershipAclVerification:
    try:
        return verify_protected_ownership_and_acl(paths)
    except Exception:
        return OwnershipAclVerification("unknown", "ownership_acl_probe_failed", ())


def _verify_supervisor(paths: MachinePaths) -> SupervisorStatus:
    try:
        return verify_machine_supervisor(paths)
    except Exception:
        return SupervisorStatus("unknown", "supervisor_probe_failed")


def _verify_device_key(paths: MachinePaths) -> KeyProtectionStatus:
    try:
        return verify_machine_device_key(paths)
    except Exception:
        return KeyProtectionStatus("unknown", "unknown", "device_key_probe_failed")


def _verify_continuity(paths: MachinePaths) -> ContinuityVerification:
    try:
        return verify_installation_continuity(paths)
    except Exception:
        return ContinuityVerification("unknown", "installation_identity_probe_failed", "lease_continuity_probe_failed")


def _continuity_components(result: ContinuityVerification) -> tuple[IntegrityComponent, IntegrityComponent]:
    identity_state = {
        "installation_identity_active": "healthy",
        "installation_identity_absent": "absent",
        "installation_identity_invalid": "tampered",
        "installation_identity_acl_invalid": "tampered",
        "installation_identity_key_mismatch": "tampered",
    }.get(result.identity_reason_code, "unknown")
    lease_state = {
        "lease_continuity_active": "healthy",
        "lease_continuity_uninitialized": "healthy",
        "lease_continuity_absent": "absent",
        "lease_continuity_invalid": "tampered",
        "lease_continuity_monotonic_regression": "tampered",
        "lease_continuity_sequence_exhausted": "degraded",
        "lease_continuity_platform_unsupported": "unsupported",
    }.get(result.lease_reason_code, "unknown")
    return (
        _component(identity_state, result.identity_reason_code),
        _component(lease_state, result.lease_reason_code),
    )


def machine_integrity_snapshot() -> LocalIntegritySnapshot:
    """Return bounded machine evidence without trusting environment path overrides."""

    paths = default_machine_paths()
    runtime_root = paths.runtime_root
    policy = _load_policy()
    minimum_version = policy.policy.update.minimum_version if policy.policy is not None else None
    live_policy = policy.policy if policy.reason_code != "managed_policy_profile_removed_cached" else None
    trust = live_policy.integrity_trust if live_policy is not None else None
    native = _verify_native(
        runtime_root,
        macos_team_id=trust.macos_team_id if trust is not None else None,
        windows_signer_thumbprints=trust.windows_signer_thumbprints if trust is not None else (),
    )
    manifest = _verify_manifest(
        paths,
        native,
        minimum_version,
        trust.release_public_keys if trust is not None else {},
    )
    update_owner = policy.policy.install_owner if policy.policy is not None else "user"
    if policy.policy is None and policy.status in {"invalid", "inaccessible", "tampered"}:
        update_owner = "mdm"
    assurance_level = _assurance_level(update_owner=update_owner)
    acl = _verify_ownership_acl(paths)
    supervisor = _verify_supervisor(paths)
    device_key = _verify_device_key(paths)
    continuity = _verify_continuity(paths)

    manifest_component = _component(manifest.status, manifest.reason_code)
    native_component = _component(native.status, native.reason_code)
    policy_state = "healthy" if policy.status == "active" else policy.status
    if policy_state in {"invalid", "inaccessible"}:
        policy_state = "degraded"
    if policy.reason_code == "managed_policy_profile_removed_cached":
        policy_state = "degraded"
    policy_component = _component(
        policy_state,
        policy.reason_code or ("managed_policy_active" if policy.status == "active" else "managed_policy_absent"),
    )
    ownership_acl = _component(acl.status, acl.reason_code)
    harness_coverage = IntegrityComponent("unsupported", "harness_coverage_verification_unavailable")
    installation_identity, lease_continuity = _continuity_components(continuity)
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
    healthy = all(component.healthy for component in component_results)
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
            "machineInstallationId": (
                continuity.record.machine_installation_id if continuity.record is not None else None
            ),
            "installationGeneration": (
                continuity.record.installation_generation if continuity.record is not None else None
            ),
        },
        "product": {
            "version": _trusted_product_version(manifest, native),
            "buildId": manifest.build_id if manifest.healthy else None,
            "sourceCommit": None,
            "packageIdentity": native.package_identity,
            "manifestHash": _bounded_file_hash(paths.manifest_path),
            "policyHash": policy.policy.content_hash if policy.policy is not None else None,
        },
        "components": components,
        "harnessCoverage": {"required": None, "protected": None, "degraded": None, "missing": None},
        "continuity": {
            "monotonicUptimeSeconds": (
                continuity.observation.monotonic_uptime_ns / 1_000_000_000
                if continuity.observation is not None
                else None
            ),
            "sequence": continuity.record.last_issued_sequence if continuity.record is not None else None,
            "previousLeaseDigest": continuity.record.last_lease_digest if continuity.record is not None else None,
            "bootSessionId": (continuity.observation.boot_session_id if continuity.observation is not None else None),
        },
        "reasonCodes": reason_codes,
        "remediationClass": _remediation_class(assurance_level, healthy, states),
    }


__all__ = ["machine_integrity_snapshot"]

"""Typed MDM policy, machine path, and status contracts."""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict

MDM_POLICY_SCHEMA_VERSION = "hol-guard-mdm-policy.v1"
MDM_STATUS_SCHEMA_VERSION = "hol-guard-mdm-status.v1"
RELEASE_MANIFEST_SCHEMA_VERSION = "hol-guard-release-manifest.v1"
LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION = "local-integrity-snapshot.v1"

InstallOwner = Literal["user", "mdm"]
ProxyMode = Literal["system", "explicit", "none"]
ManagedPolicyStatus = Literal["absent", "active", "invalid", "inaccessible", "tampered"]
AssuranceLevel = Literal["user-managed", "mdm-managed-unverified", "mdm-managed"]
IntegrityState = Literal["healthy", "degraded", "absent", "tampered", "unsupported", "unknown"]
KeyProtectionLevel = Literal["hardware-backed", "os-protected", "file-backed", "unavailable", "unknown"]
SupervisorState = Literal["running", "stopped", "disabled", "absent", "unsupported", "unknown"]
RemediationClass = Literal["none", "user-reinstall", "mdm-repair", "administrator-action"]
IntegrityReasonCode = Literal[
    "release_manifest_absent",
    "release_manifest_architecture_mismatch",
    "release_manifest_hash_mismatch",
    "release_manifest_coverage_gap",
    "release_manifest_duplicate_path",
    "release_manifest_file_limit_exceeded",
    "release_manifest_file_missing",
    "release_manifest_insecure_permissions",
    "release_manifest_invalid",
    "release_manifest_installer_identity_mismatch",
    "release_manifest_native_version_mismatch",
    "release_manifest_path_escape",
    "release_manifest_platform_mismatch",
    "release_manifest_size_limit_exceeded",
    "release_manifest_unsigned",
    "release_manifest_untrusted_key",
    "release_manifest_trust_anchor_absent",
    "release_manifest_valid",
    "release_manifest_version_rollback",
    "release_manifest_version_invalid",
    "release_manifest_wrong_owner",
    "release_runtime_insecure_permissions",
    "release_runtime_wrong_owner",
    "native_install_valid",
    "native_package_identity_absent",
    "native_package_receipt_absent",
    "native_package_version_invalid",
    "native_platform_unsupported",
    "native_publisher_signature_invalid",
    "native_publisher_pin_absent",
    "managed_policy_active",
    "managed_policy_absent",
    "managed_policy_cache_invalid",
    "managed_policy_cache_tampered",
    "managed_policy_inaccessible",
    "managed_policy_invalid",
    "managed_policy_profile_removed_cached",
    "ownership_acl_verification_unavailable",
    "ownership_acl_valid",
    "ownership_acl_surface_absent",
    "ownership_acl_wrong_owner",
    "ownership_acl_standard_user_writable",
    "ownership_acl_path_escape",
    "ownership_acl_probe_failed",
    "ownership_acl_platform_unsupported",
    "supervisor_verification_unavailable",
    "supervisor_running",
    "supervisor_absent",
    "supervisor_stopped",
    "supervisor_disabled",
    "supervisor_registration_invalid",
    "supervisor_executable_mismatch",
    "supervisor_schedule_invalid",
    "supervisor_probe_failed",
    "supervisor_platform_unsupported",
    "device_key_verification_unavailable",
    "device_key_active",
    "device_key_absent",
    "device_key_revoked",
    "device_key_metadata_invalid",
    "device_key_public_mismatch",
    "device_key_acl_invalid",
    "device_key_unusable",
    "device_key_provider_unavailable",
    "device_key_rotation_incomplete",
    "device_key_revocation_incomplete",
    "device_key_probe_failed",
    "device_key_platform_unsupported",
    "harness_coverage_verification_unavailable",
    "harness_coverage_not_required",
    "harness_coverage_healthy",
    "harness_coverage_degraded",
    "harness_coverage_missing",
    "harness_coverage_registry_absent",
    "harness_coverage_probe_failed",
    "installation_identity_verification_unavailable",
    "lease_continuity_verification_unavailable",
    "installation_identity_active",
    "installation_identity_absent",
    "installation_identity_invalid",
    "installation_identity_acl_invalid",
    "installation_identity_key_mismatch",
    "installation_identity_probe_failed",
    "lease_continuity_active",
    "lease_continuity_uninitialized",
    "lease_continuity_absent",
    "lease_continuity_invalid",
    "lease_continuity_boot_probe_failed",
    "lease_continuity_monotonic_probe_failed",
    "lease_continuity_monotonic_regression",
    "lease_continuity_sequence_exhausted",
    "lease_continuity_probe_failed",
    "lease_continuity_platform_unsupported",
    "daemon_verification_unavailable",
    "daemon_running",
    "daemon_absent",
    "daemon_stopped",
    "daemon_disabled",
    "daemon_registration_invalid",
    "daemon_probe_failed",
    "command_shadowing_verification_unavailable",
    "command_shadowing_absent",
    "command_shadowing_trusted",
    "command_shadowing_detected",
    "command_shadowing_probe_failed",
    "update_verification_unavailable",
    "update_version_allowed",
    "integrity_reason_unrecognized",
    "release_manifest_probe_failed",
    "native_install_probe_failed",
    "managed_policy_probe_failed",
]


class SnapshotComponent(TypedDict):
    state: IntegrityState
    healthy: bool
    reasonCode: IntegrityReasonCode


class SnapshotKeyComponent(TypedDict):
    state: IntegrityState
    healthy: bool
    level: KeyProtectionLevel
    reasonCode: IntegrityReasonCode


class SnapshotSupervisorComponent(TypedDict):
    state: SupervisorState
    healthy: bool
    reasonCode: IntegrityReasonCode


@dataclass(frozen=True, slots=True)
class IntegrityComponent:
    state: IntegrityState
    reason_code: IntegrityReasonCode

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"

    def to_dict(self) -> SnapshotComponent:
        return {"state": self.state, "healthy": self.healthy, "reasonCode": self.reason_code}


@dataclass(frozen=True, slots=True)
class KeyProtectionStatus:
    state: IntegrityState
    level: KeyProtectionLevel
    reason_code: IntegrityReasonCode

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"

    def to_dict(self) -> SnapshotKeyComponent:
        return {
            "state": self.state,
            "healthy": self.healthy,
            "level": self.level,
            "reasonCode": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class SupervisorStatus:
    state: SupervisorState
    reason_code: IntegrityReasonCode

    @property
    def healthy(self) -> bool:
        return self.state == "running"

    def to_dict(self) -> SnapshotSupervisorComponent:
        return {
            "state": self.state,
            "healthy": self.healthy,
            "reasonCode": self.reason_code,
        }


class SnapshotProduct(TypedDict):
    version: str
    buildId: str | None
    sourceCommit: str | None
    packageIdentity: str
    manifestHash: str | None
    policyHash: str | None


class SnapshotIdentifiers(TypedDict):
    workspaceId: str | None
    deviceId: str | None
    machineInstallationId: str | None
    installationGeneration: str | None


class SnapshotContinuity(TypedDict):
    monotonicUptimeSeconds: float | None
    sequence: int | None
    previousLeaseDigest: str | None
    bootSessionId: str | None


class HarnessCoverage(TypedDict):
    required: int | None
    protected: int | None
    degraded: int | None
    missing: int | None


class SnapshotComponents(TypedDict):
    manifest: SnapshotComponent
    nativePackage: SnapshotComponent
    managedPolicy: SnapshotComponent
    ownershipAndAcl: SnapshotComponent
    supervisor: SnapshotSupervisorComponent
    deviceKey: SnapshotKeyComponent
    harnessCoverage: SnapshotComponent
    installationIdentity: SnapshotComponent
    leaseContinuity: SnapshotComponent
    daemon: SnapshotComponent
    commandShadowing: SnapshotComponent
    update: SnapshotComponent


class LocalIntegritySnapshot(TypedDict):
    schemaVersion: Literal["local-integrity-snapshot.v1"]
    generatedAt: str
    scope: Literal["machine"]
    healthy: bool
    assuranceLevel: AssuranceLevel
    installOwner: InstallOwner
    platform: str
    architecture: str
    identifiers: SnapshotIdentifiers
    product: SnapshotProduct
    components: SnapshotComponents
    harnessCoverage: HarnessCoverage
    continuity: SnapshotContinuity
    reasonCodes: list[IntegrityReasonCode]
    remediationClass: RemediationClass


@dataclass(frozen=True, slots=True)
class MachinePaths:
    """Platform machine-owned locations used by native installers."""

    runtime_root: Path
    state_root: Path
    policy_path: Path | None
    log_root: Path
    manifest_path: Path

    def to_dict(self) -> dict[str, str | None]:
        return {
            "runtimeRoot": str(self.runtime_root),
            "stateRoot": str(self.state_root),
            "policyPath": str(self.policy_path) if self.policy_path is not None else None,
            "logRoot": str(self.log_root),
            "manifestPath": str(self.manifest_path),
        }


def default_machine_paths(*, system_name: str | None = None) -> MachinePaths:
    """Resolve stable machine paths without consulting user-controlled environment overrides."""

    resolved_system = system_name or platform.system()
    if resolved_system == "Darwin":
        runtime_root = Path("/Library/Application Support/HOL Guard")
        return MachinePaths(
            runtime_root=runtime_root,
            state_root=Path("/Library/Application Support/HOL Guard State"),
            policy_path=Path("/Library/Managed Preferences/org.hol.guard.plist"),
            log_root=Path("/Library/Logs/HOL Guard"),
            manifest_path=runtime_root / "release-manifest.json",
        )
    if resolved_system == "Windows":
        program_files = Path(r"C:\Program Files")
        program_data = Path(r"C:\ProgramData")
        runtime_root = program_files / "HOL Guard"
        state_root = program_data / "HOL Guard"
        return MachinePaths(
            runtime_root=runtime_root,
            state_root=state_root,
            policy_path=None,
            log_root=state_root / "Logs",
            manifest_path=runtime_root / "release-manifest.json",
        )
    runtime_root = Path("/opt/hol-guard")
    state_root = Path("/var/lib/hol-guard")
    return MachinePaths(
        runtime_root=runtime_root,
        state_root=state_root,
        policy_path=Path("/etc/hol-guard/managed-policy.json"),
        log_root=Path("/var/log/hol-guard"),
        manifest_path=runtime_root / "release-manifest.json",
    )


@dataclass(frozen=True, slots=True)
class ManagedNetworkPolicy:
    proxy_mode: ProxyMode = "system"
    proxy_url: str | None = None
    ca_bundle_path: str | None = None
    allow_public_registries: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "proxyMode": self.proxy_mode,
            "proxyConfigured": self.proxy_url is not None,
            "caBundleConfigured": self.ca_bundle_path is not None,
            "allowPublicRegistries": self.allow_public_registries,
        }


@dataclass(frozen=True, slots=True)
class ManagedUpdatePolicy:
    owner: InstallOwner = "user"
    channel: str = "stable"
    minimum_version: str | None = None
    maximum_version: str | None = None
    allow_downgrade: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "channel": self.channel,
            "minimumVersion": self.minimum_version,
            "maximumVersion": self.maximum_version,
            "allowDowngrade": self.allow_downgrade,
        }


@dataclass(frozen=True, slots=True)
class ManagedIntegrityTrust:
    release_public_keys: dict[str, bytes] = field(default_factory=dict)
    macos_team_id: str | None = None
    windows_signer_thumbprints: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, object]:
        return {
            "releaseKeyIds": sorted(self.release_public_keys),
            "macosTeamIdConfigured": self.macos_team_id is not None,
            "windowsSignerThumbprintsConfigured": bool(self.windows_signer_thumbprints),
        }


@dataclass(frozen=True, slots=True)
class ManagedPolicy:
    schema_version: str
    settings: dict[str, object]
    locked_settings: frozenset[str]
    required_harnesses: tuple[str, ...] = ()
    network: ManagedNetworkPolicy = field(default_factory=ManagedNetworkPolicy)
    update: ManagedUpdatePolicy = field(default_factory=ManagedUpdatePolicy)
    integrity_trust: ManagedIntegrityTrust = field(default_factory=ManagedIntegrityTrust)
    daemon_startup: Literal["on-demand", "login"] = "on-demand"
    content_hash: str = ""
    policy_bundle_keyring: dict[str, object] | None = None

    @property
    def install_owner(self) -> InstallOwner:
        return self.update.owner

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schemaVersion": self.schema_version,
            "contentHash": self.content_hash,
            "lockedSettings": sorted(self.locked_settings),
            "requiredHarnesses": list(self.required_harnesses),
            "network": self.network.to_dict(),
            "update": self.update.to_dict(),
            "integrityTrust": self.integrity_trust.to_public_dict(),
            "daemonStartup": self.daemon_startup,
        }
        if self.policy_bundle_keyring is not None:
            raw_keys = self.policy_bundle_keyring.get("keys")
            payload["policyBundleKeyring"] = {
                "configured": True,
                "keyCount": len(raw_keys) if isinstance(raw_keys, list) else 0,
                "workspaceId": self.policy_bundle_keyring.get("workspaceId"),
            }
        return payload


@dataclass(frozen=True, slots=True)
class ManagedPolicyState:
    status: ManagedPolicyStatus
    source: str
    policy: ManagedPolicy | None = None
    reason_code: str | None = None
    detail: str | None = None

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "status": self.status,
            "source": self.source,
            "reasonCode": self.reason_code,
        }
        if self.policy is not None:
            payload["policy"] = self.policy.to_public_dict()
        if self.detail is not None:
            payload["detail"] = self.detail
        return payload


def canonical_payload_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION",
    "MDM_POLICY_SCHEMA_VERSION",
    "MDM_STATUS_SCHEMA_VERSION",
    "RELEASE_MANIFEST_SCHEMA_VERSION",
    "AssuranceLevel",
    "HarnessCoverage",
    "InstallOwner",
    "IntegrityComponent",
    "IntegrityReasonCode",
    "IntegrityState",
    "KeyProtectionLevel",
    "KeyProtectionStatus",
    "LocalIntegritySnapshot",
    "MachinePaths",
    "ManagedNetworkPolicy",
    "ManagedPolicy",
    "ManagedPolicyState",
    "ManagedUpdatePolicy",
    "RemediationClass",
    "SnapshotComponent",
    "SnapshotComponents",
    "SnapshotContinuity",
    "SnapshotIdentifiers",
    "SnapshotKeyComponent",
    "SnapshotProduct",
    "SnapshotSupervisorComponent",
    "SupervisorState",
    "SupervisorStatus",
    "canonical_payload_hash",
    "default_machine_paths",
]

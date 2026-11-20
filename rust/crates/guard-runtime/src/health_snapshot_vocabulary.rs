//! The closed vocabularies a machine health snapshot may use.
//!
//! Each list mirrors one `Literal` alias in `mdm/contracts.py`, in the same
//! order; a test reads that file and fails when the two drift apart.

/// `IntegrityState`.
pub(super) const INTEGRITY_STATES: [&str; 6] = [
    "healthy",
    "degraded",
    "absent",
    "tampered",
    "unsupported",
    "unknown",
];

/// `SupervisorState`.
pub(super) const SUPERVISOR_STATES: [&str; 6] = [
    "running",
    "stopped",
    "disabled",
    "absent",
    "unsupported",
    "unknown",
];

/// `KeyProtectionLevel`.
pub(super) const KEY_PROTECTION_LEVELS: [&str; 5] = [
    "hardware-backed",
    "os-protected",
    "file-backed",
    "unavailable",
    "unknown",
];

/// `AssuranceLevel`.
pub(super) const ASSURANCE_LEVELS: [&str; 3] =
    ["user-managed", "mdm-managed-unverified", "mdm-managed"];

/// `InstallOwner`.
pub(super) const INSTALL_OWNERS: [&str; 2] = ["user", "mdm"];

/// `RemediationClass`.
pub(super) const REMEDIATION_CLASSES: [&str; 4] = [
    "none",
    "user-reinstall",
    "mdm-repair",
    "administrator-action",
];

/// `IntegrityReasonCode`.
pub(super) const INTEGRITY_REASON_CODES: [&str; 112] = [
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
    "managed_policy_source_tampered",
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
];

#[cfg(test)]
pub(super) const ALIASES: [(&str, &[&str]); 7] = [
    ("IntegrityState", &INTEGRITY_STATES),
    ("SupervisorState", &SUPERVISOR_STATES),
    ("KeyProtectionLevel", &KEY_PROTECTION_LEVELS),
    ("AssuranceLevel", &ASSURANCE_LEVELS),
    ("InstallOwner", &INSTALL_OWNERS),
    ("RemediationClass", &REMEDIATION_CLASSES),
    ("IntegrityReasonCode", &INTEGRITY_REASON_CODES),
];

"""Stable local trust vocabulary shared by Guard runtime and UI APIs."""

from __future__ import annotations

from typing import Literal

LocalTrustMode = Literal[
    "protected",
    "cloud_authoritative",
    "degraded_safe",
    "setup_required",
    "unsupported",
]

PolicyIntegrityMode = Literal["protected", "degraded"]
PolicyIntegrityEnforcement = Literal["enforce", "warn"]

POLICY_INTEGRITY_MODE_PROTECTED: PolicyIntegrityMode = "protected"
POLICY_INTEGRITY_MODE_DEGRADED: PolicyIntegrityMode = "degraded"
POLICY_INTEGRITY_ENFORCEMENT_ENFORCE: PolicyIntegrityEnforcement = "enforce"
POLICY_INTEGRITY_ENFORCEMENT_WARN: PolicyIntegrityEnforcement = "warn"

LOCAL_TRUST_MODES: tuple[LocalTrustMode, ...] = (
    "protected",
    "cloud_authoritative",
    "degraded_safe",
    "setup_required",
    "unsupported",
)

POLICY_INTEGRITY_DEGRADED_REASONS: tuple[str, ...] = (
    "system_keyring_unavailable",
    "policy_integrity_key_unavailable",
    "policy_integrity_control_unavailable",
    "guard_home_symlink",
    "guard_db_symlink",
    "guard_home_permissions",
    "guard_db_permissions",
    "guard_home_inaccessible",
    "guard_db_inaccessible",
)

POLICY_INTEGRITY_REASON_SYSTEM_KEYRING_UNAVAILABLE = "system_keyring_unavailable"
POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE = "policy_integrity_key_unavailable"
POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE = "policy_integrity_control_unavailable"
POLICY_INTEGRITY_REASON_GUARD_HOME_SYMLINK = "guard_home_symlink"
POLICY_INTEGRITY_REASON_GUARD_DB_SYMLINK = "guard_db_symlink"
POLICY_INTEGRITY_REASON_GUARD_HOME_PERMISSIONS = "guard_home_permissions"
POLICY_INTEGRITY_REASON_GUARD_DB_PERMISSIONS = "guard_db_permissions"
POLICY_INTEGRITY_REASON_GUARD_HOME_INACCESSIBLE = "guard_home_inaccessible"
POLICY_INTEGRITY_REASON_GUARD_DB_INACCESSIBLE = "guard_db_inaccessible"

"""Stable local trust vocabulary shared by Guard runtime and UI APIs."""

from __future__ import annotations

from dataclasses import dataclass, field
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

LOCAL_TRUST_DEGRADED_REASON_LABELS: dict[str, str] = {
    POLICY_INTEGRITY_REASON_SYSTEM_KEYRING_UNAVAILABLE: "System credential store unavailable",
    POLICY_INTEGRITY_REASON_KEY_UNAVAILABLE: "Local rule signing key unavailable",
    POLICY_INTEGRITY_REASON_CONTROL_UNAVAILABLE: "Local rollback control unavailable",
    POLICY_INTEGRITY_REASON_GUARD_HOME_SYMLINK: "Guard home path is not trusted",
    POLICY_INTEGRITY_REASON_GUARD_DB_SYMLINK: "Guard database path is not trusted",
    POLICY_INTEGRITY_REASON_GUARD_HOME_PERMISSIONS: "Guard home permissions are too broad",
    POLICY_INTEGRITY_REASON_GUARD_DB_PERMISSIONS: "Guard database permissions are too broad",
    POLICY_INTEGRITY_REASON_GUARD_HOME_INACCESSIBLE: "Guard home could not be inspected",
    POLICY_INTEGRITY_REASON_GUARD_DB_INACCESSIBLE: "Guard database could not be inspected",
}


@dataclass(frozen=True)
class TrustStatus:
    """User-safe trust summary for runtime, local rules, and Cloud policy authority."""

    runtime_protection: LocalTrustMode
    remembered_rules: LocalTrustMode
    cloud_policies: LocalTrustMode
    backend: str
    degraded_reasons: tuple[str, ...] = field(default_factory=tuple)
    setup_available: bool = False
    last_proof: str | None = None

    @classmethod
    def from_policy_integrity_state(cls, state: dict[str, object]) -> TrustStatus:
        mode = state.get("mode")
        reasons = state.get("degraded_reasons")
        clean_reasons = (
            tuple(reason for reason in reasons if isinstance(reason, str)) if isinstance(reasons, list) else ()
        )
        if mode == POLICY_INTEGRITY_MODE_PROTECTED:
            remembered_rules: LocalTrustMode = "protected"
        elif mode == POLICY_INTEGRITY_MODE_DEGRADED:
            remembered_rules = "degraded_safe"
        else:
            remembered_rules = "unsupported"
        setup_available = bool(state.get("setup_available"))
        if not setup_available:
            setup_available = any(reason in LOCAL_TRUST_DEGRADED_REASON_LABELS for reason in clean_reasons)
        runtime_protection = state.get("runtime_protection")
        cloud_policies = state.get("cloud_policies")
        if mode == POLICY_INTEGRITY_MODE_PROTECTED and runtime_protection not in LOCAL_TRUST_MODES:
            runtime_protection = "protected"
        return cls(
            runtime_protection=runtime_protection if runtime_protection in LOCAL_TRUST_MODES else "unsupported",
            remembered_rules=remembered_rules,
            cloud_policies=cloud_policies if cloud_policies in LOCAL_TRUST_MODES else "unsupported",
            backend=str(state.get("backend") or "unknown"),
            degraded_reasons=clean_reasons,
            setup_available=setup_available,
            last_proof=None,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "runtime_protection": self.runtime_protection,
            "remembered_rules": self.remembered_rules,
            "cloud_policies": self.cloud_policies,
            "backend": self.backend,
            "degraded_reasons": list(self.degraded_reasons),
            "degraded_reason_labels": {
                reason: LOCAL_TRUST_DEGRADED_REASON_LABELS.get(reason, "Guard trust check degraded")
                for reason in self.degraded_reasons
            },
            "setup_available": self.setup_available,
            "last_proof": self.last_proof,
        }

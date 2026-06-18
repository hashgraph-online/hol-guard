"""Stable local trust vocabulary shared by Guard runtime and UI APIs."""

from __future__ import annotations

import json
import multiprocessing
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol, TypeVar, cast

LocalTrustMode = Literal[
    "protected",
    "cloud_authoritative",
    "degraded_safe",
    "setup_required",
    "unsupported",
]
RuntimeProtectionStatus = Literal["protected", "degraded", "unknown"]
RememberedRulesStatus = Literal["enforced", "disabled_degraded", "unknown"]
CloudPoliciesStatus = Literal["available", "setup_unavailable", "unknown"]

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
    "trust_backend_timeout",
    "trust_backend_unavailable",
    "trust_backend_permission_denied",
    "trust_backend_corrupt",
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
POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT = "trust_backend_timeout"
POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE = "trust_backend_unavailable"
POLICY_INTEGRITY_REASON_BACKEND_PERMISSION_DENIED = "trust_backend_permission_denied"
POLICY_INTEGRITY_REASON_BACKEND_CORRUPT = "trust_backend_corrupt"

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
    POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT: "Local trust backend timed out",
    POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE: "Local trust backend unavailable",
    POLICY_INTEGRITY_REASON_BACKEND_PERMISSION_DENIED: "Local trust backend permission denied",
    POLICY_INTEGRITY_REASON_BACKEND_CORRUPT: "Local trust backend data could not be read",
}


class TrustBackend(Protocol):
    """Local trust backend contract for passive and explicit trust operations."""

    name: str
    priority: int
    supported: bool
    passive_no_ui_safe: bool

    def status(self) -> TrustStatus:
        """Return current backend trust status."""

    def sign(self, payload: bytes) -> str:
        """Sign canonical trust payload bytes."""

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify canonical trust payload bytes."""

    def setup(self) -> TrustStatus:
        """Run explicit foreground setup."""

    def revoke(self) -> TrustStatus:
        """Revoke backend trust material."""


_TrustResult = TypeVar("_TrustResult")


def select_trust_backend(
    backends: tuple[TrustBackend, ...],
    *,
    passive: bool,
) -> TrustBackend | None:
    """Select highest-priority supported backend, gating passive use on no-UI safety."""

    candidates = [backend for backend in backends if backend.supported and (not passive or backend.passive_no_ui_safe)]
    if not candidates:
        return None
    return sorted(candidates, key=lambda backend: (-backend.priority, backend.name))[0]


def run_trust_backend_check(
    operation: Callable[[], _TrustResult],
    *,
    timeout_seconds: float,
    timeout_result: _TrustResult,
    on_error: Callable[[BaseException], _TrustResult] | None = None,
) -> _TrustResult:
    """Run side-effect-free passive backend work under a contained timeout."""

    if timeout_seconds <= 0:
        return timeout_result
    try:
        context = multiprocessing.get_context("fork")
    except ValueError:
        return timeout_result
    results = context.Queue(maxsize=1)

    def _worker(result_queue) -> None:
        try:
            result_queue.put((True, operation()))
        except Exception as error:
            result_queue.put((False, error))

    process = context.Process(target=_worker, args=(results,), daemon=True)
    process.start()
    process.join(timeout=timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(timeout=0.2)
        if process.is_alive():
            process.kill()
            process.join(timeout=0.2)
        return timeout_result
    if results.empty():
        if on_error is None:
            return timeout_result
        return on_error(RuntimeError("trust_backend_process_failed"))
    ok, value = results.get()
    if ok:
        return cast("_TrustResult", value)
    if on_error is None:
        return timeout_result
    return on_error(cast("BaseException", value))


def degraded_reason_for_backend_error(error: BaseException) -> str:
    """Normalize backend failures into user-safe degraded reasons."""

    if isinstance(error, TimeoutError):
        return POLICY_INTEGRITY_REASON_BACKEND_TIMEOUT
    if isinstance(error, PermissionError):
        return POLICY_INTEGRITY_REASON_BACKEND_PERMISSION_DENIED
    if isinstance(error, (ValueError, json.JSONDecodeError)):
        return POLICY_INTEGRITY_REASON_BACKEND_CORRUPT
    return POLICY_INTEGRITY_REASON_BACKEND_UNAVAILABLE


@dataclass(frozen=True)
class TrustStatus:
    """User-safe trust summary for runtime, local rules, and Cloud policy authority."""

    runtime_protection: RuntimeProtectionStatus
    remembered_rules: RememberedRulesStatus
    cloud_policies: CloudPoliciesStatus
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
            runtime_protection: RuntimeProtectionStatus = "protected"
            remembered_rules: RememberedRulesStatus = "enforced"
        elif mode == POLICY_INTEGRITY_MODE_DEGRADED:
            runtime_protection = "degraded"
            remembered_rules = "disabled_degraded"
        else:
            runtime_protection = "unknown"
            remembered_rules = "unknown"
        setup_available = bool(state.get("setup_available"))
        if not setup_available:
            setup_available = any(reason in LOCAL_TRUST_DEGRADED_REASON_LABELS for reason in clean_reasons)
        runtime_override = state.get("runtime_protection")
        if runtime_override in ("protected", "degraded", "unknown"):
            runtime_protection = runtime_override
        cloud_override = state.get("cloud_policies")
        if cloud_override in ("available", "setup_unavailable", "unknown"):
            cloud_policies: CloudPoliciesStatus = cloud_override
        elif setup_available:
            cloud_policies = "setup_unavailable"
        else:
            cloud_policies = "available"
        return cls(
            runtime_protection=runtime_protection,
            remembered_rules=remembered_rules,
            cloud_policies=cloud_policies,
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

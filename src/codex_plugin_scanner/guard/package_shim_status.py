"""Package shim audit proof persistence (the manifest write is the resident's ``shim_admin``)."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .native_shim_admin import NativeShimAdminError
from .native_shim_admin import record_package_shim_audit_result as _record_audit


class HarnessContextLike(Protocol):
    @property
    def guard_home(self) -> Path: ...


PACKAGE_SHIM_STATUS_FD_ENV_VAR = "HOL_GUARD_PACKAGE_SHIM_STATUS_FD"


def record_package_shim_audit_result(
    context: HarnessContextLike,
    *,
    audited_at: str | None = None,
) -> dict[str, object]:
    """Stamp the audit time. A refused write is a ``ValueError``.

    An unavailable or overloaded resident, or a manifest that is not strict
    JSON, returns ``audit_proof_recorded`` false and does not discard the
    audit the caller already finished.
    """

    try:
        recorded = _record_audit(context.guard_home, audited_at=audited_at)
    except NativeShimAdminError as error:
        raise ValueError(error.detail or error.code) from error
    if not isinstance(recorded, dict):
        return {"audit_proof_recorded": True}
    return recorded

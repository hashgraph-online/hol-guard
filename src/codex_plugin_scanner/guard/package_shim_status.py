"""Package shim status enrichment and audit proof persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .adapters.base import HarnessContext


def enrich_package_shim_status_payload(
    status: dict[str, object],
    manifest: dict[str, object],
) -> dict[str, object]:
    bypasses = status.get("bypasses", [])
    path_broken_managers = sorted(
        {
            str(entry["manager"])
            for entry in bypasses
            if isinstance(entry, dict) and isinstance(entry.get("manager"), str)
        }
    )
    last_test_at = status.get("last_test_at", {})
    tested_managers = (
        sorted(manager for manager in last_test_at if isinstance(manager, str))
        if isinstance(last_test_at, dict)
        else []
    )
    last_audit_proof_at = manifest.get("last_audit_at")
    normalized_last_audit = last_audit_proof_at if isinstance(last_audit_proof_at, str) else None
    normalized_last_tests = last_test_at if isinstance(last_test_at, dict) else {}

    enriched = dict(status)
    enriched["path_broken_managers"] = path_broken_managers
    enriched["tested_managers"] = tested_managers
    enriched["pathBrokenManagers"] = path_broken_managers
    enriched["testedManagers"] = tested_managers
    enriched["last_intercept_proof_at"] = normalized_last_tests
    enriched["lastInterceptProofAt"] = normalized_last_tests
    enriched["detectedManagers"] = list(status.get("detected_managers", []))
    enriched["protectedManagers"] = list(status.get("protected_managers", []))
    enriched["installedManagers"] = list(status.get("installed_managers", []))
    enriched["activeManagers"] = list(status.get("active_managers", []))
    enriched["missingManagers"] = list(status.get("missing_managers", []))
    enriched["undetectedManagers"] = list(status.get("undetected_managers", []))
    enriched["last_audit_proof_at"] = normalized_last_audit
    enriched["lastAuditProofAt"] = normalized_last_audit
    return enriched


def record_package_shim_audit_result(
    context: HarnessContext,
    *,
    audited_at: str | None = None,
) -> None:
    from .shims import _load_package_shim_manifest, _write_package_shim_manifest

    manifest = _load_package_shim_manifest(context)
    manifest["last_audit_at"] = audited_at if audited_at is not None else datetime.now(timezone.utc).isoformat()
    _write_package_shim_manifest(context, manifest)

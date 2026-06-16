"""Package shim status enrichment and audit proof persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


class HarnessContextLike(Protocol):
    @property
    def guard_home(self) -> Path: ...


_PACKAGE_SHIM_MANIFEST = "manifest.json"


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _package_shim_manifest_path(context: HarnessContextLike) -> Path:
    return context.guard_home / "package-shims" / _PACKAGE_SHIM_MANIFEST


def _load_package_shim_manifest(context: HarnessContextLike) -> dict[str, object]:
    manifest_path = _package_shim_manifest_path(context)
    if not manifest_path.exists():
        return {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_package_shim_manifest(context: HarnessContextLike, payload: dict[str, object]) -> None:
    _package_shim_manifest_path(context).write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def enrich_package_shim_status_payload(
    status: dict[str, object],
    manifest: dict[str, object],
) -> dict[str, object]:
    bypasses = status.get("bypasses", [])
    bypass_entries = bypasses if isinstance(bypasses, list | tuple) else ()
    path_broken_managers = sorted(
        {
            str(entry["manager"])
            for entry in bypass_entries
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
    enriched["detectedManagers"] = _string_list(status.get("detected_managers"))
    enriched["protectedManagers"] = _string_list(status.get("protected_managers"))
    enriched["installedManagers"] = _string_list(status.get("installed_managers"))
    enriched["activeManagers"] = _string_list(status.get("active_managers"))
    enriched["missingManagers"] = _string_list(status.get("missing_managers"))
    enriched["undetectedManagers"] = _string_list(status.get("undetected_managers"))
    enriched["last_audit_proof_at"] = normalized_last_audit
    enriched["lastAuditProofAt"] = normalized_last_audit
    return enriched


def record_package_shim_audit_result(
    context: HarnessContextLike,
    *,
    audited_at: str | None = None,
) -> None:
    manifest = _load_package_shim_manifest(context)
    manifest["last_audit_at"] = audited_at if audited_at is not None else datetime.now(timezone.utc).isoformat()
    _write_package_shim_manifest(context, manifest)

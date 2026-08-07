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
_MAX_RECOVERABLE_SHIM_BYTES = 512 * 1024
_PACKAGE_SHIM_SOURCE_MARKERS = (
    "--package-shim-ui",
    "package_shim_command_requires_guard",
    "from codex_plugin_scanner.guard.package_shim_gate import (",
)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list | tuple):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


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


def _recoverable_package_shim_managers(status: dict[str, object]) -> list[str]:
    """Find orphaned Guard-generated shims without trusting them as protected.

    A missing or truncated manifest must not make an existing Guard shim invisible.
    Recovery is intentionally conservative: only a regular in-directory file with the
    expected manager binding and Guard package-shim source markers is eligible. The
    caller still reports these entries as needing repair so the normal repair path
    rewrites and re-attests them before they can count as protected.
    """

    shim_dir_value = status.get("shim_dir")
    supported_managers = _string_list(status.get("supported_managers"))
    if not isinstance(shim_dir_value, str) or not shim_dir_value.strip() or not supported_managers:
        return []
    try:
        shim_dir = Path(shim_dir_value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return []
    if not shim_dir.is_dir():
        return []

    recovered: list[str] = []
    for manager in supported_managers:
        candidate = shim_dir / manager
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=True)
            if resolved.parent != shim_dir or resolved.stat().st_size > _MAX_RECOVERABLE_SHIM_BYTES:
                continue
            source = resolved.read_text(encoding="utf-8")
        except (OSError, RuntimeError, UnicodeDecodeError):
            continue
        if f"command_name = {manager!r}" not in source:
            continue
        if not all(marker in source for marker in _PACKAGE_SHIM_SOURCE_MARKERS):
            continue
        recovered.append(manager)
    return sorted(set(recovered))


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

    installed_managers = _string_list(status.get("installed_managers"))
    recovered_managers = [
        manager for manager in _recoverable_package_shim_managers(status) if manager not in installed_managers
    ]
    if recovered_managers:
        installed_managers = sorted(set(installed_managers).union(recovered_managers))
        active_managers = sorted(set(_string_list(status.get("active_managers"))).union(recovered_managers))
        manager_details = _dict_list(status.get("manager_details"))
        detailed_managers = {
            str(item.get("manager")) for item in manager_details if isinstance(item.get("manager"), str)
        }
        detected_managers = set(_string_list(status.get("detected_managers")))
        shim_dir = str(status.get("shim_dir") or "")
        for manager in recovered_managers:
            if manager in detailed_managers:
                continue
            manager_details.append(
                {
                    "integrity": "stale",
                    "last_test_at": None,
                    "manager": manager,
                    "path_active": False,
                    "path_index": None,
                    "path_status": {
                        "shim_precedes_real": False,
                        "shim_in_path": bool(status.get("path_contains_shim_dir")),
                        "path_broken": True,
                        "shim_dir": shim_dir,
                    },
                    "real_binary_found": False,
                    "real_binary_path": None,
                    "real_binary_path_index": None,
                    "shim_path": str(Path(shim_dir) / manager) if shim_dir else None,
                    "system_binary_detected": manager in detected_managers,
                    "recovered_without_manifest": True,
                }
            )
        path_contains_shim_dir = bool(status.get("path_contains_shim_dir"))
        shell_profile_configured = bool(status.get("shell_profile_configured"))
        recovered_path_status = str(status.get("path_status") or "missing_from_path")
        process_path_status = str(status.get("process_path_status") or "missing")
        if path_contains_shim_dir:
            recovered_path_status = "in_path"
            process_path_status = "active"
        elif shell_profile_configured:
            recovered_path_status = "restart_required"
            process_path_status = "profile_staged"
        status = {
            **status,
            "active_managers": active_managers,
            "installed_managers": installed_managers,
            "manager_details": manager_details,
            "path_status": recovered_path_status,
            "process_path_status": process_path_status,
            "process_restart_required": recovered_path_status == "restart_required",
            "recovered_managers": recovered_managers,
            "restart_shell_required": recovered_path_status == "restart_required",
        }
        path_broken_managers = sorted(set(path_broken_managers).union(recovered_managers))

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
    recovered_managers = _string_list(status.get("recovered_managers"))
    enriched["recovered_managers"] = recovered_managers
    enriched["recoveredManagers"] = recovered_managers
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

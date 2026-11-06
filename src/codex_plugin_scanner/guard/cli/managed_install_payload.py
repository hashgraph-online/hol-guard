"""Public summaries of recorded native and composite harness installations."""

from __future__ import annotations

from ..adapters.contracts import contract_for


def managed_install_payload(managed_install: dict[str, object]) -> dict[str, object]:
    """Summarize recorded integration ownership without inventing native Paseo hook support."""
    payload = dict(managed_install)
    harness = str(payload.get("harness") or "")
    protection_contract = contract_for(harness)
    if protection_contract is not None:
        payload["native_hooks"] = protection_contract.native_approval
        payload["browser_fallback"] = protection_contract.browser_fallback
        payload["primary_integration"] = "native_hooks" if protection_contract.native_approval else "browser_fallback"
    manifest = payload.get("manifest")
    if isinstance(manifest, dict):
        if manifest.get("mode") == "native-provider-hooks":
            payload["primary_integration"] = "native-provider-hooks"
            payload["coverage_status"] = "limited"
        for key in (
            "config_path",
            "managed_config_path",
            "shim_path",
            "shim_paths",
            "shim_command",
            "shim_commands",
            "mode",
            "surface",
            "surfaces",
        ):
            value = manifest.get(key)
            if value is not None:
                payload[key] = value
    return payload

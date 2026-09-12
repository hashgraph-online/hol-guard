"""Paseo integration through the native runtimes that execute its agent tools."""

from __future__ import annotations

from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext
from .paseo_config import PaseoProvider, paseo_config_path, paseo_providers, require_local_path
from .paseo_install import (
    install_native,
    native_context,
    preflight_native,
    protection_paths,
    provider_status,
    read_receipt,
    receipt_path,
    write_receipt,
)

PASEO_COVERAGE_LIMIT = (
    "Paseo delegates tool execution to native providers. Guard protects supported providers through their native "
    "hooks, not Paseo's permission notifications. Paseo terminals, daemon git/browser actions, plugin code, "
    "custom commands, ACP providers, and other hosts are not covered by this adapter."
)


def _provider_rows(
    providers: tuple[PaseoProvider, ...], context: HarnessContext, receipt: dict[str, object]
) -> list[dict[str, object]]:
    """Combine credential-free provider metadata with verified installation status."""
    return [{**provider.to_dict(), "status": provider_status(provider, context, receipt)} for provider in providers]


class PaseoHarnessAdapter(HarnessAdapter):
    harness = "paseo"
    executable = "paseo"
    approval_summary = "Approvals use each provider's native Guard integration on the Paseo daemon host."
    fallback_hint = "Check the native provider in Guard on the daemon host; Paseo notifications do not enforce policy."

    def policy_path(self, context: HarnessContext) -> Path:
        """Locate the daemon configuration without treating it as a Guard policy file."""
        return paseo_config_path(context)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        """Discover enabled provider identities without exposing their environment values."""
        available = self.resolved_executable(context) is not None
        paths: tuple[str, ...] = ()
        artifacts: tuple[GuardArtifact, ...] = ()
        warnings: tuple[str, ...] = ()
        try:
            path = paseo_config_path(context)
            paths = (str(path),) if path.is_file() else ()
            if paths or available:
                providers = paseo_providers(context)
                artifacts = tuple(
                    GuardArtifact(
                        artifact_id=f"paseo:provider:{provider.provider_id}",
                        name=provider.provider_id,
                        harness=self.harness,
                        artifact_type="agent",
                        source_scope="global",
                        config_path=str(path),
                        metadata=provider.to_dict(),
                    )
                    for provider in providers
                    if provider.enabled
                )
                warnings = (PASEO_COVERAGE_LIMIT,)
        except ValueError as error:
            warnings = (str(error),)
        return HarnessDetection(self.harness, bool(paths) or available, available, paths, artifacts, warnings)

    def install(self, context: HarnessContext) -> dict[str, object]:
        """Install shared native hooks and publish a receipt only after their proofs verify."""
        providers = paseo_providers(context)
        path = receipt_path(context)
        # Reinstall every available supported native provider, including drifted
        # installations. An empty receipt intentionally makes each a fresh target.
        rows = _provider_rows(providers, context, {})
        targets = sorted({str(row["native_harness"]) for row in rows if row["status"] == "not-installed"})
        if not targets:
            raise ValueError(
                "No supported, enabled Paseo provider runtime was found. Install a native provider on the daemon "
                "host and remove custom command/config-home overrides, then run hol-guard install paseo again."
            )
        # Preflight all known write targets before touching shared native settings.
        for target in targets:
            preflight_native(target, context)
        for shim in self.guard_launcher_paths(native_context(context)):
            require_local_path(context.guard_home, shim, home_dir=context.home_dir)
        # Keep the last verified receipt until atomic replacement succeeds.
        proofs: dict[str, object] = {}
        for target in targets:
            proofs[target] = install_native(target, context)
        if paseo_providers(context) != providers:
            raise ValueError("Paseo providers changed during installation; rerun hol-guard install paseo.")
        for shim in self.guard_launcher_paths(native_context(context)):
            require_local_path(context.guard_home, shim, home_dir=context.home_dir)
        shim_manifest = install_guard_shim(self.harness, native_context(context))
        receipt = write_receipt(context, proofs)
        return {
            **shim_manifest,
            "harness": self.harness,
            "active": True,
            "config_path": str(path),
            "mode": "native-provider-hooks",
            "coverage_status": "limited",
            "cloud_inventory_status": "native-providers-only",
            "runtime_verification": "not-performed",
            "providers": _provider_rows(providers, context, receipt),
            "protection_artifact_paths": protection_paths(receipt),
            "notes": [
                PASEO_COVERAGE_LIMIT,
                "Start new provider sessions after installation. Existing sessions may retain old hooks.",
                "Paseo configuration, provider commands, credentials, models, and permissions were not changed.",
                "Native hooks are shared with other clients and remain installed when Paseo support is removed.",
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        """Remove Paseo-owned artifacts without disabling other clients' shared native hooks."""
        receipt_path(context).unlink(missing_ok=True)
        return {
            **remove_guard_shim(self.harness, context),
            "harness": self.harness,
            "active": False,
            "notes": [
                "Removed Paseo's installation receipt and launcher. Shared native Guard hooks were left intact.",
                "Use hol-guard uninstall <native-harness> separately to remove native protection for all clients.",
            ],
        }

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        """Report current per-provider coverage and installation drift without claiming live execution."""
        payload = super().diagnostics(context)
        try:
            receipt = read_receipt(context)
            rows = _provider_rows(paseo_providers(context), context, receipt)
            installed = any(row["status"] == "native-hooks-installed" for row in rows)
            changed = any(row["status"] == "changed" for row in rows)
            incomplete = any(row["status"] in {"not-installed", "runtime-unavailable"} for row in rows)
            found = payload.get("installed") or payload.get("config_paths")
            if changed:
                status = "broken"
            elif installed and not incomplete:
                status = "active"
            elif found:
                status = "partial"
            else:
                status = "not_found"
            payload.update(
                {
                    "setup_status": status,
                    "providers": rows,
                    "coverage_status": "limited",
                    "cloud_inventory_status": "native-providers-only",
                    "runtime_verification": "not-performed",
                }
            )
        except (OSError, ValueError) as error:
            payload.update({"setup_status": "broken", "providers": [], "warnings": [str(error), PASEO_COVERAGE_LIMIT]})
        return payload

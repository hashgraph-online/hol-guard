from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore


def _description_only_catalog_upgrade() -> CommandSafetyExtensionRegistry:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    return CommandSafetyExtensionRegistry(
        (replace(extensions[0], description=f"{extensions[0].description} Updated."), *extensions[1:])
    )


def test_clear_migrates_catalog_before_publishing_runtime_view(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    upgraded = _description_only_catalog_upgrade()
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=None,
    )
    migrated = store.read_extension_control_authority_for_registry(upgraded)
    runtime = ExtensionControlRuntime(migrated)

    store.clear_policy_bundle_authority(
        "2026-08-23T12:03:00Z",
        policy_bundle_last_error={"reason": "catalog-drift"},
        managed_controls_publish=runtime.publish_after_commit,
    )

    assert runtime.current().health is AuthorityHealth.PROTECTED
    assert runtime.current().catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert (
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health
        is AuthorityHealth.PROTECTED
    )

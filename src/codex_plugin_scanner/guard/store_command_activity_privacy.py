"""Atomic deletion and bounded diagnostics for command activity evidence.

Deletion and the diagnostics snapshot run in the native resident. Python
supplies the allowlists it owns (stable ids, proof levels, error classes) and
stamps the schema versions.
"""

# pyright: reportAny=false, reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final, Protocol, cast

from .runtime.command_activity_api_contract import COMMAND_ACTIVITY_API_SCHEMA_VERSION
from .runtime.command_activity_contract import (
    COMMAND_ACTIVITY_HARNESSES,
    COMMAND_ACTIVITY_SCHEMA_VERSION,
    CommandProofLevel,
)
from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .runtime.command_shadow_evaluation import COMMAND_SHADOW_SCHEMA_VERSION
from .store_command_activity_health_schema import COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION
from .store_command_activity_maintenance_schema import COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION

COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION: Final = "guard.command-activity-diagnostics.v1"
_ALLOWED_ERROR_CLASSES: Final = (
    "cursor_observer_verify_failed",
    "maintenance_failed",
    "post_record_failed",
    "pre_record_failed",
    "shadow_evaluation_failed",
)


class _NativeOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


def _allowlists() -> dict[str, object]:
    extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    return {
        "harnesses": sorted(COMMAND_ACTIVITY_HARNESSES),
        "extension_ids": sorted({extension.extension_id for extension in extensions}),
        "rule_ids": sorted({rule.rule_id for extension in extensions for rule in extension.rules}),
        "proof_levels": [level.value for level in CommandProofLevel],
        "error_classes": list(_ALLOWED_ERROR_CLASSES),
    }


class StoreCommandActivityPrivacyMixin:
    def clear_command_activity_evidence(self: _NativeOwner) -> dict[str, object]:
        """Delete command evidence and derived state in one immediate transaction."""

        payload = self._native_store_call("clear_command_activity_evidence", {})
        return {"schema_version": COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION, **cast(dict[str, object], payload)}

    def command_activity_diagnostics(self: _NativeOwner) -> dict[str, object]:
        """Return an allowlisted snapshot without command or opaque identity data."""

        payload = self._native_store_call("command_activity_diagnostics", _allowlists())
        return {
            "schema_version": COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
            "schemas": {
                "activity": COMMAND_ACTIVITY_SCHEMA_VERSION,
                "api": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
                "health": COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION,
                "maintenance": COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION,
                "shadow": COMMAND_SHADOW_SCHEMA_VERSION,
            },
            **cast(dict[str, object], payload),
        }


__all__ = (
    "COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION",
    "StoreCommandActivityPrivacyMixin",
)

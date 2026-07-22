"""HOL Guard persistent tray icon package.

Provides a cross-platform system-tray/menu-bar icon that opens the local
Guard dashboard without requiring terminal knowledge. The tray is a
convenience surface only — it never controls Guard protection, policy
enforcement, or hook execution.
"""

from __future__ import annotations

from .contracts import (
    LOCATOR_SCHEMA_VERSION,
    TrayBackend,
    TrayCapability,
    TrayLifecycleResult,
    TrayPlatform,
    TrayProcessIdentity,
    TrayReasonCode,
    TrayRegistration,
    TrayState,
    TrayStatus,
)

__all__ = [
    "LOCATOR_SCHEMA_VERSION",
    "TrayBackend",
    "TrayCapability",
    "TrayLifecycleResult",
    "TrayPlatform",
    "TrayProcessIdentity",
    "TrayReasonCode",
    "TrayRegistration",
    "TrayState",
    "TrayStatus",
]

"""Containment identifiers shared with the native contained runner."""

from __future__ import annotations

from enum import Enum
from typing import Final

CONTAINMENT_SCHEMA_VERSION: Final = "guard.containment.v1"
CONTAINMENT_POLICY_VERSION: Final = "guard.containment-policy.v1"


class ContainmentBackend(str, Enum):
    UNSUPPORTED = "unsupported"
    MACOS_SANDBOX = "macos-sandbox"
    LINUX_BWRAP = "linux-bwrap"


__all__ = (
    "CONTAINMENT_POLICY_VERSION",
    "CONTAINMENT_SCHEMA_VERSION",
    "ContainmentBackend",
)

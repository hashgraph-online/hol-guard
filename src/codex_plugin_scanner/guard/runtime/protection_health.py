"""The shapes a protection-health signal is collected in.

Which statuses add up to a protected machine, which failures are a platform
with no such check, and the words an operator reads for each state belong to
the native runtime (`guard_command::protection_health`), reached through
`native_protection_health`. Nothing here evaluates a signal; these types only
carry one from the producer that measured it to the request that asks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final

PROTECTION_CHECK_IDS: Final = (
    "harness_hooks",
    "daemon",
    "policy_engine",
    "rule_packs",
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
    "decision_stream",
    "tamper_checks",
)
_STABLE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


class ProtectionCheckStatus(str, Enum):
    PASS = "pass"
    UNKNOWN = "unknown"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class ProtectionSignal:
    status: ProtectionCheckStatus
    reason_code: str

    def __post_init__(self) -> None:
        # A free-form reason would reach the resident as a malformed request;
        # refusing it here names the producer that built it instead.
        if not _STABLE_ID.fullmatch(self.reason_code):
            raise ValueError("protection signal reason_code must be a stable identifier")


__all__ = (
    "PROTECTION_CHECK_IDS",
    "ProtectionCheckStatus",
    "ProtectionSignal",
)

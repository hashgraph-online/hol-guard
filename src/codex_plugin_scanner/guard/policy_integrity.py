"""Local policy row integrity vocabulary.

The resident ``policy_integrity_rows`` op computes every canonical payload,
digest and MAC; see ``native_policy_integrity_rows``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

POLICY_INTEGRITY_VERSION = 2
REMOTE_POLICY_SOURCES = frozenset(
    {"cloud-sync", "team-policy", "policy-bundle", "policy-bundle-canonical", "cloud-signed-memory"}
)

PolicyIntegrityStatus = Literal[
    "valid",
    "missing_integrity",
    "tampered",
    "unknown_key",
    "rollback_detected",
    "degraded_mode",
]


@dataclass(frozen=True, slots=True)
class PolicyIntegrityVerificationResult:
    status: PolicyIntegrityStatus
    payload_hash: str | None = None
    key_id: str | None = None
    message: str | None = None


def is_remote_policy_source(source: str | None) -> bool:
    return isinstance(source, str) and source in REMOTE_POLICY_SOURCES

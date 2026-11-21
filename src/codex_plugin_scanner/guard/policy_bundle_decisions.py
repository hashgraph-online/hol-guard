"""Canonical materialization of signed policy-bundle rules.

Rust owns rule scope matching, exact-representability checks and the decision
rows a bundle authorizes. This module only encodes the request and builds the
persisted ``PolicyDecision`` records from the returned rows. Rows are fetched in
bounded pages because a small bundle can expand to more rows than one resident
response may carry.
"""

from __future__ import annotations

from .models import PolicyDecision
from .native_policy_bundle import (
    PolicyBundleNativeUnavailableError,
    policy_bundle_chunks,
    policy_bundle_paged_rows,
    policy_bundle_verdict,
)


def policy_bundle_rule_saved_decision_families(rule: dict[str, object]) -> list[str]:
    """Return rule families that can be represented without broadening scope."""

    families = policy_bundle_verdict("saved_families", {"rule": rule}).get("families")
    if not isinstance(families, list) or not all(isinstance(family, str) for family in families):
        raise PolicyBundleNativeUnavailableError("native_policy_bundle_authority_schema_mismatch")
    return list(families)


def build_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    """Materialize the exact persisted decisions authorized by a policy bundle."""

    rows = policy_bundle_paged_rows(
        "build_decisions",
        {"bundle_chunks": policy_bundle_chunks(policy_bundle), "device_id": device_id, "device_name": device_name},
    )
    return [PolicyDecision(**row) for row in rows]

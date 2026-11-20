from __future__ import annotations

from tests.managed_controls.capabilities import (
    MANAGED_CONTROL_CAPABILITIES,
)
from tests.managed_controls.compatibility import (
    CompatibilityState,
    DeviceCompatibility,
    evaluate_compatibility,
)
from tests.managed_controls.migration import (
    map_legacy_rule,
    preserve_legacy_policy_document,
)


def test_unsupported_client_is_excluded_not_silently_downgraded() -> None:
    device = DeviceCompatibility(frozenset(), "catalog", 1)
    assert evaluate_compatibility(device, required_catalog_digest="catalog") is CompatibilityState.MISSING_CAPABILITY


def test_exact_catalog_is_compatible() -> None:
    device = DeviceCompatibility(MANAGED_CONTROL_CAPABILITIES, "catalog", 1)
    assert evaluate_compatibility(device, required_catalog_digest="catalog") is CompatibilityState.COMPATIBLE


def test_control_schema_must_match() -> None:
    device = DeviceCompatibility(MANAGED_CONTROL_CAPABILITIES, "catalog", 1, 2)
    assert evaluate_compatibility(device, required_catalog_digest="catalog") is CompatibilityState.SCHEMA_UNSUPPORTED


def test_unmapped_legacy_rule_remains_advanced_without_data_loss() -> None:
    mapping = map_legacy_rule("legacy", known_permission=None)
    assert mapping.advanced_raw_rule
    document = {"kind": "GuardPolicy", "spec": {"rules": []}}
    assert preserve_legacy_policy_document(document) == document

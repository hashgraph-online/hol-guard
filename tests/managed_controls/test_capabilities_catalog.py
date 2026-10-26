from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.capabilities import (
    MANAGED_CONTROL_CAPABILITIES,
    CapabilityNegotiationError,
    RuntimeCapabilityAdvertisement,
)


def test_requires_all_four_capabilities() -> None:
    advertisement = RuntimeCapabilityAdvertisement(MANAGED_CONTROL_CAPABILITIES)
    assert advertisement.supports_managed_controls
    advertisement.require(MANAGED_CONTROL_CAPABILITIES)
    with pytest.raises(CapabilityNegotiationError):
        RuntimeCapabilityAdvertisement(frozenset()).require(MANAGED_CONTROL_CAPABILITIES)


def test_capability_advertisement_deduplicates_strings() -> None:
    advertisement = RuntimeCapabilityAdvertisement.from_values(["extension-catalog.v1", "extension-catalog.v1"])
    assert advertisement.capabilities == frozenset({"extension-catalog.v1"})


@pytest.mark.parametrize(
    ("values", "catalog_version", "control_version"),
    [
        (["extension-catalog.v1", 1], 1, 1),
        (["extension-catalog.v1"], 0, 1),
        (["extension-catalog.v1"], 1, -1),
        (["extension-catalog.v1"], True, 1),
    ],
)
def test_invalid_capability_advertisement_fails_closed(
    values: object,
    catalog_version: object,
    control_version: object,
) -> None:
    with pytest.raises(CapabilityNegotiationError):
        RuntimeCapabilityAdvertisement.from_values(
            values,
            catalog_schema_version=catalog_version,  # type: ignore[arg-type]
            extension_control_schema_version=control_version,  # type: ignore[arg-type]
        )

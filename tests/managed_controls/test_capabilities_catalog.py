from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.capabilities import (
    MANAGED_CONTROL_CAPABILITIES,
    CapabilityNegotiationError,
    RuntimeCapabilityAdvertisement,
)
from codex_plugin_scanner.guard.managed_controls.catalog import (
    CatalogExtension,
    CatalogPermission,
    CatalogProjection,
    CatalogValidationError,
)


def _catalog() -> CatalogProjection:
    permission = CatalogPermission(
        "command.git.permission.push",
        "Push",
        configurable=True,
    )
    extension = CatalogExtension("command.git", "Git", "1", (permission,))
    return CatalogProjection(1, (extension,))


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


def test_catalog_identity_and_digest_are_deterministic() -> None:
    catalog = _catalog()
    assert len(catalog.digest) == 64
    assert catalog.permission(
        "command.git",
        "command.git.permission.push",
    ).configurable
    assert catalog.digest == _catalog().digest


def test_catalog_digest_canonicalizes_permission_order() -> None:
    first = CatalogPermission(
        "command.git.permission.clone",
        "Clone",
        configurable=True,
    )
    second = CatalogPermission(
        "command.git.permission.push",
        "Push",
        configurable=True,
    )
    forward = CatalogProjection(
        1,
        (CatalogExtension("command.git", "Git", "1", (first, second)),),
    )
    reverse = CatalogProjection(
        1,
        (CatalogExtension("command.git", "Git", "1", (second, first)),),
    )
    assert forward.canonical_bytes() == reverse.canonical_bytes()
    assert forward.digest == reverse.digest


@pytest.mark.parametrize(
    "factory",
    [
        lambda: CatalogPermission(1, "Push", configurable=True),
        lambda: CatalogPermission(
            "command.git.permission.push",
            None,
            configurable=True,
        ),
        lambda: CatalogExtension("command.git", None, "1", ()),
        lambda: CatalogExtension("command.git", "Git", None, ()),
    ],
)
def test_non_string_catalog_fields_fail_with_bounded_error(factory: object) -> None:
    with pytest.raises(CatalogValidationError):
        factory()  # type: ignore[operator]


def test_unknown_targets_fail_instead_of_disappearing() -> None:
    with pytest.raises(CatalogValidationError, match="unknown permission"):
        _catalog().permission("command.git", "missing")
    with pytest.raises(CatalogValidationError, match="unknown extension"):
        _catalog().permission(
            "command.missing",
            "command.missing.permission.push",
        )


def test_catalog_poisoning_changes_digest_and_duplicate_permission_ids_fail_closed() -> None:
    original = _catalog()
    poisoned = CatalogProjection(
        1,
        (
            CatalogExtension(
                "command.git",
                "Git (poisoned label)",
                "1",
                original.extensions[0].permissions,
            ),
        ),
    )
    assert poisoned.digest != original.digest

    colliding_permission = CatalogPermission(
        "command.git.permission.push",
        "Impersonated push",
        configurable=False,
    )
    with pytest.raises(CatalogValidationError, match="permission owner mismatch"):
        CatalogProjection(
            1,
            (
                original.extensions[0],
                CatalogExtension(
                    "command.other",
                    "Other",
                    "1",
                    (colliding_permission,),
                ),
            ),
        )

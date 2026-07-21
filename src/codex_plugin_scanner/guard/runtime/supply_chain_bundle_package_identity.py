"""Canonical identity validation for supply-chain bundle packages."""

from __future__ import annotations

from typing import Protocol, TypeVar

from .supply_chain_bundle_base import SupplyChainBundleMalformedError
from .supply_chain_package_identity import PackageIdentityError, canonical_package_identity


class _BundlePackage(Protocol):
    @property
    def ecosystem(self) -> str: ...

    @property
    def namespace(self) -> str | None: ...

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...


_BundlePackageT = TypeVar("_BundlePackageT", bound=_BundlePackage)


def _deduplicate_bundle_packages(
    packages: tuple[_BundlePackageT, ...],
) -> tuple[_BundlePackageT, ...]:
    """Deduplicate exact records and reject order-dependent canonical collisions."""

    by_identity: dict[object, _BundlePackageT] = {}
    ordered: list[_BundlePackageT] = []
    for package in packages:
        try:
            identity = canonical_package_identity(
                ecosystem=package.ecosystem,
                namespace=package.namespace,
                name=package.name,
                version=package.version,
            )
        except PackageIdentityError as error:
            raise SupplyChainBundleMalformedError(f"Invalid package identity: {error}") from error
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = package
            ordered.append(package)
            continue
        if existing != package:
            raise SupplyChainBundleMalformedError(
                f"Conflicting package records for canonical identity {identity.display}"
            )
    return tuple(ordered)

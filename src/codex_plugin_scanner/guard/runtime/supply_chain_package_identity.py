"""Canonical identities for supply-chain package records and targets."""

from __future__ import annotations

import re
from dataclasses import dataclass

_LOWERCASE_ECOSYSTEMS = frozenset({"npm", "packagist", "pypi"})


class PackageIdentityError(ValueError):
    """Raised when package identity fields cannot form one canonical key."""


@dataclass(frozen=True, order=True, slots=True)
class CanonicalPackageIdentity:
    """A collision-free ecosystem, namespace, leaf-name, and version key."""

    ecosystem: str
    namespace: str | None
    name: str
    version: str

    @property
    def qualified_name(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace is not None else self.name

    @property
    def display(self) -> str:
        return f"{self.ecosystem}:{self.qualified_name}@{self.version}"


def normalize_ecosystem(ecosystem: str) -> str:
    """Normalize the ecosystem identifier, which is an enum-like field."""

    normalized = ecosystem.strip().lower()
    if not normalized:
        raise PackageIdentityError("Package ecosystem cannot be empty")
    return normalized


def normalize_package_component(ecosystem: str, value: str) -> str:
    """Normalize one name component according to its ecosystem's rules."""

    normalized_ecosystem = normalize_ecosystem(ecosystem)
    normalized = value.strip()
    if not normalized:
        raise PackageIdentityError("Package name components cannot be empty")
    if normalized_ecosystem in _LOWERCASE_ECOSYSTEMS:
        normalized = normalized.lower()
    if normalized_ecosystem == "pypi":
        normalized = re.sub(r"[-_.]+", "-", normalized)
    return normalized


def canonical_package_identity(
    *,
    ecosystem: str,
    namespace: str | None,
    name: str,
    version: str,
) -> CanonicalPackageIdentity:
    """Build a canonical key from already structured bundle fields."""

    normalized_ecosystem = normalize_ecosystem(ecosystem)
    normalized_version = version.strip()
    if not normalized_version:
        raise PackageIdentityError("Package version cannot be empty")
    normalized_namespace = (
        normalize_package_component(normalized_ecosystem, namespace) if namespace is not None else None
    )
    normalized_name = normalize_package_component(normalized_ecosystem, name)
    if normalized_ecosystem == "npm":
        if normalized_namespace is not None and (
            not normalized_namespace.startswith("@") or normalized_namespace == "@" or "/" in normalized_namespace
        ):
            raise PackageIdentityError("npm namespace must be one non-empty @scope")
        if normalized_name.startswith("@") or "/" in normalized_name:
            raise PackageIdentityError("npm name must be an unqualified leaf name")
    elif normalized_ecosystem == "pypi":
        if normalized_namespace is not None or "/" in normalized_name:
            raise PackageIdentityError("PyPI package identities cannot contain a namespace")
    elif normalized_ecosystem == "packagist":
        if normalized_namespace is None or "/" in normalized_namespace or "/" in normalized_name:
            raise PackageIdentityError("Packagist identity must contain vendor and package components")
    return CanonicalPackageIdentity(
        ecosystem=normalized_ecosystem,
        namespace=normalized_namespace,
        name=normalized_name,
        version=normalized_version,
    )


def parse_package_identity(*, ecosystem: str, package_name: str, version: str) -> CanonicalPackageIdentity:
    """Parse one target name using only the selected ecosystem's syntax."""

    normalized_ecosystem = normalize_ecosystem(ecosystem)
    value = package_name.strip()
    if not value:
        raise PackageIdentityError("Package name cannot be empty")
    namespace: str | None = None
    name = value
    if normalized_ecosystem == "npm":
        if value.startswith("@"):
            if value.count("/") != 1:
                raise PackageIdentityError("Scoped npm name must be exactly @scope/name")
            namespace, name = value.split("/", 1)
        elif "/" in value:
            raise PackageIdentityError("Unscoped npm name cannot contain a slash")
    elif normalized_ecosystem == "packagist":
        if value.count("/") != 1:
            raise PackageIdentityError("Packagist name must be exactly vendor/package")
        namespace, name = value.split("/", 1)
    return canonical_package_identity(
        ecosystem=normalized_ecosystem,
        namespace=namespace,
        name=name,
        version=version,
    )


def normalize_qualified_package_name(ecosystem: str, package_name: str) -> str:
    """Return a versionless qualified name without erasing scope boundaries."""

    identity = parse_package_identity(ecosystem=ecosystem, package_name=package_name, version="*")
    return identity.qualified_name


__all__ = [
    "CanonicalPackageIdentity",
    "PackageIdentityError",
    "canonical_package_identity",
    "normalize_ecosystem",
    "normalize_package_component",
    "normalize_qualified_package_name",
    "parse_package_identity",
]

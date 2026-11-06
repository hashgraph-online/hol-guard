"""Ecosystem adapter APIs."""

from .detect import detect_packages
from .registry import get_default_adapters, list_supported_ecosystems, resolve_ecosystem
from .types import Ecosystem, NormalizedPackage, PackageCandidate

__all__ = [
    "Ecosystem",
    "NormalizedPackage",
    "PackageCandidate",
    "detect_packages",
    "get_default_adapters",
    "list_supported_ecosystems",
    "resolve_ecosystem",
]

"""Adapter protocol for ecosystem-specific scanners."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .types import Ecosystem, NormalizedPackage, PackageCandidate


class EcosystemAdapter(Protocol):
    """Contract implemented by ecosystem adapters."""

    ecosystem_id: Ecosystem

    def detect(self, root: Path) -> list[PackageCandidate]:
        """Detect package candidates for this ecosystem."""

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        """Parse a detected package candidate into normalized form."""

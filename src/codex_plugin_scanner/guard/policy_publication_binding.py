"""Captured publication identity for self-attested execution receipts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_FIELDS = frozenset({"bundleVersion", "bundleHash", "installationId"})


@dataclass(frozen=True, slots=True)
class PolicyPublicationBinding:
    bundle_version: int
    bundle_hash: str
    installation_id: str

    def __post_init__(self) -> None:
        if type(self.bundle_version) is not int or self.bundle_version < 1:
            raise ValueError("publication version must be a positive integer")
        if not isinstance(self.bundle_hash, str) or _DIGEST.fullmatch(self.bundle_hash) is None:
            raise ValueError("publication digest must be canonical SHA-256")
        if not isinstance(self.installation_id, str) or _IDENTIFIER.fullmatch(self.installation_id) is None:
            raise ValueError("installation identity must be a bounded identifier")

    def to_dict(self) -> dict[str, object]:
        return {
            "bundleVersion": self.bundle_version,
            "bundleHash": self.bundle_hash,
            "installationId": self.installation_id,
        }

    @classmethod
    def from_mapping(cls, value: object) -> PolicyPublicationBinding | None:
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            return None
        version, digest, installation = (value.get(key) for key in ("bundleVersion", "bundleHash", "installationId"))
        if type(version) is not int or not isinstance(digest, str) or not isinstance(installation, str):
            return None
        try:
            return cls(version, digest, installation)
        except ValueError:
            return None

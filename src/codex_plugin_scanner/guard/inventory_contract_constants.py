"""Shared inventory redaction, capability, and wire-format constants."""

from __future__ import annotations

import re

from .path_security import path_has_symlink_component

_SENSITIVE_KEY_RE = re.compile(
    r"(auth|authorization|bearer|token|secret|password|credential|api[^a-z0-9]?key)",
    re.IGNORECASE,
)

# ``evidenceAuthority`` names who vouches for trust evidence (``device_claim``
# from a local install). It is not a credential, and Guard Cloud rejects a
# snapshot that masks it. Only this exact key is exempt.
_NON_SECRET_KEY = "evidenceauthority"


def _is_sensitive_key(key: str) -> bool:
    """Whether a metadata key names a credential and its value must be masked."""
    if key.isascii() and key.lower() == _NON_SECRET_KEY:
        return False
    return _SENSITIVE_KEY_RE.search(key) is not None


_SENSITIVE_VALUE_RE = re.compile(r"(?i)(gh[pousr]_[a-z0-9_]+|sk-[a-z0-9_-]+|guard_live_[a-z0-9_-]+|bearer\s+\S+)")


_SERIALIZER_REDACTED_VALUE = "[REDACTED]"


_SAFE_SERIALIZED_MARKERS = frozenset(
    {
        _SERIALIZER_REDACTED_VALUE,
        "present_redacted",
        "present",
        "redacted",
        "malformed_url_redacted",
    }
)


_WHITESPACE_RE = re.compile(r"\s+")


_AIBOM_METADATA_KEYS = (
    "instructionRole",
    "localSecurity",
    "registryIdentity",
    "skillDirectoryIdentity",
    "sourceLinks",
    "sourceOfTruth",
    "trustLayers",
    "trustResolution",
    "unverifiedAdapterEvidence",
    "versionInfo",
)


_INVENTORY_DATETIME_KEYS = frozenset(
    {
        "capturedAt",
        "completedAt",
        "firstSeenAt",
        "generatedAt",
        "lastSeenAt",
        "startedAt",
    }
)


_FREE_FORM_RECORD_KEYS = frozenset({"metadata", "evidence"})


_OPTIONAL_ONLY_CONTRACT_KEYS = frozenset({"summary"})


_path_has_symlink_component = path_has_symlink_component

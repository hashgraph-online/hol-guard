#!/usr/bin/env python3
"""The core metadata versions the publishing toolchain can actually read."""

from __future__ import annotations

# PyPI's upload check parses core metadata with a pinned ``packaging`` release.
# A build backend that declares a version past the newest one that release
# knows produces a distribution nothing can upload, so a release artifact is
# rejected while it is still ours to rebuild.  The comparison is on the exact
# declared string rather than a parsed version, because PEP 440 normalization
# accepts strings that are no core metadata version at all: ``2.4.0`` compares
# equal to 2.4 and ``2.4.dev1`` compares below it.
SUPPORTED_CORE_METADATA_VERSIONS: frozenset[str] = frozenset({"1.0", "1.1", "1.2", "2.1", "2.2", "2.3", "2.4"})
NEWEST_SUPPORTED_CORE_METADATA_VERSION = "2.4"


def declared_core_metadata_versions(metadata: str) -> list[str]:
    """Return every ``Metadata-Version`` the header declares, in order."""

    declared: list[str] = []
    for line in metadata.splitlines():
        if not line.strip():
            # The header ends at the first blank line; the description follows.
            break
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "metadata-version":
            declared.append(value.strip())
    return declared


def core_metadata_version_error(metadata: str, *, label: str) -> str | None:
    """Return why ``metadata`` cannot be published, or ``None`` when it can."""

    versions = declared_core_metadata_versions(metadata)
    if not versions:
        return f"{label} declares no core metadata version"
    if len(versions) > 1:
        # A parser that reads the last header would see a different version
        # than one that reads the first, so neither answer can be trusted.
        return f"{label} declares more than one core metadata version: {', '.join(repr(v) for v in versions)}"
    declared = versions[0]
    if declared not in SUPPORTED_CORE_METADATA_VERSIONS:
        return (
            f"{label} declares core metadata {declared!r}, which the publishing toolchain "
            f"cannot upload; {NEWEST_SUPPORTED_CORE_METADATA_VERSION} is the newest it accepts"
        )
    return None

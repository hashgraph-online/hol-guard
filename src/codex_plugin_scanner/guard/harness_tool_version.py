"""Read an AI tool's own version from what its adapter already detected.

Adapters that find a host application (for example the Cline CLI or its VS Code
extension) record the version on a ``harness_host`` artifact. This module reads
that value without running any external command, so it is safe to call on every
sync. Adapters that detect no host version report ``None``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

_HOST_ARTIFACT_TYPE = "harness_host"
_MAX_VERSION_LENGTH = 64
_VERSION_PATTERN = re.compile(r"^[0-9][0-9A-Za-z.+_-]*$")


def _field(artifact: object, name: str) -> object:
    if isinstance(artifact, Mapping):
        return artifact.get(name)
    return getattr(artifact, name, None)


def _clean_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > _MAX_VERSION_LENGTH or not _VERSION_PATTERN.match(text):
        return None
    return text


def tool_version_from_artifacts(artifacts: Iterable[object]) -> str | None:
    """Return the first host version found on ``harness_host`` artifacts.

    Accepts artifact objects or their serialized dictionaries. ``"unknown"`` and
    other non-version text are ignored.
    """

    for artifact in artifacts:
        if _field(artifact, "artifact_type") != _HOST_ARTIFACT_TYPE:
            continue
        metadata = _field(artifact, "metadata")
        if not isinstance(metadata, Mapping):
            continue
        version = _clean_version(metadata.get("version"))
        if version is not None:
            return version
    return None


def tool_version_from_detection(detection: object) -> str | None:
    """Return the host version for a ``HarnessDetection``, or ``None``."""

    artifacts = getattr(detection, "artifacts", ())
    return tool_version_from_artifacts(artifacts if isinstance(artifacts, Iterable) else ())


__all__ = ["tool_version_from_artifacts", "tool_version_from_detection"]

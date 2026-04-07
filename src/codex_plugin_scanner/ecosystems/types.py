"""Core ecosystem detection and normalization types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Ecosystem(str, Enum):
    """Supported plugin ecosystems."""

    CODEX = "codex"
    CLAUDE = "claude"
    GEMINI = "gemini"
    OPENCODE = "opencode"


@dataclass(frozen=True, slots=True)
class PackageCandidate:
    """A detected package candidate before parsing."""

    ecosystem: Ecosystem
    package_kind: str
    root_path: Path
    manifest_path: Path | None = None
    detection_reason: str = ""


@dataclass(frozen=True, slots=True)
class NormalizedPackage:
    """Normalized package representation used by the scanner pipeline."""

    ecosystem: Ecosystem
    package_kind: str
    root_path: Path
    manifest_path: Path | None = None
    name: str | None = None
    version: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    components: dict[str, tuple[str, ...]] = field(default_factory=dict)
    policies: dict[str, str] = field(default_factory=dict)
    raw_manifest: dict[str, object] = field(default_factory=dict)
    manifest_parse_error: bool = False
    manifest_parse_error_reason: str | None = None

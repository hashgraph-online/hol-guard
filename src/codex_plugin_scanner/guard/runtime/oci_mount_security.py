"""Shared fail-closed normalization for OCI bind-mount sources."""

from __future__ import annotations

import posixpath
from pathlib import Path


def resolve_oci_bundle_root(bundle_root: object) -> Path | None:
    """Return an existing authoritative bundle directory."""

    if bundle_root is None:
        return None
    if not isinstance(bundle_root, (str, Path)):
        raise ValueError("OCI bundle_root must be a string or Path")
    try:
        resolved_root = Path(bundle_root).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("OCI bundle_root must resolve to an existing directory") from error
    if not resolved_root.is_dir():
        raise ValueError("OCI bundle_root must resolve to an existing directory")
    return resolved_root


def normalize_oci_bind_source(source: str) -> tuple[str, bool]:
    """Return a lexical POSIX path and whether it escapes a bundle-relative root."""
    normalized = posixpath.normpath(source)
    if source.startswith("/"):
        normalized = "/" + normalized.lstrip("/")
    escapes_bundle = not source.startswith("/") and (normalized == ".." or normalized.startswith("../"))
    return normalized, escapes_bundle


def require_oci_bundle_relative_path(source: str, *, label: str) -> str:
    """Validate and normalize an OCI path that must remain bundle-relative."""

    normalized, escapes_bundle = normalize_oci_bind_source(source)
    if not source or source.startswith("/") or normalized in ("", ".") or escapes_bundle:
        raise ValueError(f"{label} must be a non-empty bundle-relative path without parent traversal")
    return normalized

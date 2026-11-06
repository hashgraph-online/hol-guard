"""Shared fail-closed normalization for OCI bind-mount sources."""

from __future__ import annotations

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

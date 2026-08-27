"""Shared fail-closed normalization for OCI bind-mount sources."""

from __future__ import annotations

import posixpath
from collections.abc import Collection
from pathlib import Path, PurePosixPath


def is_oci_bind_mount(mount_type: str, options: Collection[str]) -> bool:
    """Recognize runtime-spec bind semantics in type and mount options."""
    return mount_type == "bind" or "bind" in options or "rbind" in options


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


def resolve_oci_bundle_path(
    source: str,
    *,
    bundle_root: str | Path | None,
    label: str,
    require_directory: bool = False,
) -> str:
    """Resolve a bundle-relative path and prove it cannot escape by symlink."""

    normalized = require_oci_bundle_relative_path(source, label=label)
    if bundle_root is None:
        raise ValueError(f"{label} containment requires an authoritative bundle root")
    try:
        resolved_root = Path(bundle_root).resolve(strict=True)
        if not resolved_root.is_dir():
            raise ValueError("bundle root is not a directory")
        candidate = resolved_root.joinpath(*PurePosixPath(normalized).parts).resolve(strict=True)
        candidate.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError(f"{label} must resolve inside the authoritative bundle root") from error
    if require_directory and not candidate.is_dir():
        raise ValueError(f"{label} must resolve to a directory")
    return candidate.as_posix()


def resolve_oci_bind_source(source: str, *, bundle_root: str | Path | None) -> str:
    """Resolve a bind source, proving relative sources remain in the bundle."""

    normalized, escapes_bundle = normalize_oci_bind_source(source)
    if not source or escapes_bundle:
        raise ValueError("OCI bind source must not traverse outside the bundle")
    if source.startswith("/"):
        try:
            return Path(normalized).resolve(strict=True).as_posix()
        except (OSError, RuntimeError) as error:
            raise ValueError("OCI bind source must resolve to an existing path") from error
    return resolve_oci_bundle_path(
        normalized,
        bundle_root=bundle_root,
        label="OCI bind source",
    )


def match_forbidden_oci_path(source: str, forbidden_sources: Collection[str]) -> str | None:
    """Return the configured forbidden prefix matching a lexical or resolved path."""

    normalized, _ = normalize_oci_bind_source(source)
    candidates = {normalized}
    if normalized.startswith("/"):
        candidates.add(Path(normalized).resolve(strict=False).as_posix())
    for forbidden in sorted(forbidden_sources):
        forbidden_candidates = {forbidden, Path(forbidden).resolve(strict=False).as_posix()}
        if any(
            candidate == prefix or (prefix != "/" and candidate.startswith(prefix.rstrip("/") + "/"))
            for candidate in candidates
            for prefix in forbidden_candidates
        ):
            return forbidden
    return None

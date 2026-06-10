"""Safe symlink and shared-root inspection for AIBOM source-of-truth metadata."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ..path_support import resolves_within_root
from .inventory_contract import fingerprint_mapping, fingerprint_path_tree, fingerprint_text, redact_local_path

AibomLinkKind = Literal["symlink", "hardlink", "shared_root", "copy"]
AibomPathClass = Literal["workspace_relative", "home_relative", "config_root", "container_mount", "unknown"]
AibomValidationState = Literal["valid", "broken", "loop", "escape_blocked", "missing"]

_MAX_SYMLINK_HOPS = 16


@dataclass(frozen=True, slots=True)
class AibomSourceInspection:
    """Redacted source-of-truth inspection for inventory metadata."""

    source_fingerprint: str
    path_class: AibomPathClass
    link_kind: AibomLinkKind
    validation_state: AibomValidationState
    target_content_hash: str | None = None
    redaction_summary: dict[str, object] = field(default_factory=dict)


def inspect_aibom_source_path(
    path: Path,
    *,
    safe_roots: tuple[Path, ...],
    home_dir: Path,
    workspace_dir: Path | None = None,
    follow_unsafe_symlinks: bool = False,
) -> AibomSourceInspection:
    """Classify a path or symlink without emitting raw local paths."""

    path_class = classify_path_class(path, home_dir=home_dir, workspace_dir=workspace_dir)
    link_kind: AibomLinkKind = "copy"
    validation_state: AibomValidationState = "missing"
    target_content_hash: str | None = None
    hop_fingerprints: list[str] = []

    if not path.exists() and not path.is_symlink():
        return _build_inspection(
            path=path,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            path_class=path_class,
            link_kind=link_kind,
            validation_state="missing",
            target_content_hash=None,
            hop_fingerprints=hop_fingerprints,
        )

    if path.is_symlink():
        link_kind = "symlink"
        resolved, validation_state, hop_fingerprints = _resolve_symlink_chain(
            path,
            safe_roots=safe_roots,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            follow_unsafe_symlinks=follow_unsafe_symlinks,
        )
        if validation_state == "valid" and resolved is not None:
            target_content_hash = _content_hash_for_target(resolved, home_dir=home_dir)
    else:
        if not follow_unsafe_symlinks and not _is_within_safe_roots(path, safe_roots):
            validation_state = "escape_blocked"
        else:
            validation_state = "valid"
            target_content_hash = _content_hash_for_target(path, home_dir=home_dir)

    return _build_inspection(
        path=path,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        path_class=path_class,
        link_kind=link_kind,
        validation_state=validation_state,
        target_content_hash=target_content_hash,
        hop_fingerprints=hop_fingerprints,
    )


def classify_path_class(
    path: Path,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> AibomPathClass:
    candidate = path
    try:
        if candidate.is_symlink():
            candidate = Path(os.readlink(candidate))
            if not candidate.is_absolute() and workspace_dir is not None:
                candidate = (path.parent / candidate).resolve()
            elif not candidate.is_absolute():
                candidate = (home_dir / candidate).resolve()
            else:
                candidate = candidate.resolve()
        else:
            candidate = candidate.resolve()
    except (OSError, RuntimeError):
        return "unknown"

    if workspace_dir is not None and resolves_within_root(workspace_dir, candidate, require_exists=False):
        return "workspace_relative"
    if resolves_within_root(home_dir, candidate, require_exists=False):
        return "home_relative"
    config_markers = {".config", ".cursor", ".codex", ".claude", ".gemini", ".openclaw", ".hermes"}
    if any(part in config_markers for part in candidate.parts):
        return "config_root"
    if "/mnt/" in candidate.as_posix() or candidate.as_posix().startswith("/var/"):
        return "container_mount"
    return "unknown"


def fingerprint_redacted_path(
    path: Path,
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> str:
    candidate = path
    if not path.is_symlink():
        try:
            candidate = path.resolve()
        except (OSError, RuntimeError):
            candidate = path
    if workspace_dir is not None:
        try:
            relative = candidate.relative_to(workspace_dir.resolve())
            return fingerprint_text(f"{{workspace}}/{relative.as_posix()}")
        except (OSError, ValueError):
            pass
    return fingerprint_text(redact_local_path(candidate, home_dir=home_dir))


def _build_inspection(
    *,
    path: Path,
    home_dir: Path,
    workspace_dir: Path | None,
    path_class: AibomPathClass,
    link_kind: AibomLinkKind,
    validation_state: AibomValidationState,
    target_content_hash: str | None,
    hop_fingerprints: list[str],
) -> AibomSourceInspection:
    path_fingerprint = fingerprint_redacted_path(path, home_dir=home_dir, workspace_dir=workspace_dir)
    source_fingerprint = fingerprint_mapping(
        {
            "path": path_fingerprint,
            "link_kind": link_kind,
            "path_class": path_class,
            "validation_state": validation_state,
            "target_content_hash": target_content_hash,
            "hop_count": len(hop_fingerprints),
        }
    )
    return AibomSourceInspection(
        source_fingerprint=source_fingerprint,
        path_class=path_class,
        link_kind=link_kind,
        validation_state=validation_state,
        target_content_hash=target_content_hash,
        redaction_summary={
            "rawPathsIncluded": False,
            "hopFingerprints": hop_fingerprints,
            "pathFingerprint": path_fingerprint,
        },
    )


def _resolve_symlink_chain(
    path: Path,
    *,
    safe_roots: tuple[Path, ...],
    home_dir: Path,
    workspace_dir: Path | None,
    follow_unsafe_symlinks: bool = False,
) -> tuple[Path | None, AibomValidationState, list[str]]:
    visited: set[str] = set()
    hop_fingerprints: list[str] = []
    current = path

    for _ in range(_MAX_SYMLINK_HOPS):
        hop_fingerprints.append(fingerprint_redacted_path(current, home_dir=home_dir, workspace_dir=workspace_dir))
        hop_key = hop_fingerprints[-1]
        if hop_key in visited:
            return None, "loop", hop_fingerprints
        visited.add(hop_key)

        if not current.is_symlink():
            if not current.exists():
                return None, "broken", hop_fingerprints
            if not follow_unsafe_symlinks and not _is_within_safe_roots(current, safe_roots):
                return None, "escape_blocked", hop_fingerprints
            return current, "valid", hop_fingerprints

        try:
            link_target = os.readlink(current)
        except OSError:
            return None, "broken", hop_fingerprints

        next_path = Path(link_target)
        if not next_path.is_absolute():
            next_path = current.parent / next_path
        try:
            current = next_path.resolve()
        except RuntimeError:
            return None, "loop", hop_fingerprints
        except OSError as exc:
            if getattr(exc, "errno", None) == 40:
                return None, "loop", hop_fingerprints
            return None, "broken", hop_fingerprints

    return None, "loop", hop_fingerprints


def _is_within_safe_roots(path: Path, safe_roots: tuple[Path, ...]) -> bool:
    return any(resolves_within_root(root, path, require_exists=False) for root in safe_roots)


def source_of_truth_metadata_from_inspection(
    inspection: AibomSourceInspection,
    *,
    source_link_id: str,
) -> dict[str, object]:
    return {
        "sourceLinkId": source_link_id,
        "sourceFingerprint": inspection.source_fingerprint,
        "linkKind": inspection.link_kind,
        "validationState": inspection.validation_state,
        "pathClass": inspection.path_class,
        "redactionSummary": inspection.redaction_summary,
        "metadata": {
            "targetContentHash": inspection.target_content_hash,
        },
    }


def _content_hash_for_target(path: Path, *, home_dir: Path) -> str | None:
    try:
        if path.is_dir():
            return fingerprint_path_tree(path, home_dir=home_dir)
        if path.is_file():
            payload = path.read_bytes()[: 1024 * 1024]
            return fingerprint_text(payload.decode("utf-8", errors="replace"))
    except OSError:
        return None
    return None

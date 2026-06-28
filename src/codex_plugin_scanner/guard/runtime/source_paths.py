"""Neutral source-path classification for the hook review fast path.

This module was refactored out of ``cli/commands_support_codex_paths.py``
so the daemon-resident hook worker and the CLI fallback can share the
same source-path/symlink/sensitive-basename logic without importing the
full CLI command layer.

The CLI module keeps its original function names as thin wrappers around
these implementations so existing tests and callsites are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..runtime.false_positive_rules import (
    SOURCE_INSPECTION_BENIGN_DOTFILES,
    SOURCE_INSPECTION_EXTENSIONS,
    SOURCE_INSPECTION_PARTS,
    SOURCE_INSPECTION_SENSITIVE_PARTS,
    target_is_known_skill_doc_path,
)

SOURCE_CLASSIFIER_VERSION = "source-paths-v1"

# These mirror the CLI constants but are owned here so the runtime layer
# does not depend on CLI internals. They are kept in sync via re-import.
_BENIGN_SOURCE_DOTFILES = SOURCE_INSPECTION_BENIGN_DOTFILES | frozenset({".worktrees"})
_SENSITIVE_SEARCH_BASENAMES = SOURCE_INSPECTION_SENSITIVE_PARTS | frozenset({"id_rsa"})
_SOURCE_SEARCH_PREFIXES = tuple(f"{part}/" for part in sorted(SOURCE_INSPECTION_PARTS))
_SOURCE_SEARCH_EXTENSIONS = SOURCE_INSPECTION_EXTENSIONS


@dataclass(frozen=True, slots=True)
class SourcePathDecision:
    """Result of classifying a candidate source path."""

    allowed: bool
    reason_code: str
    resolved_path: Path | None = None
    relative_path: str | None = None


def path_contains_symlink(path: Path, *, base_dir: Path) -> bool:
    """Return True if any component of ``path`` under ``base_dir`` is a symlink.

    If ``path`` is not relative to ``base_dir``, returns True (conservative
    reject) to prevent symlink-based path escapes.
    """
    candidate = base_dir
    try:
        relative_parts = path.relative_to(base_dir).parts
    except ValueError:
        return True
    for part in relative_parts:
        if part in {"", "."}:
            continue
        candidate /= part
        try:
            if candidate.is_symlink():
                return True
        except OSError:
            return True
    return False


def resolve_source_candidate_path(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> Path | None:
    """Resolve a user-provided path string into a candidate ``Path``.

    Handles ``~`` expansion and relative-to-cwd resolution. Returns
    ``None`` for empty or malformed ``~`` paths without a home directory.
    """
    stripped = target.strip().strip("'\"")
    if not stripped:
        return None
    if stripped.startswith("~"):
        if home_dir is None:
            return None
        if stripped == "~":
            return home_dir.resolve()
        if not stripped.startswith("~/"):
            return None
        return (home_dir / stripped[2:]).resolve(strict=False)
    target_path = Path(stripped)
    if target_path.is_absolute():
        return target_path
    return (cwd or Path.cwd()).resolve() / target_path


def source_path_is_allowed(
    target: str | Path,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> SourcePathDecision:
    """Classify whether ``target`` is an allowed source-like path.

    Decision rules (in order):
    1. Empty target -> reject ``empty_path``.
    2. ``~`` path requires ``home_dir``; otherwise reject.
    3. Known skill/doc path is allowed.
    4. Glob characters reject.
    5. Absolute paths must be inside ``cwd`` after resolve.
    6. Relative paths resolve under ``cwd``.
    7. Reject if any symlink component.
    8. Reject if any sensitive basename.
    9. Reject hidden dirs except benign source dotfiles.
    10. Allow if under source prefixes, source extensions, or benign dotfiles.
    """
    target_str = str(target) if isinstance(target, Path) else target
    stripped = target_str.strip().strip("'\"")
    if not stripped:
        return SourcePathDecision(allowed=False, reason_code="empty_path")

    if target_is_known_skill_doc_path(stripped, home_dir=home_dir):
        resolved = resolve_source_candidate_path(stripped, cwd=cwd, home_dir=home_dir)
        return SourcePathDecision(
            allowed=True,
            reason_code="known_skill_doc_path",
            resolved_path=resolved,
            relative_path=stripped,
        )

    if any(char in stripped for char in ("*", "?", "{", "}")):
        return SourcePathDecision(allowed=False, reason_code="glob_pattern")

    base_dir = (cwd or Path.cwd()).resolve()
    target_path = resolve_source_candidate_path(stripped, cwd=base_dir, home_dir=home_dir)
    if target_path is None:
        return SourcePathDecision(allowed=False, reason_code="unresolved_path")

    if target_path.is_absolute():
        # Check for symlinks BEFORE resolving — resolve() follows symlinks
        # and would hide them, making path_contains_symlink a no-op.
        if path_contains_symlink(target_path, base_dir=base_dir):
            return SourcePathDecision(allowed=False, reason_code="symlink_in_path")
        try:
            candidate = target_path.resolve(strict=False)
            relative_candidate = candidate.relative_to(base_dir)
        except (RuntimeError, ValueError):
            return SourcePathDecision(allowed=False, reason_code="absolute_path_outside_workspace")
        parts = [part for part in relative_candidate.parts if part not in {"", "."}]
    else:
        unresolved_candidate = base_dir / target_path
        if path_contains_symlink(unresolved_candidate, base_dir=base_dir):
            return SourcePathDecision(allowed=False, reason_code="symlink_in_path")
        try:
            candidate = unresolved_candidate.resolve(strict=False)
        except RuntimeError:
            return SourcePathDecision(allowed=False, reason_code="unresolvable_path")
        if candidate.exists():
            try:
                relative_candidate = candidate.relative_to(base_dir)
            except ValueError:
                return SourcePathDecision(allowed=False, reason_code="resolved_outside_workspace")
            parts = [part for part in relative_candidate.parts if part not in {"", "."}]
        else:
            parts = [part for part in target_path.parts if part not in {"", "."}]

    if not parts:
        return SourcePathDecision(allowed=False, reason_code="empty_resolved_path")

    lowered_parts = [part.lower() for part in parts]
    if any(part in _SENSITIVE_SEARCH_BASENAMES for part in lowered_parts):
        return SourcePathDecision(allowed=False, reason_code="sensitive_basename")

    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in _BENIGN_SOURCE_DOTFILES for part in hidden_parts):
        return SourcePathDecision(allowed=False, reason_code="unsafe_hidden_dir")

    normalized = "/".join(parts)
    if normalized in {prefix.rstrip("/") for prefix in _SOURCE_SEARCH_PREFIXES}:
        return SourcePathDecision(
            allowed=True,
            reason_code="source_prefix_exact",
            resolved_path=candidate,
            relative_path=normalized,
        )
    if any(normalized.startswith(prefix) for prefix in _SOURCE_SEARCH_PREFIXES):
        return SourcePathDecision(
            allowed=True,
            reason_code="source_prefix",
            resolved_path=candidate,
            relative_path=normalized,
        )
    if any(part in SOURCE_INSPECTION_PARTS for part in lowered_parts):
        return SourcePathDecision(
            allowed=True,
            reason_code="source_inspection_part",
            resolved_path=candidate,
            relative_path=normalized,
        )
    if Path(stripped).name.lower() in _BENIGN_SOURCE_DOTFILES:
        return SourcePathDecision(
            allowed=True,
            reason_code="benign_source_dotfile",
            resolved_path=candidate,
            relative_path=normalized,
        )
    if Path(stripped).suffix.lower() in _SOURCE_SEARCH_EXTENSIONS:
        return SourcePathDecision(
            allowed=True,
            reason_code="source_extension",
            resolved_path=candidate,
            relative_path=normalized,
        )

    return SourcePathDecision(
        allowed=False,
        reason_code="not_source_like",
        resolved_path=candidate,
        relative_path=normalized,
    )


def absolute_source_target_is_source_like(target_path: Path) -> bool:
    """Classify an already-absolute path as source-like without resolution.

    This mirrors the original ``_codex_absolute_search_target_is_source_like``
    semantics: check parts and suffix only, no filesystem resolution.
    """
    parts = [part for part in target_path.parts if part not in {"", "/", "."}]
    if not parts:
        return False
    lowered_parts = [part.lower() for part in parts]
    if any(part in _SENSITIVE_SEARCH_BASENAMES for part in lowered_parts):
        return False
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in _BENIGN_SOURCE_DOTFILES for part in hidden_parts):
        return False
    normalized = "/".join(parts)
    if any(f"/{prefix}" in f"/{normalized}" for prefix in _SOURCE_SEARCH_PREFIXES):
        return True
    return target_path.suffix.lower() in _SOURCE_SEARCH_EXTENSIONS


__all__ = [
    "SOURCE_CLASSIFIER_VERSION",
    "SourcePathDecision",
    "absolute_source_target_is_source_like",
    "path_contains_symlink",
    "resolve_source_candidate_path",
    "source_path_is_allowed",
]

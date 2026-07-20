"""Deterministic, fail-closed identity for an agent skill directory."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path
from typing import Literal

from codex_plugin_scanner.guard.skill_directory_discovery import discover_skill_documents
from codex_plugin_scanner.guard.skill_directory_identity_contract import (
    DEFAULT_SKILL_DIRECTORY_LIMITS,
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityFailure,
    SkillDirectoryIdentityLimits,
    SkillDocumentDiscovery,
    SkillDocumentDiscoveryIssue,
    _canonical_component,
    _canonical_relative_path,
    _incomplete_result,
    _IncompleteIdentityError,
    _InspectionState,
    _TreeEntry,
    _update_canonical_digest,
    _validate_limits,
    _validate_text_path,
    incomplete_skill_directory_identity,
    skill_directory_identity_metadata,
    validated_complete_skill_directory_hash,
)
from codex_plugin_scanner.guard.windows_paths import open_windows_locked_regular_descriptor

_HASH_CHUNK_BYTES = 64 * 1024


def inspect_skill_directory(
    skill_document: Path,
    *,
    scope_root: Path,
    limits: SkillDirectoryIdentityLimits = DEFAULT_SKILL_DIRECTORY_LIMITS,
) -> SkillDirectoryIdentity:
    """Return a complete canonical tree identity or a typed non-reusable result.

    The complete digest covers every filesystem entry below the skill root.  A
    tree that cannot be inspected in full is never represented by a partial
    digest: it receives a typed stable state hash that cannot be reused as a
    complete identity.
    """

    _validate_limits(limits)
    state = _InspectionState()
    logical_primary = Path(skill_document)
    logical_root = logical_primary.parent
    try:
        resolved_scope = _resolve_scope_root(scope_root)
        _validate_lexical_parent_links(scope_root, logical_root)
        root_lstat = _root_lstat(logical_root)
        _validate_skill_root_type(root_lstat)
        resolved_root = _resolve_existing_path(logical_root, broken_reason="root_missing")
        if not resolved_root.is_dir():
            raise _IncompleteIdentityError("root_not_directory")
        if not _is_relative_to(resolved_root, resolved_scope):
            raise _IncompleteIdentityError("symlink_escape")

        primary_name = _canonical_component(logical_primary.name)
        entries, initial_structure = _collect_entries(resolved_root, limits=limits)
        state.entry_count = len(entries)
        primary_entry = next(
            (entry for entry in entries if entry.relative_path == primary_name),
            None,
        )
        if primary_entry is None or primary_entry.entry_type == "directory":
            raise _IncompleteIdentityError("primary_missing")
        if primary_entry.entry_type == "symlink":
            raise _IncompleteIdentityError("primary_symlink_unsupported")

        records: list[dict[str, object]] = []
        ordered_entries = [primary_entry, *(entry for entry in entries if entry is not primary_entry)]
        for entry in ordered_entries:
            record, content_hash = _entry_record(
                entry,
                root=resolved_root,
                limits=limits,
                state=state,
            )
            records.append(record)
            if entry is primary_entry:
                state.primary_content_hash = content_hash

        current_root_lstat = _safe_lstat(logical_root)
        if _stat_key(current_root_lstat) != _stat_key(root_lstat):
            raise _IncompleteIdentityError("tree_changed_during_hash")
        _, final_structure = _collect_entries(resolved_root, limits=limits)
        if final_structure != initial_structure:
            raise _IncompleteIdentityError("tree_changed_during_hash")
        final_root_lstat = _safe_lstat(logical_root)
        if _stat_key(final_root_lstat) != _stat_key(root_lstat):
            raise _IncompleteIdentityError("tree_changed_during_hash")

        header: dict[str, object] = {
            "schema": SKILL_DIRECTORY_IDENTITY_SCHEMA,
            "rootMode": _security_mode(final_root_lstat.st_mode),
        }
        digest = hashlib.sha256()
        _update_canonical_digest(digest, header)
        for record in sorted(records, key=lambda item: str(item["path"]).encode("utf-8")):
            _update_canonical_digest(digest, record)
        return SkillDirectoryIdentity(
            schema_version=SKILL_DIRECTORY_IDENTITY_SCHEMA,
            status="complete",
            directory_hash=f"sha256:{digest.hexdigest()}",
            primary_content_hash=state.primary_content_hash,
            entry_count=state.entry_count,
            total_bytes=state.total_bytes,
            failure_reason=None,
            incomplete_state_hash=None,
        )
    except _IncompleteIdentityError as exc:
        return _incomplete_result(state, exc.reason)
    except (OSError, RuntimeError, ValueError):
        return _incomplete_result(state, "unreadable_entry")


def _resolve_scope_root(scope_root: Path) -> Path:
    try:
        resolved = Path(scope_root).resolve(strict=True)
    except FileNotFoundError as exc:
        raise _IncompleteIdentityError("root_missing") from exc
    except RuntimeError as exc:
        raise _IncompleteIdentityError("symlink_loop") from exc
    except OSError as exc:
        raise _IncompleteIdentityError("unreadable_entry") from exc
    if not resolved.is_dir():
        raise _IncompleteIdentityError("root_not_directory")
    return resolved


def _validate_lexical_parent_links(scope_root: Path, logical_root: Path) -> None:
    scope = Path(os.path.abspath(scope_root))
    root = Path(os.path.abspath(logical_root))
    try:
        relative = root.relative_to(scope)
    except ValueError as exc:
        raise _IncompleteIdentityError("symlink_escape") from exc
    current = scope
    for part in relative.parts[:-1]:
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _IncompleteIdentityError("unreadable_entry") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _IncompleteIdentityError("symlink_directory_unsupported")
        if _is_unsupported_reparse(metadata):
            raise _IncompleteIdentityError("unsupported_reparse_point")


def _root_lstat(root: Path) -> os.stat_result:
    try:
        metadata = os.lstat(root)
    except FileNotFoundError as exc:
        raise _IncompleteIdentityError("root_missing") from exc
    except OSError as exc:
        raise _IncompleteIdentityError("unreadable_entry") from exc
    if _is_unsupported_reparse(metadata):
        raise _IncompleteIdentityError("unsupported_reparse_point")
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
        raise _IncompleteIdentityError("root_not_directory")
    return metadata


def _validate_skill_root_type(root_lstat: os.stat_result) -> None:
    if stat.S_ISLNK(root_lstat.st_mode):
        raise _IncompleteIdentityError("symlink_directory_unsupported")


def _resolve_existing_path(
    path: Path,
    *,
    broken_reason: SkillDirectoryIdentityFailure,
) -> Path:
    try:
        return path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise _IncompleteIdentityError(broken_reason) from exc
    except RuntimeError as exc:
        raise _IncompleteIdentityError("symlink_loop") from exc
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            raise _IncompleteIdentityError("symlink_loop") from exc
        raise _IncompleteIdentityError("unreadable_entry") from exc


def _collect_entries(
    root: Path,
    *,
    limits: SkillDirectoryIdentityLimits,
) -> tuple[list[_TreeEntry], tuple[tuple[object, ...], ...]]:
    entries: list[_TreeEntry] = []
    normalized_paths: set[str] = set()
    folded_paths: dict[str, str] = {}

    def walk(directory: Path, relative_parts: tuple[str, ...]) -> None:
        try:
            children = os.scandir(directory)
        except PermissionError as exc:
            raise _IncompleteIdentityError("unreadable_entry") from exc
        except FileNotFoundError as exc:
            raise _IncompleteIdentityError("tree_changed_during_hash") from exc
        except OSError as exc:
            raise _IncompleteIdentityError("unreadable_entry") from exc
        try:
            for child in children:
                raw_name = child.name
                canonical_name = _canonical_component(raw_name)
                canonical_parts = (*relative_parts, canonical_name)
                relative_path = "/".join(canonical_parts)
                if relative_path in normalized_paths:
                    raise _IncompleteIdentityError("duplicate_path")
                folded = relative_path.casefold()
                prior = folded_paths.get(folded)
                if prior is not None and prior != relative_path:
                    raise _IncompleteIdentityError("case_collision")
                normalized_paths.add(relative_path)
                folded_paths[folded] = relative_path
                if len(canonical_parts) > limits.max_depth:
                    raise _IncompleteIdentityError("max_depth_exceeded")
                if len(entries) >= limits.max_entries:
                    raise _IncompleteIdentityError("max_entries_exceeded")

                path = Path(child.path)
                metadata = _safe_lstat(path)
                if _is_unsupported_reparse(metadata):
                    raise _IncompleteIdentityError("unsupported_reparse_point")
                if stat.S_ISLNK(metadata.st_mode):
                    try:
                        raw_target = os.readlink(path)
                    except OSError as exc:
                        raise _IncompleteIdentityError("tree_changed_during_hash") from exc
                    _validate_text_path(raw_target)
                    entry_type: Literal["directory", "file", "symlink"] = "symlink"
                elif stat.S_ISDIR(metadata.st_mode):
                    raw_target = None
                    entry_type = "directory"
                elif stat.S_ISREG(metadata.st_mode):
                    raw_target = None
                    entry_type = "file"
                else:
                    raise _IncompleteIdentityError("special_file")
                entry = _TreeEntry(
                    path=path,
                    relative_path=relative_path,
                    entry_type=entry_type,
                    metadata_key=_stat_key(metadata),
                    raw_link_target=raw_target,
                )
                entries.append(entry)
                if entry_type == "directory":
                    walk(path, canonical_parts)
        finally:
            close = getattr(children, "close", None)
            if close is not None:
                close()

    walk(root, ())
    structure = tuple(
        sorted(
            (
                entry.relative_path,
                entry.entry_type,
                entry.metadata_key,
                entry.raw_link_target,
            )
            for entry in entries
        )
    )
    return entries, structure


def _entry_record(
    entry: _TreeEntry,
    *,
    root: Path,
    limits: SkillDirectoryIdentityLimits,
    state: _InspectionState,
) -> tuple[dict[str, object], str | None]:
    metadata = _safe_lstat(entry.path)
    if _stat_key(metadata) != entry.metadata_key:
        raise _IncompleteIdentityError("tree_changed_during_hash")
    mode = _security_mode(metadata.st_mode)
    if entry.entry_type == "directory":
        return {"type": "directory", "path": entry.relative_path, "mode": mode}, None
    if entry.entry_type == "file":
        digest, size = _hash_regular_file(
            entry.path,
            expected_metadata=metadata,
            limits=limits,
            state=state,
        )
        return {
            "type": "file",
            "path": entry.relative_path,
            "mode": mode,
            "size": size,
            "digest": digest,
        }, digest

    raw_target = entry.raw_link_target
    if raw_target is None:
        raise _IncompleteIdentityError("tree_changed_during_hash")
    # Resolve the captured link payload directly.  On Windows, resolving the
    # link entry itself can reject an otherwise valid ``./name`` spelling even
    # though ``readlink`` returned it and the target exists.  The later lstat
    # and readlink checks still bind this target snapshot to the original link.
    resolved_target = _resolve_existing_path(
        entry.path.parent / raw_target,
        broken_reason="symlink_broken",
    )
    if not _is_relative_to(resolved_target, root):
        raise _IncompleteIdentityError("symlink_escape")
    target_lstat = _safe_lstat(resolved_target)
    if _is_unsupported_reparse(target_lstat):
        raise _IncompleteIdentityError("unsupported_reparse_point")
    if stat.S_ISDIR(target_lstat.st_mode):
        raise _IncompleteIdentityError("symlink_directory_unsupported")
    if not stat.S_ISREG(target_lstat.st_mode):
        raise _IncompleteIdentityError("special_file")
    target_digest, target_size = _hash_regular_file(
        resolved_target,
        expected_metadata=target_lstat,
        limits=limits,
        state=state,
    )
    current_link = _safe_lstat(entry.path)
    try:
        current_raw_target = os.readlink(entry.path)
    except OSError as exc:
        raise _IncompleteIdentityError("tree_changed_during_hash") from exc
    if _stat_key(current_link) != entry.metadata_key or current_raw_target != raw_target:
        raise _IncompleteIdentityError("tree_changed_during_hash")
    target_path = _canonical_relative_path(resolved_target.relative_to(root).parts)
    return {
        "type": "symlink",
        "path": entry.relative_path,
        "mode": mode,
        "target": raw_target,
        "targetPath": target_path,
        "targetType": "file",
        "targetMode": _security_mode(target_lstat.st_mode),
        "targetSize": target_size,
        "targetDigest": target_digest,
    }, target_digest


def _hash_regular_file(
    path: Path,
    *,
    expected_metadata: os.stat_result,
    limits: SkillDirectoryIdentityLimits,
    state: _InspectionState,
) -> tuple[str, int]:
    if expected_metadata.st_size > limits.max_file_bytes:
        raise _IncompleteIdentityError("max_file_bytes_exceeded")
    if state.total_bytes + expected_metadata.st_size > limits.max_total_bytes:
        raise _IncompleteIdentityError("max_total_bytes_exceeded")
    try:
        if os.name == "nt":
            descriptor = open_windows_locked_regular_descriptor(path)
        else:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise _IncompleteIdentityError("tree_changed_during_hash") from exc
    except OSError as exc:
        raise _IncompleteIdentityError("unreadable_entry") from exc
    total = 0
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _IncompleteIdentityError("tree_changed_during_hash")
        if os.name == "nt":
            # The native handle denies write and delete sharing. Comparing two
            # path stats while that lock is held detects a replacement between
            # discovery and open without relying on incompatible stat APIs.
            if _stat_key(_safe_lstat(path)) != _stat_key(expected_metadata):
                raise _IncompleteIdentityError("tree_changed_during_hash")
        elif _stat_key(opened) != _stat_key(expected_metadata):
            raise _IncompleteIdentityError("tree_changed_during_hash")
        while True:
            try:
                chunk = os.read(descriptor, _HASH_CHUNK_BYTES)
            except OSError as exc:
                raise _IncompleteIdentityError("unreadable_entry") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > limits.max_file_bytes:
                raise _IncompleteIdentityError("max_file_bytes_exceeded")
            if state.total_bytes + total > limits.max_total_bytes:
                raise _IncompleteIdentityError("max_total_bytes_exceeded")
            digest.update(chunk)
        if total != opened.st_size or _stat_key(os.fstat(descriptor)) != _stat_key(opened):
            raise _IncompleteIdentityError("tree_changed_during_hash")
    finally:
        os.close(descriptor)
    if _stat_key(_safe_lstat(path)) != _stat_key(expected_metadata):
        raise _IncompleteIdentityError("tree_changed_during_hash")
    state.total_bytes += total
    return f"sha256:{digest.hexdigest()}", total


def _safe_lstat(path: Path) -> os.stat_result:
    try:
        return os.lstat(path)
    except FileNotFoundError as exc:
        raise _IncompleteIdentityError("tree_changed_during_hash") from exc
    except PermissionError as exc:
        raise _IncompleteIdentityError("unreadable_entry") from exc
    except OSError as exc:
        raise _IncompleteIdentityError("unreadable_entry") from exc


def _stat_key(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
        int(getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000))),
        int(getattr(metadata, "st_file_attributes", 0)),
    )


def _security_mode(mode: int) -> str | None:
    if os.name == "nt":
        return None
    return f"{stat.S_IMODE(mode) & 0o7777:04o}"


def _is_unsupported_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & reparse_flag) and not stat.S_ISLNK(metadata.st_mode)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        _ = path.relative_to(root)
    except ValueError:
        return False
    return True


__all__ = [
    "DEFAULT_SKILL_DIRECTORY_LIMITS",
    "SKILL_DIRECTORY_IDENTITY_SCHEMA",
    "SkillDirectoryIdentity",
    "SkillDirectoryIdentityFailure",
    "SkillDirectoryIdentityLimits",
    "SkillDocumentDiscovery",
    "SkillDocumentDiscoveryIssue",
    "discover_skill_documents",
    "incomplete_skill_directory_identity",
    "inspect_skill_directory",
    "skill_directory_identity_metadata",
    "validated_complete_skill_directory_hash",
]

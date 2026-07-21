"""Bounded, fail-closed discovery of primary skill documents."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path

from codex_plugin_scanner.guard.skill_directory_identity_contract import (
    DEFAULT_SKILL_DIRECTORY_LIMITS,
    SkillDirectoryIdentityFailure,
    SkillDirectoryIdentityLimits,
    SkillDocumentDiscovery,
    SkillDocumentDiscoveryIssue,
    _canonical_component,
    _IncompleteIdentityError,
    _validate_limits,
)


def discover_skill_documents(
    skill_root: Path,
    *,
    limits: SkillDirectoryIdentityLimits = DEFAULT_SKILL_DIRECTORY_LIMITS,
) -> SkillDocumentDiscovery:
    """Discover primary documents without following links or exceeding limits.

    Discovery stops descending once a directory contains ``SKILL.md``; the
    identity inspector owns that complete subtree. Any unreadable, linked, or
    over-budget grouping path becomes a typed issue so callers can emit one
    non-reusable artifact instead of silently omitting unknown content.
    """

    _validate_limits(limits)
    root = Path(skill_root)
    try:
        root_metadata = os.lstat(root)
    except FileNotFoundError:
        return SkillDocumentDiscovery(documents=(), issues=())
    except OSError:
        return SkillDocumentDiscovery(
            documents=(),
            issues=(_discovery_issue(root, root, "unreadable_entry"),),
        )
    if stat.S_ISLNK(root_metadata.st_mode):
        return SkillDocumentDiscovery(
            documents=(),
            issues=(_discovery_issue(root, root, _linked_directory_failure(root)),),
        )
    if _is_unsupported_reparse(root_metadata):
        return SkillDocumentDiscovery(
            documents=(),
            issues=(_discovery_issue(root, root, "unsupported_reparse_point"),),
        )
    if not stat.S_ISDIR(root_metadata.st_mode):
        return SkillDocumentDiscovery(
            documents=(),
            issues=(_discovery_issue(root, root, "root_not_directory"),),
        )

    discovered: set[Path] = set()
    issues: dict[tuple[str, SkillDirectoryIdentityFailure], SkillDocumentDiscoveryIssue] = {}
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    visited_entries = 0
    budget_exhausted = False
    while pending and not budget_exhausted:
        directory, relative_parts = pending.pop()
        primary = directory / "SKILL.md"
        try:
            _ = os.lstat(primary)
        except FileNotFoundError:
            pass
        except OSError:
            issue = _discovery_issue(root, primary, "unreadable_entry")
            issues[(issue.relative_path, issue.failure_reason)] = issue
            continue
        else:
            discovered.add(primary)
            continue

        try:
            iterator = os.scandir(directory)
        except OSError:
            issue = _discovery_issue(root, directory, "unreadable_entry")
            issues[(issue.relative_path, issue.failure_reason)] = issue
            continue
        try:
            for child in iterator:
                if visited_entries >= limits.max_entries:
                    issue = _discovery_issue(root, root, "max_entries_exceeded")
                    issues[(issue.relative_path, issue.failure_reason)] = issue
                    budget_exhausted = True
                    break
                visited_entries += 1
                path = Path(child.path)
                try:
                    canonical_name = _canonical_component(child.name)
                except _IncompleteIdentityError as exc:
                    issue = _discovery_issue(root, path, exc.reason)
                    issues[(issue.relative_path, issue.failure_reason)] = issue
                    continue
                child_parts = (*relative_parts, canonical_name)
                try:
                    metadata = os.lstat(path)
                except OSError:
                    issue = _discovery_issue(root, path, "unreadable_entry")
                    issues[(issue.relative_path, issue.failure_reason)] = issue
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    issue = _discovery_issue(root, path, _linked_directory_failure(path))
                    issues[(issue.relative_path, issue.failure_reason)] = issue
                    continue
                if _is_unsupported_reparse(metadata):
                    issue = _discovery_issue(root, path, "unsupported_reparse_point")
                    issues[(issue.relative_path, issue.failure_reason)] = issue
                    continue
                if not stat.S_ISDIR(metadata.st_mode):
                    continue
                if len(child_parts) > limits.max_depth:
                    issue = _discovery_issue(root, path, "max_depth_exceeded")
                    issues[(issue.relative_path, issue.failure_reason)] = issue
                    continue
                pending.append((path, child_parts))
        except OSError:
            issue = _discovery_issue(root, directory, "unreadable_entry")
            issues[(issue.relative_path, issue.failure_reason)] = issue
        finally:
            close = getattr(iterator, "close", None)
            if close is not None:
                try:
                    close()
                except OSError:
                    issue = _discovery_issue(root, directory, "unreadable_entry")
                    issues[(issue.relative_path, issue.failure_reason)] = issue

    return SkillDocumentDiscovery(
        documents=tuple(sorted(discovered, key=os.fspath)),
        issues=tuple(sorted(issues.values(), key=lambda issue: (issue.relative_path, issue.failure_reason))),
    )


def _discovery_issue(
    root: Path,
    path: Path,
    reason: SkillDirectoryIdentityFailure,
) -> SkillDocumentDiscoveryIssue:
    try:
        relative_path = path.relative_to(root).as_posix() or "."
    except ValueError:
        relative_path = "."
    issue_material = os.fsencode(relative_path) + b"\0" + reason.encode("ascii")
    return SkillDocumentDiscoveryIssue(
        path=path,
        relative_path=relative_path,
        failure_reason=reason,
        issue_id=hashlib.sha256(issue_material).hexdigest()[:16],
    )


def _linked_directory_failure(path: Path) -> SkillDirectoryIdentityFailure:
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        return "symlink_broken"
    except RuntimeError:
        return "symlink_loop"
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            return "symlink_loop"
        return "unreadable_entry"
    return "symlink_directory_unsupported" if resolved.is_dir() else "root_not_directory"


def _is_unsupported_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & reparse_flag) and not stat.S_ISLNK(metadata.st_mode)

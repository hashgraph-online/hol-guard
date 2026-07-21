"""Filesystem containment and revalidation for Cisco preflight scans."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ApprovedScanRoot:
    path: Path
    label: str


@dataclass(frozen=True, slots=True)
class ValidatedScanTarget:
    path: Path | None
    scan_root: Path
    approved_root: ApprovedScanRoot
    kind: str


class CiscoPathContainmentError(RuntimeError):
    def __init__(self, reason: str, *, approved_root_label: str = "selected-workspace") -> None:
        super().__init__(reason)
        self.reason: str = reason
        self.approved_root_label: str = approved_root_label


def canonical_approved_scan_roots(
    workspace: Path | str | None,
    approved_scan_roots: Iterable[Path | str],
) -> tuple[ApprovedScanRoot, ...]:
    primary_value = workspace if workspace is not None else Path.cwd()
    primary_path = _canonical_readable_directory(primary_value, label="selected-workspace")
    roots = [ApprovedScanRoot(primary_path, "selected-workspace")]
    for index, root_value in enumerate(approved_scan_roots, start=1):
        label = f"explicit-root-{index}"
        canonical = _canonical_readable_directory(root_value, label=label)
        if canonical not in {root.path for root in roots}:
            roots.append(ApprovedScanRoot(canonical, label))
    return tuple(roots)


def _canonical_readable_directory(value: Path | str, *, label: str) -> Path:
    try:
        canonical = Path(value).expanduser().resolve(strict=True)
        metadata = canonical.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise CiscoPathContainmentError("approved_root_unresolved", approved_root_label=label) from exc
    readable_bits = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    searchable_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not metadata.st_mode & readable_bits
        or not metadata.st_mode & searchable_bits
        or not os.access(canonical, os.R_OK | os.X_OK)
    ):
        raise CiscoPathContainmentError("approved_root_unreadable", approved_root_label=label)
    return canonical


def cisco_target_kind(target: str, requested_sources: frozenset[str]) -> str | None:
    target_name = Path(target).name
    if "skill" in requested_sources and target_name == "SKILL.md":
        return "skill"
    if "mcp" in requested_sources and target_name == ".mcp.json":
        return "mcp"
    return None


def validated_scan_target(
    target: str,
    *,
    kind: str,
    resolution_root: Path,
    approved_roots: tuple[ApprovedScanRoot, ...],
) -> ValidatedScanTarget:
    candidate = Path(target).expanduser()
    if not candidate.is_absolute():
        candidate = resolution_root / candidate
    try:
        target_path = candidate.resolve(strict=True)
        target_metadata = target_path.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise CiscoPathContainmentError("target_unresolved") from exc
    approved_root = _most_specific_approved_root(target_path, approved_roots)
    if approved_root is None:
        raise CiscoPathContainmentError(
            "target_outside_approved_roots",
            approved_root_label="all-approved-roots",
        )
    if not stat.S_ISREG(target_metadata.st_mode) or not target_metadata.st_mode & (
        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    ):
        raise CiscoPathContainmentError(
            "target_not_readable_regular_file",
            approved_root_label=approved_root.label,
        )
    if not os.access(target_path, os.R_OK):
        raise CiscoPathContainmentError("target_unreadable", approved_root_label=approved_root.label)
    scan_root = _derived_scan_root(target_path, kind=kind, approved_root=approved_root)
    return ValidatedScanTarget(target_path, scan_root, approved_root, kind)


def validated_redacted_scan_target(kind: str, primary_root: ApprovedScanRoot) -> ValidatedScanTarget:
    scan_root = skill_scan_root_for_workspace(primary_root.path) if kind == "skill" else primary_root.path
    canonical_scan_root = _canonical_scan_root(scan_root, approved_root=primary_root)
    return ValidatedScanTarget(None, canonical_scan_root, primary_root, kind)


def _derived_scan_root(
    target_path: Path,
    *,
    kind: str,
    approved_root: ApprovedScanRoot,
) -> Path:
    candidate = _skill_scan_root_for_file(target_path, approved_root.path) if kind == "skill" else target_path.parent
    return _canonical_scan_root(candidate, approved_root=approved_root)


def _canonical_scan_root(candidate: Path, *, approved_root: ApprovedScanRoot) -> Path:
    try:
        canonical = candidate.resolve(strict=True)
        metadata = canonical.stat()
        _ = canonical.relative_to(approved_root.path)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CiscoPathContainmentError(
            "derived_scan_root_outside_approved_root",
            approved_root_label=approved_root.label,
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or not metadata.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or not os.access(canonical, os.R_OK | os.X_OK)
    ):
        raise CiscoPathContainmentError(
            "derived_scan_root_unreadable",
            approved_root_label=approved_root.label,
        )
    return canonical


def _most_specific_approved_root(
    target: Path,
    approved_roots: tuple[ApprovedScanRoot, ...],
) -> ApprovedScanRoot | None:
    for root in sorted(approved_roots, key=lambda item: len(item.path.parts), reverse=True):
        try:
            _ = target.relative_to(root.path)
        except ValueError:
            continue
        return root
    return None


def revalidate_scan_target(target: ValidatedScanTarget) -> None:
    approved_root = _canonical_readable_directory(target.approved_root.path, label=target.approved_root.label)
    if approved_root != target.approved_root.path:
        raise CiscoPathContainmentError(
            "approved_root_changed",
            approved_root_label=target.approved_root.label,
        )
    if target.path is not None:
        try:
            resolved_target = target.path.resolve(strict=True)
            target_metadata = resolved_target.stat()
        except (OSError, RuntimeError, ValueError) as exc:
            raise CiscoPathContainmentError(
                "target_changed",
                approved_root_label=target.approved_root.label,
            ) from exc
        if (
            resolved_target != target.path
            or not stat.S_ISREG(target_metadata.st_mode)
            or not target_metadata.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            or not os.access(resolved_target, os.R_OK)
        ):
            raise CiscoPathContainmentError(
                "target_changed",
                approved_root_label=target.approved_root.label,
            )
        derived_root = _derived_scan_root(
            resolved_target,
            kind=target.kind,
            approved_root=target.approved_root,
        )
        if derived_root != target.scan_root:
            raise CiscoPathContainmentError(
                "derived_scan_root_changed",
                approved_root_label=target.approved_root.label,
            )
    revalidated_scan_root = _canonical_scan_root(target.scan_root, approved_root=target.approved_root)
    if revalidated_scan_root != target.scan_root:
        raise CiscoPathContainmentError(
            "derived_scan_root_changed",
            approved_root_label=target.approved_root.label,
        )


def _skill_scan_root_for_file(path: Path, workspace: Path) -> Path:
    parent = path.parent
    if parent.parent.name == "skills":
        return parent.parent
    if parent.name == "skills":
        return parent
    if parent == workspace:
        return parent
    return parent


def skill_scan_root_for_workspace(target: Path) -> Path:
    skills_dir = target / "skills"
    if skills_dir.is_dir():
        return skills_dir
    return target

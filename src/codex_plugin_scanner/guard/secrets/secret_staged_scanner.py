"""Bounded leaked-secret scanning for the Git staging index."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from .secret_detection import SecretFinding, SecretScanSource
from .secret_repository_scanner import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TOTAL_BYTES,
    RepositorySecretScanResult,
    _bounded_positive,
    _run_git,
    _scan_blob,
)

if TYPE_CHECKING:
    from .git_object_reader import GitBlobReference


def _git_repository_root(root: Path) -> Path | None:
    try:
        result = _run_git(root, ["rev-parse", "--show-toplevel"])
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    raw = result.stdout.decode("utf-8", errors="strict").strip()
    if not raw:
        return None
    return Path(raw).resolve()


def _git_staged_paths(root: Path) -> list[GitBlobReference] | None:
    from .git_object_reader import parse_raw_diff

    try:
        result = _run_git(
            root,
            ["diff", "--cached", "--raw", "--no-abbrev", "--no-renames", "--diff-filter=ACMR", "-z", "--"],
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return parse_raw_diff(result.stdout)


def scan_staged_secrets(
    target: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_findings: int = DEFAULT_MAX_FINDINGS,
) -> RepositorySecretScanResult:
    """Scan only content currently staged in a Git index.

    The working tree is never read for candidate content. This makes the result
    suitable for pre-commit enforcement even when unstaged edits differ from the
    index that will actually be committed.
    """

    from .git_blob_scan_cache import GitBlobScanCache
    from .git_object_reader import GitObjectReader, GitObjectReadError

    requested_root = target.expanduser().resolve()
    if not requested_root.exists() or not requested_root.is_dir():
        raise ValueError("staged secret scan target must be an existing directory")
    root = _git_repository_root(requested_root)
    if root is None:
        return RepositorySecretScanResult(
            findings=(),
            files_scanned=0,
            commits_scanned=0,
            bytes_scanned=0,
            history_enabled=False,
            truncated=True,
            errors=("git_staged_enumeration_failed",),
        )

    max_files = _bounded_positive(max_files, default=DEFAULT_MAX_FILES, maximum=100_000)
    max_file_bytes = _bounded_positive(
        max_file_bytes,
        default=DEFAULT_MAX_FILE_BYTES,
        maximum=32 * 1024 * 1024,
    )
    max_total_bytes = _bounded_positive(
        max_total_bytes,
        default=DEFAULT_MAX_TOTAL_BYTES,
        maximum=4 * 1024 * 1024 * 1024,
    )
    max_findings = _bounded_positive(max_findings, default=DEFAULT_MAX_FINDINGS, maximum=10_000)

    paths = _git_staged_paths(root)
    if paths is None:
        return RepositorySecretScanResult(
            findings=(),
            files_scanned=0,
            commits_scanned=0,
            bytes_scanned=0,
            history_enabled=False,
            truncated=True,
            errors=("git_staged_enumeration_failed",),
        )

    findings: list[SecretFinding] = []
    errors: set[str] = set()
    files_scanned = 0
    bytes_scanned = 0
    truncated = False
    staged_source: SecretScanSource = "staged"
    cache = GitBlobScanCache()
    with GitObjectReader(root) as objects:
        for reference in paths:
            if files_scanned >= max_files or bytes_scanned >= max_total_bytes or len(findings) >= max_findings:
                truncated = True
                break
            try:
                size = objects.size(reference.oid)
                if size is None or size > max_file_bytes:
                    truncated = True
                    errors.add("git_staged_blob_unavailable_or_oversized")
                    continue
                if bytes_scanned + size > max_total_bytes:
                    truncated = True
                    break
                found, scanned_bytes = cache.scan(
                    objects,
                    oid=reference.oid,
                    size=size,
                    path=reference.path.replace("\\", "/"),
                    source=staged_source,
                    commit=None,
                    finding_budget=max_findings - len(findings),
                    max_file_bytes=max_file_bytes,
                    scan_blob=_scan_blob,
                )
            except (GitObjectReadError, OSError, subprocess.SubprocessError):
                truncated = True
                errors.add("git_staged_blob_unavailable_or_oversized")
                continue
            files_scanned += 1
            bytes_scanned += scanned_bytes
            findings.extend(found)
            if len(findings) >= max_findings:
                truncated = True
                break

    deduped: dict[tuple[str, int, str], SecretFinding] = {}
    for finding in findings:
        key = (finding.path, finding.line, finding.candidate)
        existing = deduped.get(key)
        if existing is None or finding.confidence_score > existing.confidence_score:
            deduped[key] = finding
    ordered = tuple(sorted(deduped.values(), key=lambda item: (item.path, item.line, item.rule_id))[:max_findings])
    if len(deduped) > len(ordered):
        truncated = True

    return RepositorySecretScanResult(
        findings=ordered,
        files_scanned=files_scanned,
        commits_scanned=0,
        bytes_scanned=bytes_scanned,
        history_enabled=False,
        truncated=truncated,
        errors=tuple(sorted(errors)),
    )


__all__ = ["scan_staged_secrets"]

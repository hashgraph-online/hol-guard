"""Bounded working-tree and Git-history scanner for leaked secrets.

The scanner is intentionally local and read-only. It does not invoke a shell,
does not contact the network, and never includes raw secret candidates in its
public result. Git-history scanning examines files changed by bounded commits
instead of materializing repository history to disk.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .secret_detection import (
    SecretFinding,
    SecretScanSource,
    detector_version,
    scan_secret_text,
)

DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 500
DEFAULT_MAX_COMMITS = 500
_GIT_TIMEOUT_SECONDS = 20
_TRUNCATION_REASON_ORDER = (
    "max_files",
    "max_total_bytes",
    "max_findings",
    "max_commits",
)

_BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".a",
        ".avi",
        ".bin",
        ".bmp",
        ".class",
        ".dll",
        ".dmg",
        ".doc",
        ".docx",
        ".eot",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".mov",
        ".mp3",
        ".mp4",
        ".o",
        ".otf",
        ".pdf",
        ".png",
        ".pyc",
        ".so",
        ".tar",
        ".tiff",
        ".ttf",
        ".wav",
        ".webm",
        ".woff",
        ".woff2",
        ".xz",
        ".zip",
    }
)
_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".next",
        ".turbo",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "coverage",
    }
)


@dataclass(frozen=True, slots=True)
class RepositorySecretScanResult:
    findings: tuple[SecretFinding, ...]
    files_scanned: int
    commits_scanned: int
    bytes_scanned: int
    history_enabled: bool
    truncated: bool
    errors: tuple[str, ...]
    truncation_reasons: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": "guard-repository-secret-scan.v1",
            "detector_version": detector_version(),
            "files_scanned": self.files_scanned,
            "commits_scanned": self.commits_scanned,
            "bytes_scanned": self.bytes_scanned,
            "history_enabled": self.history_enabled,
            "truncated": self.truncated,
            "truncation_reasons": list(self.truncation_reasons),
            "finding_count": len(self.findings),
            "findings": [finding.to_public_dict() for finding in self.findings],
            "errors": list(self.errors),
        }


def _bounded_positive(value: int, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return min(parsed, maximum)


def _active_limit_reasons(
    *,
    files_scanned: int,
    bytes_scanned: int,
    finding_count: int,
    max_files: int,
    max_total_bytes: int,
    max_findings: int,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if files_scanned >= max_files:
        reasons.append("max_files")
    if bytes_scanned >= max_total_bytes:
        reasons.append("max_total_bytes")
    if finding_count >= max_findings:
        reasons.append("max_findings")
    return tuple(reasons)


def _ordered_truncation_reasons(reasons: set[str]) -> tuple[str, ...]:
    return tuple(reason for reason in _TRUNCATION_REASON_ORDER if reason in reasons)


def _looks_binary(path: str, data: bytes) -> bool:
    if Path(path).suffix.lower() in _BINARY_SUFFIXES:
        return True
    sample = data[:8192]
    return b"\0" in sample


def _decode_text(path: str, data: bytes) -> str | None:
    if _looks_binary(path, data):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _run_git(root: Path, args: list[str], *, timeout: int = _GIT_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        timeout=timeout,
    )


def _is_git_repository(root: Path) -> bool:
    try:
        result = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.strip() == b"true"


def _git_working_paths(root: Path) -> list[str] | None:
    try:
        result = _run_git(root, ["ls-files", "-co", "--exclude-standard", "-z"])
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [item.decode("utf-8", errors="surrogateescape") for item in result.stdout.split(b"\0") if item]


def _filesystem_paths(root: Path) -> list[str]:
    paths: list[str] = []
    for current_root, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in _SKIP_DIR_NAMES]
        current = Path(current_root)
        for filename in files:
            path = current / filename
            if path.is_symlink():
                continue
            paths.append(_safe_relative(path, root))
    paths.sort()
    return paths


def _scan_blob(
    data: bytes,
    *,
    path: str,
    source: SecretScanSource,
    commit: str | None,
    finding_budget: int,
) -> tuple[tuple[SecretFinding, ...], int]:
    text = _decode_text(path, data)
    if text is None:
        return (), 0
    summary = scan_secret_text(
        text,
        path=path,
        source=source,
        commit=commit,
        max_findings=finding_budget,
    )
    return summary.findings, len(data)


def _read_working_file(root: Path, relative_path: str, max_file_bytes: int) -> bytes | None:
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    if not resolved.is_file() or resolved.is_symlink():
        return None
    try:
        size = resolved.stat().st_size
    except OSError:
        return None
    if size > max_file_bytes:
        return None
    try:
        return resolved.read_bytes()
    except OSError:
        return None


def _git_commits(root: Path, max_commits: int) -> list[str] | None:
    try:
        result = _run_git(root, ["rev-list", "--all", f"--max-count={max_commits}"])
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [line.decode("ascii", errors="ignore").strip() for line in result.stdout.splitlines() if line.strip()]


def _git_changed_paths(root: Path, commit: str) -> list[str] | None:
    try:
        result = _run_git(
            root,
            ["diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-z", commit],
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [item.decode("utf-8", errors="surrogateescape") for item in result.stdout.split(b"\0") if item]


def _git_blob(root: Path, commit: str, path: str, max_file_bytes: int) -> bytes | None:
    spec = f"{commit}:{path}"
    try:
        size_result = _run_git(root, ["cat-file", "-s", spec])
    except (OSError, subprocess.SubprocessError):
        return None
    if size_result.returncode != 0:
        return None
    try:
        size = int(size_result.stdout.strip())
    except ValueError:
        return None
    if size < 0 or size > max_file_bytes:
        return None
    try:
        blob_result = _run_git(root, ["cat-file", "blob", spec])
    except (OSError, subprocess.SubprocessError):
        return None
    if blob_result.returncode != 0 or len(blob_result.stdout) > max_file_bytes:
        return None
    return blob_result.stdout


def scan_repository_secrets(
    target: Path,
    *,
    include_history: bool = False,
    max_commits: int = DEFAULT_MAX_COMMITS,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_findings: int = DEFAULT_MAX_FINDINGS,
) -> RepositorySecretScanResult:
    """Scan a local file/directory and optionally bounded Git history."""

    root = target.expanduser().resolve()
    if not root.exists():
        raise ValueError("secret scan target does not exist")
    max_commits = _bounded_positive(max_commits, default=DEFAULT_MAX_COMMITS, maximum=50_000)
    max_files = _bounded_positive(max_files, default=DEFAULT_MAX_FILES, maximum=100_000)
    max_file_bytes = _bounded_positive(max_file_bytes, default=DEFAULT_MAX_FILE_BYTES, maximum=32 * 1024 * 1024)
    max_total_bytes = _bounded_positive(
        max_total_bytes,
        default=DEFAULT_MAX_TOTAL_BYTES,
        maximum=4 * 1024 * 1024 * 1024,
    )
    max_findings = _bounded_positive(max_findings, default=DEFAULT_MAX_FINDINGS, maximum=10_000)

    if root.is_file():
        scan_root = root.parent
        working_paths = [root.name]
        git_repo = False
    else:
        scan_root = root
        git_repo = _is_git_repository(scan_root)
        working_paths = _git_working_paths(scan_root) if git_repo else None
        if working_paths is None:
            working_paths = _filesystem_paths(scan_root)

    findings: list[SecretFinding] = []
    errors: list[str] = []
    truncation_reasons: set[str] = set()
    files_scanned = 0
    commits_scanned = 0
    bytes_scanned = 0
    truncated = False

    for relative_path in working_paths:
        active_reasons = _active_limit_reasons(
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            finding_count=len(findings),
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_findings=max_findings,
        )
        if active_reasons:
            truncation_reasons.update(active_reasons)
            truncated = True
            break
        data = _read_working_file(scan_root, relative_path, max_file_bytes)
        if data is None:
            continue
        if bytes_scanned + len(data) > max_total_bytes:
            truncation_reasons.add("max_total_bytes")
            truncated = True
            break
        found, scanned_bytes = _scan_blob(
            data,
            path=relative_path.replace("\\", "/"),
            source="working_tree",
            commit=None,
            finding_budget=max_findings - len(findings),
        )
        files_scanned += 1
        bytes_scanned += scanned_bytes
        findings.extend(found)

    if include_history and git_repo:
        active_reasons = _active_limit_reasons(
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            finding_count=len(findings),
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_findings=max_findings,
        )
        if active_reasons:
            truncation_reasons.update(active_reasons)
            truncated = True
        else:
            commit_candidates = _git_commits(scan_root, max_commits + 1)
            if commit_candidates is None:
                errors.append("git_history_enumeration_failed")
                truncated = True
                commits: list[str] = []
            else:
                commits = commit_candidates[:max_commits]
                if len(commit_candidates) > max_commits:
                    truncation_reasons.add("max_commits")
                    truncated = True
            for commit in commits:
                active_reasons = _active_limit_reasons(
                    files_scanned=files_scanned,
                    bytes_scanned=bytes_scanned,
                    finding_count=len(findings),
                    max_files=max_files,
                    max_total_bytes=max_total_bytes,
                    max_findings=max_findings,
                )
                if active_reasons:
                    truncation_reasons.update(active_reasons)
                    truncated = True
                    break
                commits_scanned += 1
                changed_paths = _git_changed_paths(scan_root, commit)
                if changed_paths is None:
                    errors.append("git_history_changed_paths_failed")
                    truncated = True
                    continue
                for relative_path in changed_paths:
                    active_reasons = _active_limit_reasons(
                        files_scanned=files_scanned,
                        bytes_scanned=bytes_scanned,
                        finding_count=len(findings),
                        max_files=max_files,
                        max_total_bytes=max_total_bytes,
                        max_findings=max_findings,
                    )
                    if active_reasons:
                        truncation_reasons.update(active_reasons)
                        truncated = True
                        break
                    data = _git_blob(scan_root, commit, relative_path, max_file_bytes)
                    if data is None:
                        continue
                    if bytes_scanned + len(data) > max_total_bytes:
                        truncation_reasons.add("max_total_bytes")
                        truncated = True
                        break
                    found, scanned_bytes = _scan_blob(
                        data,
                        path=relative_path.replace("\\", "/"),
                        source="git_history",
                        commit=commit,
                        finding_budget=max_findings - len(findings),
                    )
                    files_scanned += 1
                    bytes_scanned += scanned_bytes
                    findings.extend(found)
    elif include_history and not git_repo:
        errors.append("history_requested_for_non_git_target")
        truncated = True

    # A provider rule can also be recognized by the contextual assignment rule.
    # Keep occurrences stable while preferring the stronger provider format.
    deduped: dict[tuple[str, int, str, str | None], SecretFinding] = {}
    for finding in findings:
        key = (finding.path, finding.line, finding.candidate, finding.commit)
        existing = deduped.get(key)
        if existing is None or finding.confidence_score > existing.confidence_score:
            deduped[key] = finding
    ordered = tuple(
        sorted(
            deduped.values(),
            key=lambda item: (item.commit or "", item.path, item.line, item.rule_id),
        )[:max_findings]
    )
    if len(deduped) > len(ordered):
        truncation_reasons.add("max_findings")
        truncated = True

    return RepositorySecretScanResult(
        findings=ordered,
        files_scanned=files_scanned,
        commits_scanned=commits_scanned,
        bytes_scanned=bytes_scanned,
        history_enabled=include_history,
        truncated=truncated,
        errors=tuple(errors),
        truncation_reasons=_ordered_truncation_reasons(truncation_reasons),
    )


__all__ = [
    "DEFAULT_MAX_COMMITS",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_FINDINGS",
    "DEFAULT_MAX_TOTAL_BYTES",
    "RepositorySecretScanResult",
    "scan_repository_secrets",
]

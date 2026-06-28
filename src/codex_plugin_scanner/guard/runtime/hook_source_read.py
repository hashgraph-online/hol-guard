"""Source-read fast-path evaluator for direct safe file reads.

This module implements the deterministic proof that a post-tool direct
file-read output is safe to return to the model in full, without a
reviewed-excerpt fallback.

The algorithm:
1. Validate request shape (event, source ref, action type).
2. Resolve the target path and reject sensitive/symlink/unsafe paths.
3. Read the file with a stat-before/stat-after TOCTOU guard.
4. Decode strict UTF-8 and compare output hash to the adapter's claim.
5. Check cache; on exact hit, return allow_original.
6. Run the streaming scanner; reject on secret match or budget exhaustion.
7. Save cache and return allow_original.

Security invariants:
- Never trust ``guard_source_ref`` alone — re-read, re-stat, re-hash.
- Never allow original output without exact hash match.
- Never bypass scanner/policy evaluation.
- Never broad-cache arbitrary stdout.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .hook_content_scanner import ContentScanMatch, ContentScanner
from .hook_decision_cache import HookDecisionCache, SourceReadCacheMaterial, hook_config_fingerprint
from .hook_review_types import HookReviewRequest
from .secret_sensitivity import classify_secret_path
from .source_paths import SOURCE_CLASSIFIER_VERSION, resolve_source_candidate_path, source_path_is_allowed

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore
    from .actions import GuardActionEnvelope

SOURCE_READ_FAST_PATH_VERSION = "source-read-fast-v1"
SOURCE_READ_MAX_SCAN_BYTES = 5 * 1024 * 1024
SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET = 1 * 1024 * 1024
SOURCE_READ_ALLOWED_EVENT = "PostToolUse"
SOURCE_READ_ALLOWED_ACTION_TYPE = "file_read"
SOURCE_READ_HASH_ENCODING = "utf-8"

_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class SourceReadProof:
    """Evidence that a source file was safely read and scanned."""

    realpath: str
    content_sha256: str
    output_sha256: str
    bytes_scanned: int
    stat_dev: int | None
    stat_ino: int | None
    stat_size: int
    stat_mtime_ns: int


@dataclass(frozen=True, slots=True)
class SourceReadFastPathResult:
    """Result of evaluating a source-file ref for the fast path."""

    status: Literal["allow_original", "risky", "inconclusive"]
    reason_code: str
    proof: SourceReadProof | None = None
    scanner_matches: tuple[ContentScanMatch, ...] = ()
    reviewed_excerpt: str | None = None


def stat_identity(stat_result: os.stat_result) -> tuple[int | None, int | None, int, int]:
    """Extract a stable identity tuple from a stat result."""
    return (
        getattr(stat_result, "st_dev", None),
        getattr(stat_result, "st_ino", None),
        int(stat_result.st_size),
        int(getattr(stat_result, "st_mtime_ns", int(stat_result.st_mtime * 1_000_000_000))),
    )


def sha256_text(text: str) -> str:
    """Return the SHA-256 hex digest of a string encoded as UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def output_equivalent(file_text: str, *, output_sha256: str, output_chars: int) -> bool:
    """Return True if file text matches the adapter's claimed output hash.

    Allows a single trailing newline difference (file may have trailing
    newline that the adapter stripped). No other transformations are
    accepted — no line-number formatting, banners, or truncation.
    """
    if sha256_text(file_text) == output_sha256 and len(file_text) == output_chars:
        return True
    if file_text.endswith("\n"):
        stripped = file_text[:-1]
        if sha256_text(stripped) == output_sha256 and len(stripped) == output_chars:
            return True
    return False


def evaluate_source_file_ref(
    *,
    request: HookReviewRequest,
    envelope: GuardActionEnvelope,
    scanner: ContentScanner,
    cache: HookDecisionCache,
    config: GuardConfig,
    store: GuardStore,
    deadline_monotonic: float,
) -> SourceReadFastPathResult:
    """Evaluate whether a direct source-file read is safe to return in full.

    Returns:
        - ``allow_original`` with proof if the file is safe and scanned.
        - ``risky`` if secrets were found in the file.
        - ``inconclusive`` if the fast path cannot prove safety (caller
          should fall back to full payload review, safe excerpt, or deny).
    """
    # 1. Shape validation.
    if request.event_name != SOURCE_READ_ALLOWED_EVENT:
        return SourceReadFastPathResult(status="inconclusive", reason_code="not_post_tool")
    if request.source_ref is None:
        return SourceReadFastPathResult(status="inconclusive", reason_code="missing_source_ref")
    if request.source_ref.version != 1:
        return SourceReadFastPathResult(status="inconclusive", reason_code="invalid_source_ref_version")
    if not _HEX_PATTERN.match(request.source_ref.output_sha256):
        return SourceReadFastPathResult(status="inconclusive", reason_code="invalid_output_hash")
    if request.source_ref.output_chars < 0 or request.source_ref.output_chars > SOURCE_READ_MAX_SCAN_BYTES:
        return SourceReadFastPathResult(status="inconclusive", reason_code="output_too_large")
    if envelope.action_type != SOURCE_READ_ALLOWED_ACTION_TYPE:
        return SourceReadFastPathResult(status="inconclusive", reason_code="not_file_read")
    if len(envelope.target_paths) != 1:
        return SourceReadFastPathResult(status="inconclusive", reason_code="not_single_target_path")

    source_ref = request.source_ref

    # 2. Resolve target path.
    #    The source ref's path fields are adapter-controlled and could
    #    point at a different file than the actual tool read target.
    #    Resolve the source ref candidate AND the envelope target, then
    #    require both to resolve to the same real path. This prevents
    #    a malformed source ref from pointing at a benign file while the
    #    actual tool read targeted a different file.
    candidate_path_str = source_ref.tool_input_path or source_ref.path or envelope.target_paths[0]
    resolved_path = resolve_source_candidate_path(
        candidate_path_str,
        cwd=request.cwd,
        home_dir=request.home_dir,
    )
    if resolved_path is None:
        return SourceReadFastPathResult(status="inconclusive", reason_code="unresolved_path")

    # Verify the source ref path matches the normalized envelope target.
    # Both must resolve to the same real path after symlink resolution.
    envelope_target_str = envelope.target_paths[0]
    envelope_resolved = resolve_source_candidate_path(
        envelope_target_str,
        cwd=request.cwd,
        home_dir=request.home_dir,
    )
    if envelope_resolved is None:
        return SourceReadFastPathResult(status="inconclusive", reason_code="unresolved_envelope_target")

    try:
        if os.path.realpath(resolved_path) != os.path.realpath(envelope_resolved):
            return SourceReadFastPathResult(status="inconclusive", reason_code="source_ref_target_mismatch")
    except OSError:
        return SourceReadFastPathResult(status="inconclusive", reason_code="source_ref_target_mismatch")

    # 3. Reject sensitive path (before source_path_is_allowed, so .env etc.
    #    return risky, not inconclusive).
    sensitive_match = classify_secret_path(
        str(resolved_path),
        cwd=request.cwd,
        home_dir=request.home_dir,
    )
    if sensitive_match is not None:
        return SourceReadFastPathResult(
            status="risky",
            reason_code="sensitive_path",
            scanner_matches=(
                ContentScanMatch(
                    classifier="sensitive-path",
                    family=sensitive_match.family,
                    sensitivity=sensitive_match.sensitivity,
                    reason=sensitive_match.reason,
                ),
            ),
        )

    # 4. Check source path is allowed (symlink, escape, hidden dirs).
    path_decision = source_path_is_allowed(
        candidate_path_str,
        cwd=request.cwd,
        home_dir=request.home_dir,
    )
    if not path_decision.allowed:
        return SourceReadFastPathResult(status="inconclusive", reason_code=path_decision.reason_code)

    # 5. Read with TOCTOU guard.
    try:
        pre_stat = resolved_path.stat()
    except OSError:
        return SourceReadFastPathResult(status="inconclusive", reason_code="stat_failed")

    if (pre_stat.st_mode & 0o170000) != 0o100000:  # S_ISREG
        return SourceReadFastPathResult(status="inconclusive", reason_code="not_regular_file")

    if pre_stat.st_size > SOURCE_READ_MAX_SCAN_BYTES:
        return SourceReadFastPathResult(status="inconclusive", reason_code="source_file_too_large")

    try:
        raw = resolved_path.read_bytes()
    except OSError:
        return SourceReadFastPathResult(status="inconclusive", reason_code="read_failed")

    if len(raw) > SOURCE_READ_MAX_SCAN_BYTES:
        return SourceReadFastPathResult(status="inconclusive", reason_code="source_read_limit_exceeded")

    try:
        post_stat = resolved_path.stat()
    except OSError:
        return SourceReadFastPathResult(status="inconclusive", reason_code="post_stat_failed")

    if stat_identity(pre_stat) != stat_identity(post_stat):
        return SourceReadFastPathResult(status="inconclusive", reason_code="source_stat_changed")

    # 5. Binary check.
    if b"\x00" in raw:
        return SourceReadFastPathResult(status="inconclusive", reason_code="binary_file")

    # 6. Decode strict UTF-8.
    try:
        text = raw.decode(SOURCE_READ_HASH_ENCODING)
    except UnicodeDecodeError:
        return SourceReadFastPathResult(status="inconclusive", reason_code="invalid_utf8")

    # 7. Output hash comparison.
    if not output_equivalent(
        text,
        output_sha256=source_ref.output_sha256,
        output_chars=source_ref.output_chars,
    ):
        return SourceReadFastPathResult(status="inconclusive", reason_code="output_mismatch")

    content_sha = sha256_text(text)
    stat_dev, stat_ino, stat_size, stat_mtime_ns = stat_identity(post_stat)

    # 8. Build cache material and check cache.
    workspace_hash = envelope.workspace_hash
    policy_fp = store.policy_fingerprint(harness=request.harness, workspace=request.cwd)
    config_fp = hook_config_fingerprint(config)
    scanner_version = scanner.version

    cache_material = SourceReadCacheMaterial(
        kind="source-read-v1",
        harness=request.harness,
        event_name=request.event_name,
        workspace_hash=workspace_hash,
        realpath=str(resolved_path),
        stat_dev=stat_dev,
        stat_ino=stat_ino,
        stat_size=stat_size,
        stat_mtime_ns=stat_mtime_ns,
        content_sha256=content_sha,
        output_sha256=source_ref.output_sha256,
        scanner_version=scanner_version,
        source_classifier_version=SOURCE_CLASSIFIER_VERSION,
        policy_fingerprint=policy_fp,
        config_fingerprint=config_fp,
    )

    cached = cache.get_source_read(cache_material)
    if cached is not None and cached.get("decision") == "allow_original":
        proof = SourceReadProof(
            realpath=str(resolved_path),
            content_sha256=content_sha,
            output_sha256=source_ref.output_sha256,
            bytes_scanned=len(raw),
            stat_dev=stat_dev,
            stat_ino=stat_ino,
            stat_size=stat_size,
            stat_mtime_ns=stat_mtime_ns,
        )
        return SourceReadFastPathResult(
            status="allow_original",
            reason_code="source_cache_hit",
            proof=proof,
        )

    # 9. Streaming scan.
    scan_result = scanner.scan_text(
        text,
        local_content=True,
        source_context=True,
        max_bytes=SOURCE_READ_MAX_SCAN_BYTES,
        deadline_monotonic=deadline_monotonic,
    )

    if scan_result.budget_exhausted:
        return SourceReadFastPathResult(
            status="inconclusive",
            reason_code="scanner_budget_exhausted",
            reviewed_excerpt=text[:SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET],
        )

    if scan_result.matches:
        return SourceReadFastPathResult(
            status="risky",
            reason_code="source_secret_match",
            scanner_matches=scan_result.matches,
        )

    # 10. Save cache and allow original.
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    cache.save_source_read(
        cache_material,
        {
            "decision": "allow_original",
            "reason_code": "source_full_scan_allow",
            "content_sha256": content_sha,
            "output_sha256": source_ref.output_sha256,
            "bytes_scanned": len(raw),
            "scanner_version": scanner_version,
            "source_classifier_version": SOURCE_CLASSIFIER_VERSION,
            "cached_at": now,
        },
        now=now,
    )

    proof = SourceReadProof(
        realpath=str(resolved_path),
        content_sha256=content_sha,
        output_sha256=source_ref.output_sha256,
        bytes_scanned=len(raw),
        stat_dev=stat_dev,
        stat_ino=stat_ino,
        stat_size=stat_size,
        stat_mtime_ns=stat_mtime_ns,
    )

    return SourceReadFastPathResult(
        status="allow_original",
        reason_code="source_full_scan_allow",
        proof=proof,
    )


__all__ = [
    "SOURCE_READ_ALLOWED_ACTION_TYPE",
    "SOURCE_READ_ALLOWED_EVENT",
    "SOURCE_READ_FAST_PATH_VERSION",
    "SOURCE_READ_FULL_MODEL_BYTES_P95_TARGET",
    "SOURCE_READ_HASH_ENCODING",
    "SOURCE_READ_MAX_SCAN_BYTES",
    "SourceReadFastPathResult",
    "SourceReadProof",
    "evaluate_source_file_ref",
    "output_equivalent",
    "sha256_text",
    "stat_identity",
]

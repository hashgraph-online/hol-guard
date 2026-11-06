"""Sanitized evidence contract for the Guarded Repository GitHub Action.

The evidence intentionally records scan/run metadata only. Scanner findings,
repository file paths, source content, prompts, commands, credentials, actor
identity, and private workflow inputs are excluded.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

SCHEMA_VERSION = "guarded-repository/v1"
CLAIM = (
    "Guarded Repository means this commit completed a versioned HOL Guard repository "
    "scan under the recorded configuration and produced a GitHub-signed provenance "
    "attestation. It does not mean vulnerability-free and does not prove runtime protection."
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[a-f0-9]{40}$")

Visibility = Literal["public", "private"]


@dataclass(frozen=True)
class GuardedRepositoryEvidence:
    schema_version: Literal["guarded-repository/v1"]
    repository: str
    commit_sha: str
    workflow_run_id: str
    scanner_version: str
    scanner_profile: str
    score: int
    grade: str
    max_severity: str
    findings_total: int
    sarif_sha256: str
    generated_at: str
    visibility: Visibility
    claim: str
    runtime_coverage_claimed: Literal[False]
    sensitive_content_included: Literal[False]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_guarded_repository_evidence(
    *,
    repository: str,
    commit_sha: str,
    workflow_run_id: str,
    scanner_version: str,
    scanner_profile: str,
    score: int,
    grade: str,
    max_severity: str,
    findings_total: int,
    sarif_sha256: str,
    visibility: Visibility,
    generated_at: datetime | None = None,
) -> GuardedRepositoryEvidence:
    if not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must be owner/name")
    if not _SHA_RE.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a lowercase 40-character git SHA")
    if not workflow_run_id.isdigit() or len(workflow_run_id) > 32:
        raise ValueError("workflow_run_id must be numeric")
    if not scanner_version or len(scanner_version) > 64:
        raise ValueError("scanner_version is invalid")
    if not scanner_profile or len(scanner_profile) > 64:
        raise ValueError("scanner_profile is invalid")
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
        raise ValueError("score must be an integer from 0 to 100")
    if not grade or len(grade) > 8:
        raise ValueError("grade is invalid")
    if max_severity not in {"none", "info", "low", "medium", "high", "critical"}:
        raise ValueError("max_severity is invalid")
    if not isinstance(findings_total, int) or isinstance(findings_total, bool) or findings_total < 0:
        raise ValueError("findings_total must be a non-negative integer")
    if not _SHA256_RE.fullmatch(sarif_sha256):
        raise ValueError("sarif_sha256 must be lowercase SHA-256")
    if visibility not in {"public", "private"}:
        raise ValueError("visibility must be public or private")
    observed = generated_at or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    return GuardedRepositoryEvidence(
        schema_version=SCHEMA_VERSION,
        repository=repository,
        commit_sha=commit_sha,
        workflow_run_id=workflow_run_id,
        scanner_version=scanner_version,
        scanner_profile=scanner_profile,
        score=score,
        grade=grade,
        max_severity=max_severity,
        findings_total=findings_total,
        sarif_sha256=sarif_sha256,
        generated_at=observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        visibility=visibility,
        claim=CLAIM,
        runtime_coverage_claimed=False,
        sensitive_content_included=False,
    )


def guarded_repository_evidence_json(evidence: GuardedRepositoryEvidence) -> str:
    return json.dumps(asdict(evidence), sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def guarded_repository_evidence_sha256(evidence: GuardedRepositoryEvidence) -> str:
    return hashlib.sha256(guarded_repository_evidence_json(evidence).encode("utf-8")).hexdigest()

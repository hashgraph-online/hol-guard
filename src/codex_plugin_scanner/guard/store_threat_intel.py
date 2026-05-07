"""Threat intelligence bundle cache storage.

Provides schema statements, write/read helpers, and migration tests for
caching signed advisory bundles and their match results locally.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime.threat_intel import ThreatIntelBundle


def threat_intel_bundle_schema_statement() -> str:
    """CREATE TABLE IF NOT EXISTS for guard_threat_intel_bundles."""
    return """
    CREATE TABLE IF NOT EXISTS guard_threat_intel_bundles (
        bundle_id     text primary key,
        version       integer not null,
        source        text not null,
        generated_at  real not null,
        expires_at    real not null,
        signature     text not null,
        advisories_json text not null default '[]',
        cached_at     real not null
    )
    """


def threat_intel_matches_schema_statement() -> str:
    """CREATE TABLE IF NOT EXISTS for guard_threat_intel_matches."""
    return """
    CREATE TABLE IF NOT EXISTS guard_threat_intel_matches (
        match_id        text primary key,
        bundle_id       text not null,
        advisory_id     text not null,
        artifact_id     text not null,
        harness         text not null default '',
        workspace       text not null default '',
        severity        text not null default 'info',
        matched_at      real not null,
        target_json     text not null default '{}'
    )
    """


def threat_intel_index_statements() -> tuple[str, ...]:
    """Index statements for threat intel cache tables."""
    return (
        "CREATE INDEX IF NOT EXISTS idx_ti_bundle_version ON guard_threat_intel_bundles(version DESC)",
        "CREATE INDEX IF NOT EXISTS idx_ti_bundle_expires ON guard_threat_intel_bundles(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_ti_match_bundle ON guard_threat_intel_matches(bundle_id)",
        "CREATE INDEX IF NOT EXISTS idx_ti_match_artifact ON guard_threat_intel_matches(artifact_id)",
        "CREATE INDEX IF NOT EXISTS idx_ti_match_severity ON guard_threat_intel_matches(severity, matched_at DESC)",
    )


@dataclass(frozen=True, slots=True)
class CachedBundle:
    """Lightweight cache row for a previously fetched bundle."""

    bundle_id: str
    version: int
    source: str
    generated_at: float
    expires_at: float
    signature: str
    advisories_json: str
    cached_at: float

    def is_fresh(self, now: float | None = None, skew: float = 300.0) -> bool:
        ts = now if now is not None else time.time()
        return ts <= self.expires_at + skew


@dataclass(frozen=True, slots=True)
class ThreatIntelMatch:
    """A single advisory match result stored for audit and dashboard display."""

    match_id: str
    bundle_id: str
    advisory_id: str
    artifact_id: str
    harness: str
    workspace: str
    severity: str
    matched_at: float
    target_json: str


def upsert_bundle(conn: sqlite3.Connection, bundle: ThreatIntelBundle, bundle_id: str) -> None:
    """Insert or replace a bundle row in the local cache."""
    conn.execute(
        """
        INSERT OR REPLACE INTO guard_threat_intel_bundles
            (bundle_id, version, source, generated_at, expires_at, signature, advisories_json, cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            bundle_id,
            bundle.version,
            bundle.source,
            bundle.generated_at,
            bundle.expires_at,
            bundle.signature,
            json.dumps([a.to_dict() for a in bundle.advisories]),
            time.time(),
        ),
    )


def latest_cached_bundle(conn: sqlite3.Connection) -> CachedBundle | None:
    """Return the cached bundle with the highest version, or None."""
    row = conn.execute(
        """
        SELECT bundle_id, version, source, generated_at, expires_at,
               signature, advisories_json, cached_at
        FROM guard_threat_intel_bundles
        ORDER BY version DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return None
    return CachedBundle(
        bundle_id=row[0],
        version=row[1],
        source=row[2],
        generated_at=row[3],
        expires_at=row[4],
        signature=row[5],
        advisories_json=row[6],
        cached_at=row[7],
    )


def insert_match(conn: sqlite3.Connection, match: ThreatIntelMatch) -> None:
    """Insert a threat intel match result."""
    conn.execute(
        """
        INSERT OR REPLACE INTO guard_threat_intel_matches
            (match_id, bundle_id, advisory_id, artifact_id, harness, workspace,
             severity, matched_at, target_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            match.match_id,
            match.bundle_id,
            match.advisory_id,
            match.artifact_id,
            match.harness,
            match.workspace,
            match.severity,
            match.matched_at,
            match.target_json,
        ),
    )


def list_matches(
    conn: sqlite3.Connection,
    artifact_id: str | None = None,
    harness: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[ThreatIntelMatch]:
    """List cached threat intel matches with optional filters."""
    clauses: list[str] = []
    params: list[object] = []
    if artifact_id is not None:
        clauses.append("artifact_id = ?")
        params.append(artifact_id)
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
        SELECT match_id, bundle_id, advisory_id, artifact_id, harness, workspace,
               severity, matched_at, target_json
        FROM guard_threat_intel_matches
        {where}
        ORDER BY matched_at DESC
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    return [
        ThreatIntelMatch(
            match_id=r[0],
            bundle_id=r[1],
            advisory_id=r[2],
            artifact_id=r[3],
            harness=r[4],
            workspace=r[5],
            severity=r[6],
            matched_at=r[7],
            target_json=r[8],
        )
        for r in rows
    ]

"""Threat intelligence bundle cache schema statements."""

from __future__ import annotations


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

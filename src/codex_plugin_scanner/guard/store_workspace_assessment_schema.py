"""Storage for background workspace assessments.

One state row per admitted worktree carries its dirty generation; one run row
per assessment attempt carries the snapshot it was bound to, its lease and its
bounded result. A worktree watched only because a harness install registered
it is marked, so its admission ends with the install. Customer source never
lands here: findings hold package coordinates and rule identifiers only. A fix proposal row binds one reviewed
manifest edit to the snapshot it was prepared against; it holds a bounded
diff of the edit and the byte offsets to apply it, never the manifest itself.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from .store_command_activity_schema import _validate_schema_object_sql

WORKSPACE_ASSESSMENT_MIGRATION_VERSION: Final = 33
WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION: Final = 34

MAX_COVERAGE_JSON_BYTES: Final = 16 * 1024
MAX_FINDINGS_JSON_BYTES: Final = 256 * 1024
MAX_FIX_DIFF_BYTES: Final = 64 * 1024
MAX_FIX_EDITS_JSON_BYTES: Final = 16 * 1024

_STATEMENTS: Final = (
    """
    CREATE TABLE IF NOT EXISTS workspace_assessment_state (
        codebase_key TEXT NOT NULL CHECK (length(codebase_key) = 64),
        worktree_key TEXT NOT NULL CHECK (length(worktree_key) = 64),
        private_root TEXT NOT NULL CHECK (length(private_root) <= 4096),
        observed_stat_digest TEXT CHECK (observed_stat_digest IS NULL OR length(observed_stat_digest) = 64),
        observed_feed_digest TEXT CHECK (observed_feed_digest IS NULL OR length(observed_feed_digest) = 64),
        dirty_generation INTEGER NOT NULL DEFAULT 0 CHECK (dirty_generation >= 0),
        last_completed_generation INTEGER NOT NULL DEFAULT 0,
        last_scan_at_ms INTEGER,
        paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
        admitted_at_ms INTEGER NOT NULL CHECK (admitted_at_ms >= 0),
        PRIMARY KEY (codebase_key, worktree_key),
        CHECK (last_completed_generation >= 0 AND last_completed_generation <= dirty_generation)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workspace_assessment_install_admissions (
        codebase_key TEXT NOT NULL,
        worktree_key TEXT NOT NULL,
        PRIMARY KEY (codebase_key, worktree_key),
        FOREIGN KEY (codebase_key, worktree_key)
            REFERENCES workspace_assessment_state(codebase_key, worktree_key) ON DELETE CASCADE
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS workspace_assessment_generation_monotonic
    BEFORE UPDATE OF dirty_generation, last_completed_generation ON workspace_assessment_state
    WHEN NEW.dirty_generation < OLD.dirty_generation
        OR NEW.last_completed_generation < OLD.last_completed_generation
    BEGIN SELECT RAISE(ABORT, 'assessment generations cannot move backward'); END
    """,
    """
    CREATE TABLE IF NOT EXISTS workspace_assessment_runs (
        run_id TEXT NOT NULL PRIMARY KEY CHECK (length(run_id) <= 64),
        codebase_key TEXT NOT NULL,
        worktree_key TEXT NOT NULL,
        snapshot_digest TEXT CHECK (snapshot_digest IS NULL OR length(snapshot_digest) = 64),
        input_manifest_digest TEXT CHECK (input_manifest_digest IS NULL OR length(input_manifest_digest) = 64),
        detector_set_digest TEXT NOT NULL CHECK (length(detector_set_digest) = 64),
        feed_context_digest TEXT CHECK (feed_context_digest IS NULL OR length(feed_context_digest) = 64),
        kind TEXT NOT NULL CHECK (kind IN ('deterministic', 'verification')),
        trigger_kind TEXT NOT NULL CHECK (trigger_kind IN
            ('workspace_open', 'file_change', 'feed_change', 'manual', 'fix_verification')),
        state TEXT NOT NULL CHECK (state IN
            ('queued', 'running', 'completed', 'partial', 'failed', 'canceled', 'superseded')),
        dirty_generation INTEGER NOT NULL CHECK (dirty_generation >= 0),
        lease_generation INTEGER NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
        lease_owner TEXT,
        lease_until_ms INTEGER,
        coverage_json TEXT NOT NULL DEFAULT '{}'
            CHECK (json_valid(coverage_json) AND json_type(coverage_json) = 'object'
                AND length(coverage_json) <= 16384),
        findings_json TEXT NOT NULL DEFAULT '[]'
            CHECK (json_valid(findings_json) AND json_type(findings_json) = 'array'
                AND length(findings_json) <= 262144),
        error_code TEXT CHECK (error_code IS NULL OR length(error_code) <= 128),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        triggered_at_ms INTEGER NOT NULL CHECK (triggered_at_ms >= created_at_ms),
        started_at_ms INTEGER,
        finished_at_ms INTEGER,
        FOREIGN KEY (codebase_key, worktree_key)
            REFERENCES workspace_assessment_state(codebase_key, worktree_key) ON DELETE CASCADE,
        CHECK (state NOT IN ('completed', 'partial', 'superseded') OR snapshot_digest IS NOT NULL),
        CHECK (state != 'running' OR (lease_owner IS NOT NULL AND lease_until_ms IS NOT NULL)),
        CHECK (state NOT IN ('completed', 'partial', 'failed', 'canceled', 'superseded')
            OR finished_at_ms IS NOT NULL),
        CHECK (finished_at_ms IS NULL OR finished_at_ms >= created_at_ms)
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS workspace_assessment_one_active
    ON workspace_assessment_runs (codebase_key, worktree_key) WHERE state = 'running'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS workspace_assessment_one_queued
    ON workspace_assessment_runs (codebase_key, worktree_key) WHERE state = 'queued'
    """,
    """
    CREATE INDEX IF NOT EXISTS workspace_assessment_recent
    ON workspace_assessment_runs (codebase_key, worktree_key, created_at_ms DESC)
    """,
)

_FIX_PROPOSAL_STATEMENTS: Final = (
    """
    CREATE TABLE IF NOT EXISTS workspace_fix_proposals (
        proposal_id TEXT NOT NULL PRIMARY KEY CHECK (length(proposal_id) <= 64),
        codebase_key TEXT NOT NULL,
        worktree_key TEXT NOT NULL,
        finding_id TEXT NOT NULL CHECK (length(finding_id) = 32),
        ecosystem TEXT NOT NULL CHECK (length(ecosystem) BETWEEN 1 AND 64),
        package_name TEXT NOT NULL CHECK (length(package_name) BETWEEN 1 AND 256),
        fix_version TEXT NOT NULL CHECK (length(fix_version) BETWEEN 1 AND 128),
        advisory_ids_json TEXT NOT NULL CHECK (
            json_valid(advisory_ids_json) AND json_type(advisory_ids_json) = 'array'
            AND length(advisory_ids_json) <= 16384
        ),
        rule_ids_json TEXT NOT NULL CHECK (
            json_valid(rule_ids_json) AND json_type(rule_ids_json) = 'array' AND length(rule_ids_json) <= 16384
        ),
        source_run_id TEXT NOT NULL CHECK (length(source_run_id) <= 64),
        snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
        manifest_path TEXT NOT NULL CHECK (length(manifest_path) <= 1024),
        base_sha256 TEXT NOT NULL CHECK (length(base_sha256) = 64),
        new_sha256 TEXT NOT NULL CHECK (length(new_sha256) = 64),
        edits_json TEXT NOT NULL
            CHECK (json_valid(edits_json) AND json_type(edits_json) = 'array' AND length(edits_json) <= 16384),
        diff_text TEXT NOT NULL CHECK (length(diff_text) <= 65536),
        state TEXT NOT NULL CHECK (state IN
            ('prepared', 'applied', 'stale', 'rejected', 'verified_fixed', 'still_present')),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
        applied_at_ms INTEGER,
        verified_at_ms INTEGER,
        verification_run_id TEXT CHECK (verification_run_id IS NULL OR length(verification_run_id) <= 64),
        FOREIGN KEY (codebase_key, worktree_key)
            REFERENCES workspace_assessment_state(codebase_key, worktree_key) ON DELETE CASCADE,
        CHECK (state NOT IN ('applied', 'verified_fixed', 'still_present') OR applied_at_ms IS NOT NULL)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS workspace_fix_proposals_recent
    ON workspace_fix_proposals (codebase_key, worktree_key, created_at_ms DESC)
    """,
)


def ensure_workspace_assessment_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    connection.execute("savepoint workspace_assessment_schema_v1")
    try:
        for statement in _STATEMENTS:
            connection.execute(statement)
        _validate_schema_object_sql(connection, _STATEMENTS, family_label="workspace assessment ", allow_unique=True)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (WORKSPACE_ASSESSMENT_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to workspace_assessment_schema_v1")
        connection.execute("release workspace_assessment_schema_v1")
        raise
    connection.execute("release workspace_assessment_schema_v1")


def ensure_workspace_fix_proposal_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    connection.execute("savepoint workspace_fix_proposal_schema_v1")
    try:
        for statement in _FIX_PROPOSAL_STATEMENTS:
            connection.execute(statement)
        _validate_schema_object_sql(connection, _FIX_PROPOSAL_STATEMENTS, family_label="workspace fix proposal ")
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to workspace_fix_proposal_schema_v1")
        connection.execute("release workspace_fix_proposal_schema_v1")
        raise
    connection.execute("release workspace_fix_proposal_schema_v1")


__all__ = [
    "MAX_COVERAGE_JSON_BYTES",
    "MAX_FINDINGS_JSON_BYTES",
    "MAX_FIX_DIFF_BYTES",
    "MAX_FIX_EDITS_JSON_BYTES",
    "WORKSPACE_ASSESSMENT_MIGRATION_VERSION",
    "WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION",
    "ensure_workspace_assessment_schema",
    "ensure_workspace_fix_proposal_schema",
]

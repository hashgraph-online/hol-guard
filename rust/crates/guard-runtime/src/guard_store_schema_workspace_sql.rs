//! The workspace assessment and fix proposal statements: a copy of
//! `store_workspace_assessment_schema.py`. A parity test on the Python side
//! holds the two copies equal.

/// `WORKSPACE_ASSESSMENT_MIGRATION_VERSION`.
pub(super) const ASSESSMENT_VERSION: i64 = 33;
/// `WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION`.
pub(super) const FIX_PROPOSAL_VERSION: i64 = 34;

/// `_STATEMENTS`.
pub(super) const ASSESSMENT_STATEMENTS: [&str; 8] = [
    r##"CREATE TABLE IF NOT EXISTS workspace_assessment_state (
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
)"##,
    r##"CREATE TABLE IF NOT EXISTS workspace_assessment_install_admissions (
    codebase_key TEXT NOT NULL,
    worktree_key TEXT NOT NULL,
    PRIMARY KEY (codebase_key, worktree_key),
    FOREIGN KEY (codebase_key, worktree_key)
        REFERENCES workspace_assessment_state(codebase_key, worktree_key) ON DELETE CASCADE
)"##,
    r##"CREATE TABLE IF NOT EXISTS workspace_assessment_ended_admissions (
    codebase_key TEXT NOT NULL,
    worktree_key TEXT NOT NULL,
    ended_at_ms INTEGER NOT NULL CHECK (ended_at_ms >= 0),
    PRIMARY KEY (codebase_key, worktree_key),
    FOREIGN KEY (codebase_key, worktree_key)
        REFERENCES workspace_assessment_state(codebase_key, worktree_key) ON DELETE CASCADE
)"##,
    r##"CREATE TRIGGER IF NOT EXISTS workspace_assessment_generation_monotonic
BEFORE UPDATE OF dirty_generation, last_completed_generation ON workspace_assessment_state
WHEN NEW.dirty_generation < OLD.dirty_generation
    OR NEW.last_completed_generation < OLD.last_completed_generation
BEGIN SELECT RAISE(ABORT, 'assessment generations cannot move backward'); END"##,
    r##"CREATE TABLE IF NOT EXISTS workspace_assessment_runs (
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
)"##,
    r##"CREATE UNIQUE INDEX IF NOT EXISTS workspace_assessment_one_active
ON workspace_assessment_runs (codebase_key, worktree_key) WHERE state = 'running'"##,
    r##"CREATE UNIQUE INDEX IF NOT EXISTS workspace_assessment_one_queued
ON workspace_assessment_runs (codebase_key, worktree_key) WHERE state = 'queued'"##,
    r##"CREATE INDEX IF NOT EXISTS workspace_assessment_recent
ON workspace_assessment_runs (codebase_key, worktree_key, created_at_ms DESC)"##,
];

/// `_FIX_PROPOSAL_STATEMENTS`.
pub(super) const FIX_PROPOSAL_STATEMENTS: [&str; 2] = [
    r##"CREATE TABLE IF NOT EXISTS workspace_fix_proposals (
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
)"##,
    r##"CREATE INDEX IF NOT EXISTS workspace_fix_proposals_recent
ON workspace_fix_proposals (codebase_key, worktree_key, created_at_ms DESC)"##,
];

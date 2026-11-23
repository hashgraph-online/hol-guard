//! Columns and indexes the store adds to tables created by older releases.
//!
//! A mirror of `store_schema_columns.py`: each list names the columns a table
//! gained after it first shipped, in the order the store adds them. A parity
//! test on the Python side holds the two copies equal.

use std::collections::BTreeSet;

use rusqlite::Connection;

pub(super) const POLICY_COLUMNS: [(&str, &str); 16] = [
    ("publisher", "text"),
    ("artifact_hash", "text"),
    ("owner", "text"),
    ("source", "text not null default 'local'"),
    ("expires_at", "text"),
    ("integrity_version", "integer"),
    ("integrity_generation", "integer"),
    ("payload_hash", "text"),
    ("payload_mac", "text"),
    ("integrity_key_id", "text"),
    ("signed_at", "text"),
    ("policy_document_schema_version", "text"),
    ("policy_document_id", "text"),
    ("policy_document_digest", "text"),
    ("policy_rule_id", "text"),
    ("policy_provenance_json", "text"),
];

pub(super) const LOCAL_ONCE_COLUMNS: [(&str, &str); 6] = [
    ("integrity_version", "integer"),
    ("payload_hash", "text"),
    ("payload_mac", "text"),
    ("integrity_key_id", "text"),
    ("signed_at", "text"),
    ("authority_kind", "text"),
];

pub(super) const RECEIPT_COLUMNS: [(&str, &str); 6] = [
    ("capabilities_summary", "text not null default ''"),
    ("scanner_evidence_json", "text not null default '[]'"),
    ("diff_summary", "text"),
    ("approval_source", "text"),
    ("approval_request_id", "text"),
    ("raw_command_text", "text"),
];

pub(super) const APPROVAL_COLUMNS: [(&str, &str); 26] = [
    ("artifact_type", "text not null default 'artifact'"),
    ("launch_target", "text"),
    ("transport", "text"),
    ("risk_summary", "text"),
    ("risk_signals_json", "text not null default '[]'"),
    ("artifact_label", "text"),
    ("source_label", "text"),
    ("trigger_summary", "text"),
    ("why_now", "text"),
    ("launch_summary", "text"),
    ("risk_headline", "text"),
    ("action_envelope_json", "text"),
    ("decision_v2_json", "text"),
    ("workspace", "text"),
    ("normalized_identity_key", "text"),
    ("action_identity", "text"),
    ("queue_group_id", "text"),
    ("dedupe_count", "integer not null default 1"),
    ("last_seen_at", "text"),
    ("fallback_cli_command", "text"),
    ("scanner_evidence_json", "text not null default '[]'"),
    ("browser_intent_json", "text"),
    ("desktop_notified_at", "text"),
    ("raw_command_text", "text"),
    ("continuation_snapshot_json", "text"),
    ("extension_allow_hint_json", "text"),
];

pub(super) const ATTACHMENT_COLUMNS: [(&str, &str); 2] = [
    ("lease_id", "text not null default ''"),
    ("lease_expires_at", "text"),
];

pub(super) const POLICY_INDEXES: [&str; 14] = [
    r##"create index if not exists idx_policy_decisions_reuse_artifact
on policy_decisions (action, harness, artifact_id, updated_at desc, decision_id desc)"##,
    r##"create index if not exists idx_policy_decisions_reuse_hash
on policy_decisions (action, harness, artifact_hash, updated_at desc, decision_id desc)"##,
    r##"create index if not exists idx_policy_decisions_reuse_publisher
on policy_decisions (action, harness, publisher, updated_at desc, decision_id desc)"##,
    r##"create index if not exists idx_policy_decisions_lookup_artifact
on policy_decisions (artifact_id, harness, artifact_hash, updated_at desc, decision_id desc)
where scope = 'artifact'"##,
    r##"create index if not exists idx_policy_decisions_lookup_workspace
on policy_decisions (workspace, harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
where scope = 'workspace'"##,
    r##"create index if not exists idx_policy_decisions_lookup_publisher
on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
where scope = 'publisher'"##,
    r##"create index if not exists idx_policy_decisions_lookup_publisher_legacy
on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
where scope = 'publisher' and artifact_hash is not null
  and artifact_hash not like 'guard-approval-context:v1:%'"##,
    r##"create index if not exists idx_policy_decisions_lookup_harness
on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
where scope = 'harness'"##,
    r##"create index if not exists idx_policy_decisions_lookup_harness_legacy
on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
where scope = 'harness' and artifact_hash is not null
  and artifact_hash not like 'guard-approval-context:v1:%'"##,
    r##"create index if not exists idx_policy_decisions_lookup_global
on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
where scope = 'global'"##,
    r##"create index if not exists idx_policy_decisions_lookup_global_legacy
on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
where scope = 'global' and artifact_hash is not null
  and artifact_hash not like 'guard-approval-context:v1:%'"##,
    r##"create index if not exists idx_policy_decisions_diagnostic_harness_broad
on policy_decisions (harness, updated_at desc, decision_id desc)
where scope = 'harness' and action = 'allow' and artifact_id is null"##,
    r##"create index if not exists idx_policy_decisions_diagnostic_global_broad
on policy_decisions (harness, updated_at desc, decision_id desc)
where scope = 'global' and action = 'allow' and artifact_id is null"##,
    r##"create index if not exists idx_policy_decisions_diagnostic_publisher
on policy_decisions (harness, publisher, updated_at desc, decision_id desc)
where scope = 'publisher' and action = 'allow'"##,
];

pub(super) const LOCAL_ONCE_INDEX: &str = r##"create index if not exists idx_guard_exact_cloud_local_once_lookup
on guard_local_once_approvals (authority_kind, request_id, claimed_at, expires_at)"##;

/// Adds each listed column the table does not have yet, in list order.
pub(super) fn ensure_columns(
    connection: &Connection,
    table: &str,
    columns: &[(&str, &str)],
) -> rusqlite::Result<()> {
    let mut existing = table_columns(connection, table)?;
    for (name, kind) in columns {
        if existing.contains(*name) {
            continue;
        }
        connection.execute_batch(&format!("alter table {table} add column {name} {kind}"))?;
        existing.insert((*name).to_owned());
    }
    Ok(())
}

pub(super) fn table_columns(
    connection: &Connection,
    table: &str,
) -> rusqlite::Result<BTreeSet<String>> {
    let mut statement = connection.prepare(&format!("pragma table_info({table})"))?;
    let names = statement.query_map([], |row| row.get::<_, String>(1))?;
    names.collect()
}

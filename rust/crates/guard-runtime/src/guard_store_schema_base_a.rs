//! The first half of the base tables, views and indexes the Guard store
//! creates before any migration runs: the `statements` list of
//! `_initialize_schema` in `store_connection_schema.py`, in the same order.
//! Each statement's indentation is removed.

pub(super) const FIRST: [&str; 30] = [
    r##"create table if not exists harness_installations (
  harness text primary key,
  active integer not null,
  workspace text,
  config_path text,
  metadata_json text not null default '{}',
  updated_at text not null
)"##,
    r##"create table if not exists artifact_snapshots (
  artifact_id text not null,
  harness text not null,
  snapshot_json text not null,
  artifact_hash text not null,
  recorded_at text not null,
  primary key (artifact_id, harness)
)"##,
    r##"create table if not exists artifact_hashes (
  artifact_id text not null,
  harness text not null,
  artifact_hash text not null,
  recorded_at text not null
)"##,
    r##"create table if not exists artifact_diffs (
  diff_id integer primary key autoincrement,
  artifact_id text not null,
  harness text not null,
  changed_fields_json text not null,
  previous_hash text,
  current_hash text not null,
  recorded_at text not null
)"##,
    r##"create table if not exists artifact_capabilities (
  artifact_id text not null,
  harness text not null,
  capability_json text not null,
  updated_at text not null,
  primary key (artifact_id, harness)
)"##,
    r##"create table if not exists provenance_cache (
  artifact_hash text primary key,
  payload_json text not null,
  updated_at text not null
)"##,
    r##"create table if not exists artifact_inventory (
  artifact_id text not null,
  harness text not null,
  artifact_name text not null,
  artifact_type text not null,
  source_scope text not null,
  config_path text not null,
  publisher text,
  origin_url text,
  launch_command text,
  transport text,
  first_seen_at text not null,
  last_seen_at text not null,
  last_changed_at text,
  last_approved_at text,
  removed_at text,
  present integer not null default 1,
  last_policy_action text not null,
  artifact_hash text not null,
  primary key (artifact_id, harness)
)"##,
    r##"create table if not exists policy_decisions (
  decision_id integer primary key autoincrement,
  harness text not null,
  scope text not null,
  artifact_id text,
  artifact_hash text,
  workspace text,
  publisher text,
  action text not null,
  reason text,
  owner text,
  source text not null default 'local',
  expires_at text,
  policy_document_schema_version text,
  policy_document_id text,
  policy_document_digest text,
  policy_rule_id text,
  policy_provenance_json text,
  updated_at text not null
)"##,
    r##"create table if not exists runtime_receipts (
  receipt_id text primary key,
  harness text not null,
  artifact_id text not null,
  artifact_hash text not null,
  policy_decision text not null,
  capabilities_summary text not null default '',
  changed_capabilities_json text not null,
  provenance_summary text not null,
  user_override text,
  artifact_name text,
  source_scope text,
  scanner_evidence_json text not null default '[]',
  timestamp text not null,
  raw_command_text text
)"##,
    r##"create table if not exists runtime_receipt_envelopes (
  receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
  envelope_full_json text,
  envelope_redacted_json text not null
)"##,
    r##"create table if not exists publisher_cache (
  publisher_key text primary key,
  payload_json text not null,
  updated_at text not null
)"##,
    r##"create table if not exists sync_state (
  state_key text primary key,
  payload_json text not null,
  updated_at text not null
)"##,
    r##"create table if not exists guard_devices (
  device_key text primary key,
  installation_id text not null,
  device_label text not null,
  created_at text not null,
  updated_at text not null
)"##,
    r##"create table if not exists schema_migrations (
  version integer primary key,
  applied_at text not null
)"##,
    r##"create table if not exists guard_events (
  event_id integer primary key autoincrement,
  event_name text not null,
  payload_json text not null,
  occurred_at text not null
)"##,
    r##"create index if not exists idx_guard_events_recent
on guard_events (occurred_at desc, event_id desc)"##,
    r##"create index if not exists idx_guard_events_name_recent
on guard_events (event_name, occurred_at desc, event_id desc)"##,
    r##"create table if not exists guard_exact_cloud_review_receipts (
  receipt_id text primary key,
  request_id text not null,
  claimed_at text not null
)"##,
    r##"create table if not exists guard_local_once_approvals (
  approval_id text primary key,
  request_id text not null,
  harness text not null,
  artifact_id text not null,
  artifact_hash text not null,
  workspace text,
  publisher text,
  action text not null,
  created_at text not null,
  expires_at text not null,
  claimed_at text,
  integrity_version integer,
  payload_hash text,
  payload_mac text,
  integrity_key_id text,
  signed_at text,
  authority_kind text
)"##,
    r##"create index if not exists idx_guard_local_once_approvals_lookup
on guard_local_once_approvals (claimed_at, harness, artifact_id, artifact_hash, expires_at)"##,
    r##"create index if not exists idx_guard_local_once_reuse_artifact
on guard_local_once_approvals (action, harness, artifact_id, created_at desc, approval_id desc)"##,
    r##"create index if not exists idx_guard_local_once_reuse_hash
on guard_local_once_approvals (action, harness, artifact_hash, created_at desc, approval_id desc)"##,
    r##"create index if not exists idx_guard_local_once_diagnostic_artifact
on guard_local_once_approvals (harness, artifact_id, created_at desc, approval_id desc)
where claimed_at is null and action = 'allow'"##,
    r##"create index if not exists idx_guard_local_once_diagnostic_hash
on guard_local_once_approvals (harness, artifact_hash, created_at desc, approval_id desc)
where claimed_at is null and action = 'allow'"##,
    r##"create table if not exists guard_approval_authority_revision (
  singleton integer primary key check (singleton = 1),
  revision integer not null
)"##,
    r##"insert or ignore into guard_approval_authority_revision (singleton, revision)
values (1, 0)"##,
    r##"create trigger if not exists trg_policy_decisions_authority_insert
after insert on policy_decisions begin
  update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
end"##,
    r##"create trigger if not exists trg_policy_decisions_authority_update
after update on policy_decisions begin
  update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
end"##,
    r##"create trigger if not exists trg_policy_decisions_authority_delete
after delete on policy_decisions begin
  update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
end"##,
    r##"create trigger if not exists trg_local_once_authority_insert
after insert on guard_local_once_approvals begin
  update guard_approval_authority_revision set revision = revision + 1 where singleton = 1;
end"##,
];

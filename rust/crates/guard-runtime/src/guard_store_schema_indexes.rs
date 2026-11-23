//! Index and table statements the store runs after its column upgrades.
//!
//! Mirrors of the Python statement lists named beside each constant. A parity
//! test on the Python side calls each list and holds the two copies equal.

/// The supply-chain cache indexes. Mirrors `store_supply_chain.supply_chain_index_statements`.
pub(super) const SUPPLY_CHAIN_INDEXES: [&str; 3] = [
    r##"CREATE INDEX IF NOT EXISTS idx_supply_chain_bundle_cached_at ON guard_supply_chain_bundle_cache(cached_at)"##,
    r##"CREATE INDEX IF NOT EXISTS idx_supply_chain_eval_bundle_version ON guard_supply_chain_eval_cache(bundle_version)"##,
    r##"CREATE INDEX IF NOT EXISTS idx_supply_chain_eval_updated_at ON guard_supply_chain_eval_cache(updated_at)"##,
];

/// The threat-intel cache indexes. Mirrors `store_threat_intel.threat_intel_index_statements`.
pub(super) const THREAT_INTEL_INDEXES: [&str; 5] = [
    r##"CREATE INDEX IF NOT EXISTS idx_ti_bundle_version ON guard_threat_intel_bundles(version DESC)"##,
    r##"CREATE INDEX IF NOT EXISTS idx_ti_bundle_expires ON guard_threat_intel_bundles(expires_at)"##,
    r##"CREATE INDEX IF NOT EXISTS idx_ti_match_bundle ON guard_threat_intel_matches(bundle_id)"##,
    r##"CREATE INDEX IF NOT EXISTS idx_ti_match_artifact ON guard_threat_intel_matches(artifact_id)"##,
    r##"CREATE INDEX IF NOT EXISTS idx_ti_match_severity ON guard_threat_intel_matches(severity, matched_at DESC)"##,
];

/// The approval-queue indexes. Mirrors `store_approvals.approval_index_statements`.
pub(super) const APPROVAL_INDEXES: [&str; 12] = [
    r##"create index if not exists idx_approval_status_created on approval_requests(status, created_at desc)"##,
    r##"create index if not exists idx_approval_status_harness_created on approval_requests(status, harness, created_at desc)"##,
    r##"create index if not exists idx_approval_status_identity_workspace on approval_requests(status, normalized_identity_key, workspace)"##,
    r##"create index if not exists idx_approval_source_group_status on approval_requests(oauth_source, queue_group_id, status)"##,
    r##"create index if not exists idx_approval_status_last_seen on approval_requests(status, last_seen_at desc, request_id desc)"##,
    r##"create index if not exists idx_approval_status_harness_last_seen on approval_requests(status, harness, last_seen_at desc, request_id desc)"##,
    r##"create index if not exists idx_approval_harness_status on approval_requests(harness, status)"##,
    r##"create index if not exists idx_approval_artifact_hash on approval_requests(artifact_hash)"##,
    r##"create index if not exists idx_approval_workspace_status on approval_requests(workspace, status)"##,
    r##"create index if not exists idx_approval_policy_action on approval_requests(policy_action)"##,
    r##"create index if not exists idx_approval_status_watch_last_seen on approval_requests(status, watch_only_observation, last_seen_at desc, request_id desc)"##,
    r##"create index if not exists idx_approval_resolution on approval_requests(resolution_action, resolved_at)"##,
];

/// The runtime-receipt indexes. Mirrors `store_base.receipt_index_statements`.
pub(super) const RECEIPT_INDEXES: [&str; 6] = [
    r##"create index if not exists idx_receipts_harness_artifact on runtime_receipts(harness, artifact_id)"##,
    r##"create index if not exists idx_receipts_timestamp_harness on runtime_receipts(timestamp, harness)"##,
    r##"create index if not exists idx_receipts_timestamp_desc on runtime_receipts(timestamp desc)"##,
    r##"create index if not exists idx_receipts_harness_timestamp_desc on runtime_receipts(harness, timestamp desc)"##,
    r##"create index if not exists idx_receipts_harness_artifact_timestamp_desc on runtime_receipts(harness, artifact_id, timestamp desc)"##,
    r##"create index if not exists idx_receipts_approval_request_decision on runtime_receipts(approval_request_id, policy_decision)"##,
];

/// The receipt rollup tables and triggers. Mirrors `store_receipt_rollup_schema.receipt_rollup_schema_statements`.
pub(super) const RECEIPT_ROLLUP_TABLES: [&str; 14] = [
    r##"create table if not exists receipt_aggregate_totals (
  totals_key text primary key,
  total integer not null default 0,
  allowed integer not null default 0,
  blocked integer not null default 0,
  reviewed integer not null default 0,
  first_activity_at text,
  last_activity_at text
)"##,
    r##"create table if not exists receipt_daily_rollups (
  day_key text primary key,
  total integer not null default 0,
  allowed integer not null default 0,
  blocked integer not null default 0,
  reviewed integer not null default 0
)"##,
    r##"create table if not exists receipt_harness_rollups (
  harness text primary key,
  total integer not null default 0,
  allowed integer not null default 0,
  blocked integer not null default 0,
  reviewed integer not null default 0
)"##,
    r##"create table if not exists receipt_artifact_rollups (
  artifact_key text primary key,
  total integer not null default 0,
  allowed integer not null default 0,
  blocked integer not null default 0,
  reviewed integer not null default 0
)"##,
    r##"create table if not exists receipt_rollup_actions (
  receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
  policy_decision text not null,
  dirty integer not null default 0 check (dirty in (0, 1))
)"##,
    r##"drop trigger if exists receipt_rollup_approval_update_dirty"##,
    r##"create trigger if not exists receipt_rollup_runtime_insert_dirty
after insert on runtime_receipts
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  values (new.receipt_id, new.policy_decision, 1)
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger if not exists receipt_rollup_runtime_authority_dirty
after update of policy_decision, approval_request_id on runtime_receipts
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  values (new.receipt_id, old.policy_decision, 1)
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger if not exists receipt_rollup_envelope_insert_dirty
after insert on runtime_receipt_envelopes
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  select r.receipt_id, r.policy_decision, 1
  from runtime_receipts r
  where r.receipt_id = new.receipt_id
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger if not exists receipt_rollup_envelope_update_dirty
after update of envelope_full_json, envelope_redacted_json on runtime_receipt_envelopes
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  select r.receipt_id, r.policy_decision, 1
  from runtime_receipts r
  where r.receipt_id = new.receipt_id
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger if not exists receipt_rollup_envelope_delete_dirty
after delete on runtime_receipt_envelopes
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  select r.receipt_id, r.policy_decision, 1
  from runtime_receipts r
  where r.receipt_id = old.receipt_id
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger if not exists receipt_rollup_approval_insert_dirty
after insert on approval_requests
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  select r.receipt_id, r.policy_decision, 1
  from runtime_receipts r
  where r.approval_request_id = new.request_id
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger receipt_rollup_approval_update_dirty
after update of status, resolution_action, resolved_at, policy_action,
                decision_v2_json, action_envelope_json on approval_requests
when old.status is not new.status
  or old.resolution_action is not new.resolution_action
  or old.resolved_at is not new.resolved_at
  or old.policy_action is not new.policy_action
  or old.decision_v2_json is not new.decision_v2_json
  or old.action_envelope_json is not new.action_envelope_json
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  select r.receipt_id, r.policy_decision, 1
  from runtime_receipts r
  where r.approval_request_id = new.request_id
  on conflict(receipt_id) do update set dirty = 1;
end"##,
    r##"create trigger if not exists receipt_rollup_approval_delete_dirty
after delete on approval_requests
begin
  insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
  select r.receipt_id, r.policy_decision, 1
  from runtime_receipts r
  where r.approval_request_id = old.request_id
  on conflict(receipt_id) do update set dirty = 1;
end"##,
];

/// The receipt rollup indexes. Mirrors `store_receipt_rollup_schema.receipt_rollup_index_statements`.
pub(super) const RECEIPT_ROLLUP_INDEXES: [&str; 4] = [
    r##"create index if not exists idx_receipt_daily_rollups_day on receipt_daily_rollups(day_key)"##,
    r##"create index if not exists idx_receipt_harness_rollups_total on receipt_harness_rollups(total desc)"##,
    r##"create index if not exists idx_receipt_artifact_rollups_total on receipt_artifact_rollups(total desc)"##,
    r##"create index if not exists idx_receipt_rollup_actions_dirty on receipt_rollup_actions(dirty) where dirty = 1"##,
];

/// The storage-maintenance singleton row and its table. Mirrors `store_storage_maintenance.storage_maintenance_schema_statements`.
pub(super) const STORAGE_MAINTENANCE: [&str; 2] = [
    r##"create table if not exists guard_storage_maintenance (
  singleton integer primary key check (singleton = 1),
  archived_receipts integer not null default 0,
  last_run_at text,
  last_receipts_archived integer not null default 0,
  last_guard_events_deleted integer not null default 0,
  last_cloud_events_deleted integer not null default 0,
  last_pages_reclaimed integer not null default 0
)"##,
    r##"insert or ignore into guard_storage_maintenance (singleton)
values (1)"##,
];

//! The command activity maintenance, API and display statements: a mirror of
//! `store_command_activity_maintenance_schema.py`,
//! `store_command_activity_api_schema.py` and
//! `store_command_activity_display_schema.py`. A parity test on the Python
//! side holds the copies equal.

pub(super) const MAINTENANCE_STATEMENTS: [&str; 10] = [
    r##"create table if not exists command_activity_rollup_membership (
  activity_id text primary key,
  day text not null,
  occurred_at text not null,
  rolled_at text not null,
  detail_present integer not null default 1 check (detail_present in (0, 1))
)"##,
    r##"create index if not exists idx_command_activity_rollup_membership_day
on command_activity_rollup_membership (detail_present, day, activity_id)"##,
    r##"create index if not exists idx_command_activity_rollup_membership_occurred_at
on command_activity_rollup_membership (detail_present, occurred_at, activity_id)"##,
    r##"create table if not exists command_activity_rollup_pending (
  activity_id text primary key,
  occurred_at text not null
)"##,
    r##"create table if not exists command_activity_maintenance (
  singleton integer primary key check (singleton = 1),
  last_completed_day text,
  last_run_at text,
  detail_compaction_started_at text,
  rollup_backfill_cursor_occurred_at text,
  rollup_backfill_cursor_activity_id text,
  rollup_backfill_complete integer not null default 0 check (rollup_backfill_complete in (0, 1)),
  last_backfilled_rows integer not null default 0 check (last_backfilled_rows >= 0),
  last_detail_rows_deleted integer not null default 0 check (last_detail_rows_deleted >= 0),
  last_correlation_rows_deleted integer not null default 0 check (last_correlation_rows_deleted >= 0),
  last_aggregate_rows_deleted integer not null default 0 check (last_aggregate_rows_deleted >= 0),
  schema_version text not null
)"##,
    r##"create trigger if not exists trg_command_activity_rollup_membership_parent
before insert on command_activity_rollup_membership
when not exists (
  select 1 from command_activity where activity_id = new.activity_id
)
begin
  select raise(abort, 'command activity rollup membership parent is missing');
end"##,
    r##"create trigger if not exists trg_command_activity_rollup_membership_detail_deleted
after delete on command_activity
begin
  update command_activity_rollup_membership
  set detail_present = 0 where activity_id = old.activity_id;
end"##,
    r##"create trigger if not exists trg_command_activity_rollup_pending_parent_inserted
after insert on command_activity
begin
  insert or ignore into command_activity_rollup_pending (activity_id, occurred_at)
  values (new.activity_id, new.occurred_at);
end"##,
    r##"create trigger if not exists trg_command_activity_rollup_pending_membership_inserted
after insert on command_activity_rollup_membership
begin
  delete from command_activity_rollup_pending where activity_id = new.activity_id;
end"##,
    r##"create trigger if not exists trg_command_activity_rollup_pending_parent_deleted
after delete on command_activity
begin
  delete from command_activity_rollup_pending where activity_id = old.activity_id;
end"##,
];

pub(super) const MAINTENANCE_SEED: &str = r##"insert or ignore into command_activity_maintenance (
  singleton, last_completed_day, last_run_at, detail_compaction_started_at,
  rollup_backfill_cursor_occurred_at, rollup_backfill_cursor_activity_id,
  rollup_backfill_complete,
  last_backfilled_rows,
  last_detail_rows_deleted, last_correlation_rows_deleted,
  last_aggregate_rows_deleted, schema_version
) values (1, null, null, null, null, null, 0, 0, 0, 0, 0, ?1)"##;

pub(super) const API_STATEMENTS: [&str; 13] = [
    r##"create table if not exists command_activity_feedback (
  activity_id text primary key references command_activity(activity_id) on delete cascade,
  label text not null check (
    label in ('should_not_have_interrupted', 'expected_guard_to_stop_this')
  ),
  created_at text not null,
  updated_at text not null,
  schema_version text not null
)"##,
    r##"create table if not exists command_activity_invalidations (
  sequence integer primary key autoincrement,
  activity_id text not null
)"##,
    r##"create index if not exists idx_command_activity_feedback_label
on command_activity_feedback (label, updated_at desc, activity_id desc)"##,
    r##"create index if not exists idx_command_activity_execution_status_occurred_at
on command_activity (execution_status, occurred_at desc, activity_id desc)"##,
    r##"create index if not exists idx_command_activity_proof_level_occurred_at
on command_activity (proof_level, occurred_at desc, activity_id desc)"##,
    r##"create index if not exists idx_command_activity_approval_reuse_occurred_at
on command_activity (approval_reuse_status, occurred_at desc, activity_id desc)"##,
    r##"create index if not exists idx_command_activity_prompted_occurred_at
on command_activity (prompted, occurred_at desc, activity_id desc)"##,
    r##"create trigger if not exists trg_command_activity_invalidation_insert
after insert on command_activity
begin
  insert into command_activity_invalidations (activity_id) values (new.activity_id);
  delete from command_activity_invalidations
  where sequence <= last_insert_rowid() - 10000;
end"##,
    r##"create trigger if not exists trg_command_activity_invalidation_update
after update on command_activity
begin
  insert into command_activity_invalidations (activity_id) values (new.activity_id);
  delete from command_activity_invalidations
  where sequence <= last_insert_rowid() - 10000;
end"##,
    r##"create trigger if not exists trg_command_activity_invalidation_delete
after delete on command_activity
begin
  insert into command_activity_invalidations (activity_id) values (old.activity_id);
  delete from command_activity_invalidations
  where sequence <= last_insert_rowid() - 10000;
end"##,
    r##"create trigger if not exists trg_command_activity_feedback_invalidation_insert
after insert on command_activity_feedback
begin
  insert into command_activity_invalidations (activity_id) values (new.activity_id);
  delete from command_activity_invalidations
  where sequence <= last_insert_rowid() - 10000;
end"##,
    r##"create trigger if not exists trg_command_activity_feedback_invalidation_update
after update on command_activity_feedback
begin
  insert into command_activity_invalidations (activity_id) values (new.activity_id);
  delete from command_activity_invalidations
  where sequence <= last_insert_rowid() - 10000;
end"##,
    r##"create trigger if not exists trg_command_activity_feedback_invalidation_delete
after delete on command_activity_feedback
begin
  insert into command_activity_invalidations (activity_id) values (old.activity_id);
  delete from command_activity_invalidations
  where sequence <= last_insert_rowid() - 10000;
end"##,
];

pub(super) const DISPLAY_STATEMENTS: [&str; 3] = [
    r##"create table if not exists command_activity_invocation (
  activity_id text primary key references command_activity(activity_id) on delete cascade,
  invocation_preview text not null check (
    length(invocation_preview) between 1 and 4096
  )
)"##,
    r##"create trigger if not exists trg_command_activity_invocation_immutable
before update on command_activity_invocation
begin
  select raise(abort, 'command_activity_invocation_immutable');
end"##,
    r##"create trigger if not exists trg_command_activity_invocation_parent
before insert on command_activity_invocation
when not exists (
  select 1 from command_activity where activity_id = new.activity_id
)
begin
  select raise(abort, 'command activity invocation parent is missing');
end"##,
];

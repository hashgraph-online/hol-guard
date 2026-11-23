//! The command activity schema statements: a mirror of
//! `store_command_activity_schema.py` and `store_command_activity_health_schema.py`.
//! A parity test on the Python side holds the two copies equal.

pub(super) const ACTIVITY_STATEMENTS: [&str; 21] = [
    r##"create table if not exists command_activity (
  activity_id text primary key,
  occurred_at text not null,
  harness text not null,
  hook_phase text not null,
  execution_status text not null,
  proof_level text not null,
  policy_action text,
  decision_reason_code text,
  controlling_rule_id text,
  parse_confidence text,
  uncertainty_class text,
  match_count integer not null check (match_count >= 0),
  prompted integer not null check (prompted in (0, 1)),
  approval_reuse_status text not null,
  receipt_link_status text not null,
  receipt_id text,
  evaluation_latency_bucket text not null,
  persistence_latency_bucket text not null,
  schema_version text not null
)"##,
    r##"create table if not exists command_activity_matches (
  activity_id text not null references command_activity(activity_id) on delete cascade,
  ordinal integer not null check (ordinal >= 0),
  extension_id text not null,
  extension_version text not null,
  rule_id text not null,
  rule_version text not null,
  match_class text not null,
  severity text not null,
  default_floor text not null,
  safe_variant_id text,
  schema_version text not null,
  primary key (activity_id, ordinal),
  unique (activity_id, rule_id)
)"##,
    r##"create table if not exists command_activity_match_effects (
  activity_id text not null,
  ordinal integer not null,
  effect_class text not null,
  primary key (activity_id, ordinal, effect_class),
  foreign key (activity_id, ordinal)
    references command_activity_matches(activity_id, ordinal) on delete cascade
)"##,
    r##"create table if not exists command_activity_correlations (
  activity_id text not null references command_activity(activity_id) on delete cascade,
  kind text not null,
  harness text not null,
  key_id text not null,
  digest text not null,
  primary key (activity_id, kind)
)"##,
    r##"create table if not exists command_activity_daily_totals (
  day text primary key,
  total integer not null default 0 check (total >= 0)
)"##,
    r##"create table if not exists command_activity_daily_rollups (
  day text not null,
  dimension text not null,
  dimension_value text not null,
  count integer not null default 0 check (count >= 0),
  primary key (day, dimension, dimension_value)
)"##,
    r##"create index if not exists idx_command_activity_occurred_at
on command_activity (occurred_at desc, activity_id desc)"##,
    r##"create index if not exists idx_command_activity_harness_occurred_at
on command_activity (harness, occurred_at desc, activity_id desc)"##,
    r##"create index if not exists idx_command_activity_match_rule
on command_activity_matches (rule_id, activity_id)"##,
    r##"create index if not exists idx_command_activity_match_extension
on command_activity_matches (extension_id, activity_id)"##,
    r##"create index if not exists idx_command_activity_correlation_lookup
on command_activity_correlations (kind, harness, key_id, digest)"##,
    r##"create unique index if not exists idx_command_activity_request_correlation_unique
on command_activity_correlations (harness, key_id, digest)
where kind = 'request'"##,
    r##"create trigger if not exists trg_command_activity_matches_parent
before insert on command_activity_matches
when not exists (
  select 1 from command_activity where activity_id = new.activity_id
)
begin
  select raise(abort, 'command activity match requires parent activity');
end"##,
    r##"create trigger if not exists trg_command_activity_effects_parent
before insert on command_activity_match_effects
when not exists (
  select 1 from command_activity_matches
  where activity_id = new.activity_id and ordinal = new.ordinal
)
begin
  select raise(abort, 'command activity effect requires parent match');
end"##,
    r##"create trigger if not exists trg_command_activity_correlations_parent
before insert on command_activity_correlations
when not exists (
  select 1 from command_activity where activity_id = new.activity_id
)
begin
  select raise(abort, 'command activity correlation requires parent activity');
end"##,
    r##"create trigger if not exists trg_command_activity_delete_children
after delete on command_activity
begin
  delete from command_activity_correlations where activity_id = old.activity_id;
  delete from command_activity_matches where activity_id = old.activity_id;
end"##,
    r##"create trigger if not exists trg_command_activity_match_delete_effects
after delete on command_activity_matches
begin
  delete from command_activity_match_effects
  where activity_id = old.activity_id and ordinal = old.ordinal;
end"##,
    r##"create trigger if not exists trg_command_activity_id_immutable
before update of activity_id on command_activity
when new.activity_id != old.activity_id
begin
  select raise(abort, 'command activity identity is immutable');
end"##,
    r##"create trigger if not exists trg_command_activity_match_parent_immutable
before update of activity_id, ordinal on command_activity_matches
when new.activity_id != old.activity_id or new.ordinal != old.ordinal
begin
  select raise(abort, 'command activity match parent is immutable');
end"##,
    r##"create trigger if not exists trg_command_activity_effect_parent_immutable
before update of activity_id, ordinal on command_activity_match_effects
when new.activity_id != old.activity_id or new.ordinal != old.ordinal
begin
  select raise(abort, 'command activity effect parent is immutable');
end"##,
    r##"create trigger if not exists trg_command_activity_correlation_parent_immutable
before update of activity_id on command_activity_correlations
when new.activity_id != old.activity_id
begin
  select raise(abort, 'command activity correlation parent is immutable');
end"##,
];

pub(super) const HEALTH_TABLE: &str = r##"create table if not exists command_activity_health (
  singleton integer primary key check (singleton = 1),
  dropped_event_count integer not null check (dropped_event_count between 0 and 9223372036854775807),
  persistence_error_count integer not null check (persistence_error_count between 0 and 9223372036854775807),
  last_error_code text check (last_error_code is null or length(last_error_code) between 1 and 64),
  last_error_at text,
  schema_version text not null
)"##;

pub(super) const HEALTH_ACTIVE_TABLE: &str = r##"create table if not exists command_activity_health_active (
  singleton integer primary key check (singleton = 1),
  command_error_active integer not null check (command_error_active in (0, 1)),
  shadow_error_active integer not null check (shadow_error_active in (0, 1)),
  maintenance_error_active integer not null check (maintenance_error_active in (0, 1)),
  foreign key (singleton) references command_activity_health(singleton) on delete cascade
)"##;

pub(super) const HEALTH_SEED: &str = r##"insert or ignore into command_activity_health (
  singleton, dropped_event_count, persistence_error_count,
  last_error_code, last_error_at, schema_version
) values (1, 0, 0, null, null, ?1)"##;

pub(super) const HEALTH_ACTIVE_SEED: &str = r##"insert or ignore into command_activity_health_active (
  singleton, command_error_active, shadow_error_active, maintenance_error_active
)
select singleton,
  case when last_error_code is null then 0 else 1 end,
  case when last_error_code is null then 0 else 1 end,
  case when last_error_code is null then 0 else 1 end
from command_activity_health where singleton = 1"##;

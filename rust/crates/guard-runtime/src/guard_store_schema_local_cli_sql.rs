//! The statements of `store_local_cli_schema.py`, `store_local_cli_capabilities.py`
//! and `store_local_cli_context.py`, which
//! `tests/test_native_schema_local_cli_parity.py` runs beside the Python step
//! and compares.

pub(super) const MIGRATION_TABLE: &str = r##"create table if not exists local_cli_schema_migration (
    singleton integer primary key check (singleton = 1),
    version integer not null,
    checksum text not null
)"##;

pub(super) const MARKER: &str =
    "select version, checksum from local_cli_schema_migration where singleton = 1";

pub(super) const MARKER_INSERT: &str =
    "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?1, ?2)";

pub(super) const MARKER_UPDATE: &str =
    "update local_cli_schema_migration set version = ?1, checksum = ?2 where singleton = 1";

pub(super) const OBSERVATION_TABLE: &str = r##"create table if not exists local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    kind text not null check (kind in ('executable', 'script')),
    name text not null,
    interpreter_name text,
    example_label text not null,
    observed_count integer not null check (observed_count >= 1),
    last_seen_at text not null,
    source_path text,
    help_status text,
    surface text not null default 'cli' check (surface in ('cli', 'mcp', 'package-scripts')),
    server_identity_hash text,
    server_command text,
    server_args_hash text,
    source_label text,
    remote_origin text,
    declared_sources_json text
)"##;

pub(super) const GRANT_TABLE: &str = r##"create table if not exists local_cli_grant (
    cli_id text primary key,
    identity_hash text not null,
    state text not null check (state in ('allowed', 'blocked')),
    revision integer not null check (revision >= 1),
    updated_at text not null
)"##;

pub(super) const AUTHORITY_TABLE: &str = r##"create table if not exists local_cli_authority (
    singleton integer primary key check (singleton = 1),
    revision integer not null check (revision >= 0)
)"##;

pub(super) const AUTHORITY_SEED: &str =
    "insert or ignore into local_cli_authority (singleton, revision) values (1, 0)";

pub(super) const COMMAND_TABLES: [&str; 2] = [
    r##"create table if not exists local_cli_command (
    cli_id text not null,
    command_id text not null,
    name text not null,
    usage text not null,
    description text not null,
    parent_id text,
    sort_index integer not null check (sort_index >= 0),
    primary key (cli_id, command_id)
)"##,
    r##"create table if not exists local_cli_command_grant (
    cli_id text not null,
    command_id text not null,
    state text not null check (state in ('inherit', 'allow', 'review', 'block')),
    primary key (cli_id, command_id)
)"##,
];

pub(super) const TOOL_AUTHORITY_TABLE: &str = r##"create table if not exists local_mcp_tool_authority (
    cli_id text not null, identity_hash text not null, tool_name text not null,
    catalog_revision integer not null, authority_hash text not null,
    primary key (cli_id, identity_hash, tool_name)
)"##;

pub(super) const WORKFLOW_PROPOSAL_TABLE: &str = r##"create table if not exists local_mcp_workflow_proposal (
    cli_id text not null, identity_hash text not null, proposal_id text not null,
    proposal_json text not null, seen_at text not null,
    primary key (cli_id, identity_hash, proposal_id)
)"##;

pub(super) const CATALOG_TABLE: &str = r##"create table if not exists local_mcp_catalog (
    cli_id text primary key,
    identity_hash text not null,
    catalog_json text not null,
    revision integer not null check (revision >= 1),
    updated_at text not null,
    last_complete_at text
)"##;

pub(super) const PROVIDER_GRANT_TABLE: &str = r##"create table if not exists local_mcp_provider_grant (
    cli_id text not null,
    identity_hash text not null,
    tool_slug text not null,
    state text not null check (state in ('review', 'block')),
    updated_at text not null,
    primary key (cli_id, identity_hash, tool_slug)
)"##;

pub(super) const PROVIDER_AUTHORITY_TABLE: &str = r##"create table if not exists local_mcp_provider_authority (
    cli_id text not null, identity_hash text not null, digest text not null,
    primary key (cli_id, identity_hash)
)"##;

pub(super) const PROVIDER_ACTION_TABLE: &str = r##"create table if not exists local_mcp_provider_action (
    cli_id text not null,
    identity_hash text not null,
    provider text not null check (provider = 'composio'),
    tool_slug text not null,
    toolkit text not null,
    description text not null,
    input_schema_json text not null,
    authority_hash text not null,
    full_schema integer not null check (full_schema in (0, 1)),
    source_tool text not null,
    revision integer not null check (revision >= 1),
    updated_at text not null,
    primary key (cli_id, identity_hash, provider, tool_slug)
)"##;

pub(super) const CAPABILITY_TABLE: &str = r##"create table if not exists local_cli_grant_capability (
    cli_id text not null,
    capability text not null
        check (capability in ('loopback-network', 'state-dir-read', 'state-dir-write')),
    state text not null check (state in ('on', 'off')),
    revision integer not null check (revision >= 1),
    updated_at text not null,
    primary key (cli_id, capability)
)"##;

/// `CONTEXT_COLUMNS`: every one is nullable text.
pub(super) const CONTEXT_COLUMNS: [(&str, &str); 6] = [
    ("first_blocked_cause", "text"),
    ("last_trigger_summary", "text"),
    ("last_why_now", "text"),
    ("last_harness", "text"),
    ("last_workspace_label", "text"),
    ("last_context_at", "text"),
];

/// `_migrate_v1_to_v2`: the source and help columns.
pub(super) const V2_COLUMNS: [(&str, &str); 2] = [("source_path", "text"), ("help_status", "text")];

/// `_migrate_v2_to_v3`: the surface and server columns.
pub(super) const V3_COLUMNS: [(&str, &str); 4] = [
    ("surface", "text not null default 'cli'"),
    ("server_identity_hash", "text"),
    ("server_command", "text"),
    ("server_args_hash", "text"),
];

/// `_migrate_v3_to_v4`: rebuild the observation table so `surface` carries
/// its check.
pub(super) const V4_REBUILD: [&str; 4] = [
    "alter table local_cli_observation rename to local_cli_observation_v3",
    r##"create table local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    kind text not null check (kind in ('executable', 'script')),
    name text not null,
    interpreter_name text,
    example_label text not null,
    observed_count integer not null check (observed_count >= 1),
    last_seen_at text not null,
    source_path text,
    help_status text,
    surface text not null default 'cli' check (surface in ('cli', 'mcp', 'package-scripts')),
    server_identity_hash text,
    server_command text,
    server_args_hash text
)"##,
    r##"insert into local_cli_observation (
    cli_id, identity_hash, kind, name, interpreter_name, example_label,
    observed_count, last_seen_at, source_path, help_status, surface,
    server_identity_hash, server_command, server_args_hash
)
select
    cli_id, identity_hash, kind, name, interpreter_name, example_label,
    observed_count, last_seen_at, source_path, help_status, surface,
    server_identity_hash, server_command, server_args_hash
from local_cli_observation_v3"##,
    "drop table local_cli_observation_v3",
];

/// `_migrate_v4_to_v5`: the source label column.
pub(super) const V5_COLUMNS: [(&str, &str); 1] = [("source_label", "text")];

/// `_migrate_v6_to_v7`: rebuild the command grant table so `state` carries
/// its current check. The command tables are created first and again after
/// the rename.
pub(super) const V7_RENAME: &str =
    "alter table local_cli_command_grant rename to local_cli_command_grant_v6";
pub(super) const V7_COPY: [&str; 2] = [
    "insert into local_cli_command_grant (cli_id, command_id, state) select cli_id, command_id, state from local_cli_command_grant_v6",
    "drop table local_cli_command_grant_v6",
];

/// `_migrate_v11_to_v12`: the remote origin and declared sources columns.
pub(super) const V12_COLUMNS: [(&str, &str); 2] =
    [("remote_origin", "text"), ("declared_sources_json", "text")];

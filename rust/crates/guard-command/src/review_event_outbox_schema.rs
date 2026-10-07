//! Schema and migration for the append-only local Review event outbox.
//!
//! Ports `store_review_event_outbox_schema.py` + the wake/upgrade submodules it
//! composes (`store_review_event_wake_schema`, `store_review_event_outbox_upgrade`,
//! `review_event_integrity`, `review_event_wake`). Every operation is expressed
//! against an injected `&mut dyn Connection` — the crate owns no rusqlite
//! dependency; the host (guard-runtime) supplies a `rusqlite`-backed
//! implementation inside a `BEGIN IMMEDIATE` transaction.

use std::path::Path;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// `sqlite3.Connection` seam (mirrors the `HttpTransport`/`StoreApi` pattern).
// ---------------------------------------------------------------------------

/// Row-cell value extracted from a `sqlite3.Row`.
#[derive(Debug, Clone, PartialEq)]
pub enum RowValue {
    Null,
    Integer(i64),
    Text(String),
}

impl RowValue {
    /// `int(value)` — SQLite columns that are already `INTEGER` stay as-is; a
    /// `TEXT` holding a decimal string is parsed. Anything else maps to 0 so the
    /// callers that do `int(row["col"] or 0)`/`int(row["col"])` remain total.
    pub fn as_i64(&self) -> i64 {
        match self {
            Self::Integer(v) => *v,
            Self::Text(v) => v.parse::<i64>().unwrap_or(0),
            Self::Null => 0,
        }
    }

    /// `str(value)` / direct `TEXT` extraction. `Null` → `""` (matches the
    /// Python `str(row["col"])` contract used on `payload_json`-style fields).
    pub fn as_str(&self) -> &str {
        match self {
            Self::Text(v) => v.as_str(),
            Self::Integer(_) | Self::Null => "",
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl From<i64> for RowValue {
    fn from(v: i64) -> Self {
        Self::Integer(v)
    }
}
impl From<String> for RowValue {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}
impl From<&str> for RowValue {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}

/// One `sqlite3.Row` keyed by column name. Indexing by name is the Python
/// `row["col"]` contract; `get` is the `row["col"]` with a default of `Null`.
pub type DbRow = Map<String, Value>;

/// `sqlite3.Connection.execute(sql, params).fetchall()/fetchone()` seam.
///
/// `params` uses `serde_json::Value` so callers can pass integers, strings, or
/// `Value::Null` for `NULL`. `execute` returns the affected row count
/// (`cursor.rowcount`).
pub trait Connection {
    /// `execute(sql, params)` → affected rows (`cursor.rowcount`).
    fn execute(&mut self, sql: &str, params: &[Value]) -> Result<i64, String>;
    /// `execute(sql, params).fetchone()` → one row keyed by column name.
    fn query_row(&mut self, sql: &str, params: &[Value]) -> Result<Option<DbRow>, String>;
    /// `execute(sql, params).fetchall()` → rows keyed by column name.
    fn query_all(&mut self, sql: &str, params: &[Value]) -> Result<Vec<DbRow>, String>;
    /// `executemany(sql, seq_of_params)` → total affected rows.
    fn executemany(&mut self, sql: &str, params_seq: &[Vec<Value>]) -> Result<i64, String>;
    /// `commit()` — durable commit of the surrounding transaction.
    fn commit(&mut self) -> Result<(), String>;
    /// `rollback()` — abort the surrounding transaction.
    fn rollback(&mut self) -> Result<(), String>;
    /// `connection.total_changes` snapshot used by `commit_review_event_transaction`.
    fn total_changes(&self) -> i64;
}

/// Convenience: `row["name"]` → `Value` (Null when absent).
pub fn row_get<'a>(row: &'a DbRow, name: &str) -> &'a Value {
    row.get(name).unwrap_or(&Value::Null)
}

pub fn row_i64(row: &DbRow, name: &str) -> i64 {
    match row.get(name) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

pub fn row_str<'a>(row: &'a DbRow, name: &str) -> &'a str {
    match row.get(name) {
        Some(Value::String(s)) => s.as_str(),
        _ => "",
    }
}

pub fn row_is_null(row: &DbRow, name: &str) -> bool {
    matches!(row.get(name), None | Some(Value::Null))
}

pub fn row_value<'a>(row: &'a DbRow, name: &str) -> &'a Value {
    row.get(name).unwrap_or(&Value::Null)
}

// ---------------------------------------------------------------------------
// `review_event_integrity.py` — HMAC payload digest.
// ---------------------------------------------------------------------------

const INTEGRITY_DOMAIN: &[u8] = b"hol-guard-review-event-integrity-v1";

/// `review_event_payload_digest` — `hmac.digest(DOMAIN + b"\0" + binding,
/// payload_json, "sha256")`. `None` binding members map to `""`.
pub fn review_event_payload_digest(
    payload_json: &str,
    oauth_source: Option<&str>,
    oauth_subject_hash: Option<&str>,
    workspace_id: Option<&str>,
    machine_id: Option<&str>,
    machine_installation_id: Option<&str>,
) -> String {
    let members = [
        oauth_source,
        oauth_subject_hash,
        workspace_id,
        machine_id,
        machine_installation_id,
    ];
    let mut binding = String::new();
    for (index, member) in members.iter().enumerate() {
        if index > 0 {
            binding.push('\0');
        }
        binding.push_str(member.unwrap_or(""));
    }
    // Manual HMAC-SHA256 — the `hmac` crate is not a guard-command dep.
    const BLOCK: usize = 64;
    let mut key = [0u8; BLOCK];
    let material = [INTEGRITY_DOMAIN, b"\0", binding.as_bytes()].concat();
    let material_hash = if material.len() > BLOCK {
        let digest = Sha256::digest(&material);
        let mut buf = [0u8; BLOCK];
        buf[..32].copy_from_slice(&digest);
        buf.to_vec()
    } else {
        material.clone()
    };
    key[..material_hash.len().min(BLOCK)]
        .copy_from_slice(&material_hash[..material_hash.len().min(BLOCK)]);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(payload_json.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    hex::encode(outer.finalize())
}

// ---------------------------------------------------------------------------
// `store_review_event_wake_schema.py` — durable mutation generation.
// ---------------------------------------------------------------------------

fn row_generation_trigger(operation: &str) -> String {
    format!(
        "
        create trigger if not exists guard_review_outbox_wake_after_{operation}
        after {operation} on guard_review_outbox_events
        begin
          update guard_review_outbox_wake_state
          set generation = generation + 1
          where singleton = 1;
        end
        ",
    )
}

fn update_generation_trigger() -> String {
    "create trigger if not exists guard_review_outbox_wake_after_update
     after update on guard_review_outbox_events
     begin
       update guard_review_outbox_wake_state
       set generation = generation + 1
       where singleton = 1;
     end"
    .to_string()
}

/// `review_event_wake_schema_statements()` — schema objects that count every
/// committed outbox row mutation.
pub fn review_event_wake_schema_statements() -> Vec<String> {
    vec![
        "
        create table if not exists guard_review_outbox_wake_state (
          singleton integer primary key check(singleton = 1),
          generation integer not null
        )
        "
        .to_string(),
        "
        insert or ignore into guard_review_outbox_wake_state (singleton, generation)
        values (1, 0)
        "
        .to_string(),
        row_generation_trigger("insert"),
        update_generation_trigger(),
        row_generation_trigger("delete"),
    ]
}

/// `review_event_outbox_generation` — durable outbox mutation generation, or 0
/// before setup.
pub fn review_event_outbox_generation(connection: &mut dyn Connection) -> i64 {
    let table = connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = 'guard_review_outbox_wake_state'",
            &[],
        )
        .ok()
        .flatten();
    if table.is_none() {
        return 0;
    }
    connection
        .query_row(
            "select generation from guard_review_outbox_wake_state where singleton = 1",
            &[],
        )
        .ok()
        .flatten()
        .map(|row| row_i64(&row, "generation"))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// `review_event_wake.py` — process-local wake signal.
// ---------------------------------------------------------------------------

/// `ReviewEventWakeSignal.notify_if_outbox_changed` seam — implemented by the
/// host so a committed generation change wakes the sync worker.
pub trait ReviewEventWakeApi {
    /// `notify_if_outbox_changed(generation)` — no-op when the generation is
    /// unchanged or the signal has already fired for it.
    fn notify_if_outbox_changed(&mut self, outbox_generation: i64);
}

/// `review_event_wake_signal(database_path)` — host seam that resolves the
/// process-local signal for one database path.
pub trait ReviewEventWakeLocator {
    fn wake_signal(&self, database_path: &Path) -> Box<dyn ReviewEventWakeApi>;
}

// ---------------------------------------------------------------------------
// Module constants.
// ---------------------------------------------------------------------------

/// `REVIEW_EVENT_SCHEMA_VERSION`.
pub const REVIEW_EVENT_SCHEMA_VERSION: i64 = 1;
/// `REVIEW_EVENT_SCHEMA_NAME`.
pub const REVIEW_EVENT_SCHEMA_NAME: &str = "guard-cloud-review-event-v2";
/// `REVIEW_EVENT_OUTBOX_MIGRATION_VERSION`.
pub const REVIEW_EVENT_OUTBOX_MIGRATION_VERSION: i64 = 25;
/// `_RETIRED_OUTBOX_MIGRATION_STATE_KEY`.
pub const RETIRED_OUTBOX_MIGRATION_STATE_KEY: &str = "guard_review_outbox_events_migrated";

/// `REVIEW_REQUEST_SNAPSHOT_COLUMNS` — the immutable request-snapshot contract.
pub const REVIEW_REQUEST_SNAPSHOT_COLUMNS: &[&str] = &[
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "publisher",
    "policy_action",
    "recommended_scope",
    "changed_fields_json",
    "source_scope",
    "oauth_source",
    "config_path",
    "workspace",
    "launch_target",
    "normalized_identity_key",
    "action_identity",
    "queue_group_id",
    "dedupe_count",
    "last_seen_at",
    "transport",
    "risk_summary",
    "risk_signals_json",
    "artifact_label",
    "source_label",
    "trigger_summary",
    "why_now",
    "launch_summary",
    "risk_headline",
    "action_envelope_json",
    "decision_v2_json",
    "fallback_cli_command",
    "scanner_evidence_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "desktop_notified_at",
    "raw_command_text",
    "guard_version",
    "first_seen_guard_version",
    "last_seen_guard_version",
    "watch_only_observation",
    "review_command",
    "approval_url",
    "status",
    "resolution_action",
    "resolution_scope",
    "reason",
    "created_at",
    "resolved_at",
];

// ---------------------------------------------------------------------------
// Schema statement assembly.
// ---------------------------------------------------------------------------

/// `review_event_outbox_schema_statements()` — all `CREATE`/`DROP` DDL that owns
/// the outbox tables, indexes, and update trigger.
pub fn review_event_outbox_schema_statements() -> Vec<String> {
    let mut statements = vec![
        "
        create table if not exists guard_review_outbox_events (
          stream_sequence integer primary key autoincrement,
          event_id text not null unique,
          local_request_id text not null,
          request_sequence integer not null,
          event_type text not null,
          event_schema_version integer not null,
          payload_json text not null,
          payload_hash text not null,
          occurred_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text,
          binding_status text not null check(binding_status in ('ready', 'quarantined')),
          quarantine_reason text,
          acknowledged_at text,
          attempt_count integer not null default 0,
          next_attempt_at text,
          last_error text,
          unique(local_request_id, request_sequence)
        )
        "
        .to_string(),
        "
        create table if not exists guard_review_outbox_cursors (
          oauth_source text not null,
          oauth_subject_hash text not null,
          workspace_id text not null,
          machine_id text not null,
          machine_installation_id text not null,
          acknowledged_stream_sequence integer not null default 0,
          updated_at text not null,
          primary key (
            oauth_source, oauth_subject_hash, workspace_id, machine_id,
            machine_installation_id
          )
        )
        "
        .to_string(),
        "
        create table if not exists guard_review_outbox_request_sequences (
          local_request_id text primary key,
          last_sequence integer not null default 0,
          updated_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text
        )
        "
        .to_string(),
        "
        create index if not exists idx_guard_review_outbox_ready
        on guard_review_outbox_events (binding_status, acknowledged_at, stream_sequence)
        "
        .to_string(),
        "
        create index if not exists idx_guard_review_outbox_request
        on guard_review_outbox_events (local_request_id, request_sequence)
        "
        .to_string(),
        "
        create index if not exists idx_guard_review_outbox_quarantine
        on guard_review_outbox_events (binding_status, quarantine_reason, stream_sequence)
        "
        .to_string(),
        "
        create index if not exists idx_guard_review_outbox_empty_payload_digest
        on guard_review_outbox_events (payload_hash) where payload_hash = ''
        "
        .to_string(),
        "
        create trigger if not exists guard_approval_oauth_source_immutable
        before update of oauth_source on approval_requests
        when old.oauth_source is not null and new.oauth_source is not old.oauth_source
        begin
          select raise(abort, 'approval OAuth source is immutable');
        end
        "
        .to_string(),
    ];
    statements.extend(review_event_wake_schema_statements());
    statements
}

// ---------------------------------------------------------------------------
// Payload assembly.
// ---------------------------------------------------------------------------

fn binding_value(column: &str) -> String {
    format!(
        "(
      select {column}
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    )"
    )
}

/// `review_event_payload_json` — canonical immutable event payload from a
/// complete request row. Returns `Err` listing the missing columns.
pub fn review_event_payload_json(
    request: &Map<String, Value>,
    event_type: &str,
    occurred_at: &str,
    continuation_result: Option<&Map<String, Value>>,
    native_replay: bool,
) -> Result<String, String> {
    let missing: Vec<String> = REVIEW_REQUEST_SNAPSHOT_COLUMNS
        .iter()
        .filter(|column| !request.contains_key(**column))
        .map(|column| (*column).to_string())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "Review request snapshot is missing columns: {}",
            missing.join(", ")
        ));
    }
    let mut snapshot = Map::with_capacity(REVIEW_REQUEST_SNAPSHOT_COLUMNS.len());
    for column in REVIEW_REQUEST_SNAPSHOT_COLUMNS {
        snapshot.insert(
            (*column).to_string(),
            request.get(*column).cloned().unwrap_or(Value::Null),
        );
    }
    let mut payload = Map::new();
    payload.insert(
        "schema".to_string(),
        Value::String(REVIEW_EVENT_SCHEMA_NAME.to_string()),
    );
    payload.insert(
        "localRequestId".to_string(),
        request.get("request_id").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "eventType".to_string(),
        Value::String(event_type.to_string()),
    );
    payload.insert(
        "occurredAt".to_string(),
        Value::String(occurred_at.to_string()),
    );
    payload.insert(
        "status".to_string(),
        request.get("status").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "resolutionAction".to_string(),
        request
            .get("resolution_action")
            .cloned()
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "resolutionScope".to_string(),
        request
            .get("resolution_scope")
            .cloned()
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "reason".to_string(),
        request.get("reason").cloned().unwrap_or(Value::Null),
    );
    payload.insert(
        "oauthSource".to_string(),
        request.get("oauth_source").cloned().unwrap_or(Value::Null),
    );
    payload.insert("requestSnapshot".to_string(), Value::Object(snapshot));
    if let Some(result) = continuation_result {
        payload.insert(
            "continuationResult".to_string(),
            Value::Object(result.clone()),
        );
    }
    if event_type == "review.request.snapshot_requeued" {
        payload.insert("nativeReplay".to_string(), Value::Bool(native_replay));
    }
    // `json.dumps(payload, sort_keys=True, separators=(",", ":"))`.
    serde_json::to_string(&Value::Object(payload)).map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// Trigger bodies.
// ---------------------------------------------------------------------------

fn event_payload(prefix: &str, event_type: &str) -> String {
    // `json.dumps(payload, sort_keys=True, separators=(",", ":"))` expressed in
    // SQL so the trigger emits the same canonical bytes the Python side builds.
    let snapshot = REVIEW_REQUEST_SNAPSHOT_COLUMNS
        .iter()
        .map(|column| format!("'{column}', {prefix}.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "(select json_object(
           'schema', '{REVIEW_EVENT_SCHEMA_NAME}',
           'localRequestId', {prefix}.request_id,
           'eventType', '{event_type}',
           'occurredAt', coalesce({prefix}.last_seen_at, {prefix}.created_at),
           'status', {prefix}.status,
           'resolutionAction', {prefix}.resolution_action,
           'resolutionScope', {prefix}.resolution_scope,
           'reason', {prefix}.reason,
           'oauthSource', {prefix}.oauth_source,
           'requestSnapshot', json_object({snapshot})
         ))"
    )
}

fn insert_trigger() -> String {
    let payload = event_payload("new", "review.request.created");
    format!(
        "
        create trigger if not exists guard_review_outbox_after_insert
        after insert on approval_requests
        begin
          insert into guard_review_outbox_request_sequences (
            local_request_id, last_sequence, updated_at
          ) values (new.request_id, 1, coalesce(new.last_seen_at, new.created_at))
          on conflict(local_request_id) do update set
            last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
            updated_at = excluded.updated_at;
          insert into guard_review_outbox_events (
            event_id, local_request_id, request_sequence, event_type,
            event_schema_version, payload_json, payload_hash, occurred_at,
            oauth_source, binding_status, quarantine_reason
          ) values (
            lower(hex(randomblob(16))),
            new.request_id,
            (select last_sequence from guard_review_outbox_request_sequences
             where local_request_id = new.request_id),
            'review.request.created',
            {REVIEW_EVENT_SCHEMA_VERSION},
            {payload},
            '',
            coalesce(new.last_seen_at, new.created_at),
            new.oauth_source,
            'quarantined',
            'identity_incomplete'
          );
        end
        ",
    )
}

fn update_trigger() -> String {
    let event_type = "(select case when new.status = 'pending' then 'review.request.refreshed' else 'review.request.resolved' end)";
    let payload = format!(
        "(select json_object(
           'schema', '{REVIEW_EVENT_SCHEMA_NAME}',
           'localRequestId', new.request_id,
           'eventType', {event_type},
           'occurredAt', coalesce(new.resolved_at, new.last_seen_at, new.created_at),
           'status', new.status,
           'resolutionAction', new.resolution_action,
           'resolutionScope', new.resolution_scope,
           'reason', new.reason,
           'oauthSource', new.oauth_source,
           'requestSnapshot', json_object({})
         ))",
        REVIEW_REQUEST_SNAPSHOT_COLUMNS
            .iter()
            .map(|column| format!("'{column}', new.{column}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let source = "coalesce(new.oauth_source, (select oauth_source from guard_review_outbox_request_sequences where local_request_id = new.request_id))";
    let subject = binding_value("oauth_subject_hash");
    let workspace = binding_value("workspace_id");
    let machine = binding_value("machine_id");
    let installation = binding_value("machine_installation_id");
    let complete = format!(
        "{source} is not null and {subject} is not null and {workspace} is not null and {machine} is not null and {installation} is not null"
    );
    format!(
        "
        create trigger if not exists guard_review_outbox_after_update
        after update on approval_requests
        begin
          insert into guard_review_outbox_request_sequences (
            local_request_id, last_sequence, updated_at
          ) values (new.request_id, 1, coalesce(new.resolved_at, new.last_seen_at, new.created_at))
          on conflict(local_request_id) do update set
            last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
            updated_at = excluded.updated_at;
          insert into guard_review_outbox_events (
            event_id, local_request_id, request_sequence, event_type,
            event_schema_version, payload_json, payload_hash, occurred_at,
            oauth_source, oauth_subject_hash, workspace_id, machine_id,
            machine_installation_id, binding_status, quarantine_reason
          ) values (
            lower(hex(randomblob(16))),
            new.request_id,
            (select last_sequence from guard_review_outbox_request_sequences
             where local_request_id = new.request_id),
            {event_type},
            {REVIEW_EVENT_SCHEMA_VERSION},
            {payload},
            '',
            coalesce(new.resolved_at, new.last_seen_at, new.created_at),
            {source},
            {subject},
            {workspace},
            {machine},
            {installation},
            case when {complete} then 'ready' else 'quarantined' end,
            case when {complete} then null else 'identity_incomplete' end
          );
        end
        ",
    )
}

// ---------------------------------------------------------------------------
// Retired-outbox migration.
// ---------------------------------------------------------------------------

fn retired_outbox_marker_payload(row: &DbRow) -> String {
    let mut payload = Map::new();
    payload.insert(
        "schema".to_string(),
        Value::String(REVIEW_EVENT_SCHEMA_NAME.to_string()),
    );
    payload.insert(
        "localRequestId".to_string(),
        Value::String(row_str(row, "local_request_id").to_string()),
    );
    payload.insert(
        "eventType".to_string(),
        Value::String("review.request.snapshot_migrated".to_string()),
    );
    payload.insert(
        "occurredAt".to_string(),
        Value::String(row_str(row, "changed_at").to_string()),
    );
    payload.insert(
        "retiredSequence".to_string(),
        Value::Number(row_i64(row, "sequence").into()),
    );
    serde_json::to_string(&Value::Object(payload)).unwrap_or_default()
}

fn retired_outbox_payload(
    connection: &mut dyn Connection,
    row: &DbRow,
) -> (String, Option<String>) {
    let request = connection
        .query_row(
            "select * from approval_requests where request_id = ?",
            &[row_value(row, "local_request_id").clone()],
        )
        .ok()
        .flatten();
    let Some(request_row) = request else {
        return (
            retired_outbox_marker_payload(row),
            Some("retired_request_snapshot_missing".to_string()),
        );
    };
    let payload = match review_event_payload_json(
        &request_row,
        "review.request.snapshot_migrated",
        row_str(row, "changed_at"),
        None,
        false,
    ) {
        Ok(value) => value,
        Err(_) => {
            return (
                retired_outbox_marker_payload(row),
                Some("retired_request_snapshot_incomplete".to_string()),
            );
        }
    };
    if request_row.get("oauth_source").and_then(Value::as_str) != Some(row_str(row, "oauth_source"))
    {
        return (
            payload,
            Some("retired_request_source_ambiguous".to_string()),
        );
    }
    (payload, None)
}

fn migrate_retired_outbox(connection: &mut dyn Connection, now: &str) {
    let marker = connection
        .query_row(
            "select 1 from sync_state where state_key = ?",
            &[Value::String(
                RETIRED_OUTBOX_MIGRATION_STATE_KEY.to_string(),
            )],
        )
        .ok()
        .flatten();
    if marker.is_some() {
        return;
    }
    let old_table = connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = 'guard_live_request_outbox'",
            &[],
        )
        .ok()
        .flatten();
    if old_table.is_some() {
        let rows = connection
            .query_all(
                "
                select sequence, local_request_id, changed_at, oauth_source,
                       oauth_subject_hash, workspace_id, machine_id, machine_installation_id,
                       attempt_count, next_attempt_at, last_error
                from guard_live_request_outbox order by sequence
                ",
                &[],
            )
            .unwrap_or_default();
        for row in rows {
            let (payload, source_quarantine) = retired_outbox_payload(connection, &row);
            let identity = [
                row.get("oauth_source"),
                row.get("oauth_subject_hash"),
                row.get("workspace_id"),
                row.get("machine_id"),
                row.get("machine_installation_id"),
            ];
            let complete = identity
                .iter()
                .all(|value| matches!(value, Some(Value::String(text)) if !text.trim().is_empty()));
            let quarantine_reason = source_quarantine.or_else(|| {
                if complete {
                    None
                } else {
                    Some("retired_identity_incomplete".to_string())
                }
            });
            let _ = connection.execute(
                "
                insert into guard_review_outbox_events (
                  event_id, local_request_id, request_sequence, event_type,
                  event_schema_version, payload_json, payload_hash, occurred_at,
                  oauth_source, oauth_subject_hash, workspace_id, machine_id,
                  machine_installation_id, binding_status, quarantine_reason,
                  acknowledged_at, attempt_count, next_attempt_at, last_error
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ",
                &[
                    Value::String(uuid4_hex()),
                    row_value(&row, "local_request_id").clone(),
                    row_value(&row, "sequence").clone(),
                    Value::String("review.request.snapshot_migrated".to_string()),
                    Value::Number(REVIEW_EVENT_SCHEMA_VERSION.into()),
                    Value::String(payload.clone()),
                    Value::String(review_event_payload_digest(
                        &payload,
                        row.get("oauth_source").and_then(Value::as_str),
                        row.get("oauth_subject_hash").and_then(Value::as_str),
                        row.get("workspace_id").and_then(Value::as_str),
                        row.get("machine_id").and_then(Value::as_str),
                        row.get("machine_installation_id").and_then(Value::as_str),
                    )),
                    row_value(&row, "changed_at").clone(),
                    row_value(&row, "oauth_source").clone(),
                    row_value(&row, "oauth_subject_hash").clone(),
                    row_value(&row, "workspace_id").clone(),
                    row_value(&row, "machine_id").clone(),
                    row_value(&row, "machine_installation_id").clone(),
                    Value::String(
                        if quarantine_reason.is_none() {
                            "ready"
                        } else {
                            "quarantined"
                        }
                        .to_string(),
                    ),
                    quarantine_reason.map(Value::String).unwrap_or(Value::Null),
                    Value::Null,
                    row_value(&row, "attempt_count").clone(),
                    row_value(&row, "next_attempt_at").clone(),
                    row_value(&row, "last_error").clone(),
                ],
            );
        }
    }
    let _ = connection.execute(
        "insert or ignore into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
        &[
            Value::String(RETIRED_OUTBOX_MIGRATION_STATE_KEY.to_string()),
            Value::String("1".to_string()),
            Value::String(now.to_string()),
        ],
    );
}

// ---------------------------------------------------------------------------
// Schema ensure / commit / wake notification.
// ---------------------------------------------------------------------------

/// `commit_review_event_transaction` — commit durably and return the outbox
/// generation only after writes. `record_commit` receives elapsed milliseconds.
pub fn commit_review_event_transaction(
    connection: &mut dyn Connection,
    initial_changes: i64,
    record_commit: &mut dyn FnMut(f64),
) -> Option<i64> {
    let started = std::time::Instant::now();
    let _ = connection.commit();
    record_commit(started.elapsed().as_secs_f64() * 1000.0);
    if connection.total_changes() > initial_changes {
        Some(review_event_outbox_generation(connection))
    } else {
        None
    }
}

/// `notify_review_event_wake` — publish a wake hint only after a transaction
/// commits changes.
pub fn notify_review_event_wake(
    database_path: &Path,
    outbox_generation: Option<i64>,
    locator: &dyn ReviewEventWakeLocator,
) {
    if let Some(generation) = outbox_generation {
        locator
            .wake_signal(database_path)
            .notify_if_outbox_changed(generation);
    }
}

/// `finalize_review_event_payload_hashes` — finalize trigger-written hashes
/// inside the surrounding SQLite transaction.
pub fn finalize_review_event_payload_hashes(connection: &mut dyn Connection) {
    let rows = connection
        .query_all(
            "
            select stream_sequence, payload_json, oauth_source, oauth_subject_hash,
                   workspace_id, machine_id, machine_installation_id
            from guard_review_outbox_events where payload_hash = ''
            ",
            &[],
        )
        .unwrap_or_default();
    for row in rows {
        let payload = row_str(&row, "payload_json").to_string();
        let _ = connection.execute(
            "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?",
            &[
                Value::String(review_event_payload_digest(
                    &payload,
                    row.get("oauth_source").and_then(Value::as_str),
                    row.get("oauth_subject_hash").and_then(Value::as_str),
                    row.get("workspace_id").and_then(Value::as_str),
                    row.get("machine_id").and_then(Value::as_str),
                    row.get("machine_installation_id").and_then(Value::as_str),
                )),
                row_value(&row, "stream_sequence").clone(),
            ],
        );
    }
}

/// `ensure_review_event_outbox_schema` — apply DDL, run the retired-outbox
/// migration, rebuild triggers, and stamp `schema_migrations`.
pub fn ensure_review_event_outbox_schema(connection: &mut dyn Connection, now: &str) {
    for statement in review_event_outbox_schema_statements() {
        let _ = connection.execute(&statement, &[]);
    }
    ensure_review_event_outbox_upgrade(connection);
    migrate_retired_outbox(connection, now);
    let _ = connection.execute(
        "drop trigger if exists guard_live_request_outbox_after_insert",
        &[],
    );
    let _ = connection.execute(
        "drop trigger if exists guard_live_request_outbox_after_update",
        &[],
    );
    let _ = connection.execute(
        "drop trigger if exists guard_review_outbox_after_insert",
        &[],
    );
    let _ = connection.execute(
        "drop trigger if exists guard_review_outbox_after_update",
        &[],
    );
    let _ = connection.execute(&insert_trigger(), &[]);
    let _ = connection.execute(&update_trigger(), &[]);
    let migrations = connection
        .query_row(
            "select 1 from sqlite_master where type = 'table' and name = 'schema_migrations'",
            &[],
        )
        .ok()
        .flatten();
    if migrations.is_some() {
        let _ = connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            &[
                Value::Number(REVIEW_EVENT_OUTBOX_MIGRATION_VERSION.into()),
                Value::String(now.to_string()),
            ],
        );
    }
}

/// `ensure_review_event_outbox_upgrade` — backfill `payload_hash` for any rows
/// created before the integrity contract existed.
fn ensure_review_event_outbox_upgrade(connection: &mut dyn Connection) {
    let events = connection
        .query_all(
            "
            select stream_sequence, payload_json, oauth_source, oauth_subject_hash,
                   workspace_id, machine_id, machine_installation_id
            from guard_review_outbox_events
            ",
            &[],
        )
        .unwrap_or_default();
    for event in events {
        let _ = connection.execute(
            "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?",
            &[
                Value::String(review_event_payload_digest(
                    row_str(&event, "payload_json"),
                    event.get("oauth_source").and_then(Value::as_str),
                    event.get("oauth_subject_hash").and_then(Value::as_str),
                    event.get("workspace_id").and_then(Value::as_str),
                    event.get("machine_id").and_then(Value::as_str),
                    event.get("machine_installation_id").and_then(Value::as_str),
                )),
                row_value(&event, "stream_sequence").clone(),
            ],
        );
    }
}

// ---------------------------------------------------------------------------
// `uuid.uuid4().hex` — 16 random bytes with version/variant bits, hex-encoded.
// ---------------------------------------------------------------------------

fn uuid4_hex() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return "0".repeat(32);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    hex::encode(bytes)
}

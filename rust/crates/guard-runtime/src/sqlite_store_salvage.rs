//! `sqlite-store-salvage --stdin`: carry state out of a quarantined Guard
//! database into the freshly initialized one that replaces it.
//!
//! Two independent salvages run in order, each in its own destination
//! transaction:
//!
//! * Cloud Review restores the sync credentials, consent, revocation and
//!   replay records together or not at all. These are current-state reads,
//!   not restoration from an older backup; normal OAuth, DPoP,
//!   capability-signature, revocation and request-binding checks still apply
//!   afterwards, and no consent is created or renewed here.
//! * Custom-extension (`local_cli_*`) tables can still SELECT after a full
//!   `quick_check` fails. Grant, command and command-grant copies must all
//!   succeed so an allowed grant never restores without its scoped catalog.
//!
//! The caller creates the `local_cli_*` schema in the destination first and
//! wakes review listeners when Cloud Review state came back.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::guard_store_json::dumps_sorted;

#[path = "sqlite_store_salvage_local_cli.rs"]
mod local_cli;
#[cfg(test)]
#[path = "sqlite_store_salvage_tests.rs"]
mod tests;

use local_cli::salvage_local_cli;

const SCHEMA: &str = "sqlite-store-salvage.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const BUSY_TIMEOUT: Duration = Duration::from_secs(1);

/// Consent never recovers without its revocation and replay records.
const STATE_KEYS: [&str; 5] = [
    "oauth_local_credentials",
    "guard_exact_cloud_review_capability",
    "guard_exact_cloud_review_revocation",
    "guard_review_verification_keyring",
    "guard_cloud_review_settings_recovery",
];
const TABLES: [&str; 7] = [
    "guard_devices",
    "guard_connect_states",
    "guard_exact_cloud_review_receipts",
    "approval_requests",
    "guard_review_outbox_events",
    "guard_review_outbox_cursors",
    "guard_review_outbox_request_sequences",
];
/// Only additive presentation columns may be absent in an older request
/// table. Identity, decisions, revocations and replay records stay complete.
const OPTIONAL_REQUEST_COLUMNS: [&str; 12] = [
    "artifact_label",
    "source_label",
    "trigger_summary",
    "why_now",
    "launch_summary",
    "risk_headline",
    "desktop_notified_at",
    "guard_version",
    "first_seen_guard_version",
    "last_seen_guard_version",
    "dedupe_count",
    "last_seen_at",
];
/// `NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX`.
const RECEIPT_PREFIX: &str = "native_workspace_review.receipt:";
/// `ATTRIBUTION_STATE_PREFIX`.
const ATTRIBUTION_PREFIX: &str = "review_policy_attribution:";
const MAX_RECEIPT_REQUEST_ID_CHARS: usize = 128;
/// `_RECEIPT_BINDINGS` plus the two digests `_receipt_payload` checks.
const RECEIPT_DIGESTS: [&str; 14] = [
    "claim_id",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
    "request_snapshot_digest",
    "envelope_digest",
    "authority_record_digest",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    source: PathBuf,
    destination: PathBuf,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "sqlite-store-salvage"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "sqlite_store_salvage_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("sqlite_store_salvage_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "sqlite_store_salvage_request_invalid".to_owned())?;
    if request.schema != SCHEMA
        || !request.source.is_absolute()
        || !request.destination.is_absolute()
    {
        return Err("sqlite_store_salvage_request_invalid".to_owned());
    }
    let cloud_review = salvage_cloud_review(&request.source, &request.destination);
    let local_cli = salvage_local_cli(&request.source, &request.destination);
    serde_json::to_vec(&json!({ "cloud_review": cloud_review, "local_cli": local_cli }))
        .map_err(|_| "sqlite_store_salvage_response_unencodable".to_owned())
}

/// Both stores open, the source read-only through its resolved path, or
/// `None` when either path is a link or the destination is not a file.
fn open_pair(source: &Path, destination: &Path) -> Option<(Connection, Connection)> {
    if is_link(source) || is_link(destination) || !destination.is_file() {
        return None;
    }
    let resolved = source.canonicalize().ok()?;
    let src = Connection::open_with_flags(
        resolved,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let dst = Connection::open(destination).ok()?;
    src.busy_timeout(BUSY_TIMEOUT).ok()?;
    dst.busy_timeout(BUSY_TIMEOUT).ok()?;
    Some((src, dst))
}

fn is_link(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
}

pub(super) fn salvage_cloud_review(source: &Path, destination: &Path) -> bool {
    let Some((src, mut dst)) = open_pair(source, destination) else {
        return false;
    };
    copy_cloud_review(&src, &mut dst).unwrap_or(false)
}

fn copy_cloud_review(src: &Connection, dst: &mut Connection) -> rusqlite::Result<bool> {
    src.execute_batch("begin")?;
    let transaction = dst.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !destination_is_empty(&transaction)? {
        return Ok(false);
    }
    let mut states = select_states(
        src,
        &format!(
            "select state_key, payload_json, updated_at from sync_state where state_key in ({})",
            placeholders(STATE_KEYS.len())
        ),
        rusqlite::params_from_iter(STATE_KEYS),
    )?;
    if !states
        .iter()
        .any(|row| matches!(&row[0], SqlValue::Text(key) if key == "oauth_local_credentials"))
    {
        return Ok(false);
    }
    states.extend(validated_receipt_states(src)?);
    states.extend(policy_attribution_states(src)?);
    let installation: Option<SqlValue> = src
        .query_row(
            "select installation_id from guard_devices where device_key = 'local-device'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if !matches!(installation, Some(SqlValue::Text(id)) if !id.is_empty()) {
        return Ok(false);
    }
    {
        let mut insert = transaction.prepare(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
        )?;
        for row in &states {
            insert.execute(rusqlite::params_from_iter(row))?;
        }
    }
    for table in TABLES {
        // An incomplete table drops the whole salvage with the transaction.
        if !copy_complete_table(src, &transaction, table)? {
            return Ok(false);
        }
    }
    transaction.commit()?;
    Ok(true)
}

fn destination_is_empty(connection: &Connection) -> rusqlite::Result<bool> {
    let sql = format!(
        "select 1 from sync_state where state_key in ({}) limit 1",
        placeholders(STATE_KEYS.len())
    );
    let present: Option<i64> = connection
        .query_row(&sql, rusqlite::params_from_iter(STATE_KEYS), |row| {
            row.get(0)
        })
        .optional()?;
    if present.is_some() {
        return Ok(false);
    }
    for table in TABLES {
        // Schema initialization creates a replacement installation ID.
        if table == "guard_devices" {
            continue;
        }
        let present: Option<i64> = connection
            .query_row(&format!("select 1 from \"{table}\" limit 1"), [], |row| {
                row.get(0)
            })
            .optional()?;
        if present.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

type StateRow = [SqlValue; 3];

fn select_states(
    src: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<Vec<StateRow>> {
    let mut statement = src.prepare(sql)?;
    let rows = statement.query_map(params, |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?]))?;
    rows.collect()
}

fn prefixed_states(src: &Connection, prefix: &str) -> rusqlite::Result<Vec<StateRow>> {
    let rows = select_states(
        src,
        "select state_key, payload_json, updated_at from sync_state where state_key like ?",
        [format!("{prefix}%")],
    )?;
    // LIKE ignores case and reads `_` as a wildcard; the key must start with
    // the prefix exactly.
    Ok(rows
        .into_iter()
        .filter(|row| matches!(&row[0], SqlValue::Text(key) if key.starts_with(prefix)))
        .collect())
}

/// Only native receipts bound to their resolved local request. A missing or
/// corrupt receipt is omitted, never manufactured, so native redelivery stays
/// fail-closed.
fn validated_receipt_states(src: &Connection) -> rusqlite::Result<Vec<StateRow>> {
    let mut recovered = Vec::new();
    for [state_key, payload, updated_at] in prefixed_states(src, RECEIPT_PREFIX)? {
        let SqlValue::Text(key) = &state_key else {
            continue;
        };
        let request_id = &key[RECEIPT_PREFIX.len()..];
        if !request_id_is_safe(request_id) {
            continue;
        }
        let request: Option<[SqlValue; 3]> = src
            .query_row(
                "select status, resolution_action, resolution_scope from approval_requests \
                 where request_id = ?",
                [request_id],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?]),
            )
            .optional()?;
        let Some([SqlValue::Text(status), SqlValue::Text(action), SqlValue::Text(scope)]) = request
        else {
            continue;
        };
        if status != "resolved"
            || !matches!(action.as_str(), "allow" | "block")
            || scope != "artifact"
        {
            continue;
        }
        let Some(canonical) = payload_text(&payload)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .and_then(|receipt| receipt_payload(&receipt, request_id, &action))
        else {
            continue;
        };
        recovered.push([state_key, SqlValue::Text(canonical), updated_at]);
    }
    Ok(recovered)
}

/// `_receipt_payload`: the receipt as canonical compact ASCII JSON, or
/// `None` when it does not bind this request and decision.
pub(super) fn receipt_payload(receipt: &Value, request_id: &str, action: &str) -> Option<String> {
    let fields = receipt.as_object()?;
    let expected_decision = if action == "block" { "deny" } else { "allow" };
    let status = fields.get("status").and_then(Value::as_str);
    let valid = fields.get("request_id").and_then(Value::as_str) == Some(request_id)
        && fields.get("decision").and_then(Value::as_str) == Some(expected_decision)
        && matches!(status, Some("verified" | "replayed"))
        && fields.get("replayed").and_then(Value::as_bool) == Some(status == Some("replayed"))
        && RECEIPT_DIGESTS.iter().all(|name| {
            fields
                .get(*name)
                .and_then(Value::as_str)
                .is_some_and(is_hex_digest)
        });
    if !valid {
        return None;
    }
    dumps_sorted(receipt)
}

fn is_hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn request_id_is_safe(request_id: &str) -> bool {
    !request_id.is_empty()
        && request_id.chars().count() <= MAX_RECEIPT_REQUEST_ID_CHARS
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

/// Each request's recorded policy rule, kept byte for byte so its claim hash
/// survives recovery.
fn policy_attribution_states(src: &Connection) -> rusqlite::Result<Vec<StateRow>> {
    Ok(prefixed_states(src, ATTRIBUTION_PREFIX)?
        .into_iter()
        .filter(|[_, payload, _]| {
            payload_text(payload)
                .and_then(|text| crate::pyjson::parse(text).ok())
                .is_some_and(|value| value.as_dict().is_some())
        })
        .collect())
}

/// A stored JSON payload as text: `json.loads` reads text, and a blob only
/// when it is UTF-8.
fn payload_text(value: &SqlValue) -> Option<&str> {
    match value {
        SqlValue::Text(text) => Some(text),
        SqlValue::Blob(bytes) => std::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

/// False, with nothing written, when the source lacks a column the
/// destination requires.
fn copy_complete_table(src: &Connection, dst: &Connection, table: &str) -> rusqlite::Result<bool> {
    let destination = table_info(dst, table)?;
    let source: Vec<String> = table_info(src, table)?
        .into_iter()
        .map(|column| column.name)
        .collect();
    let complete = !destination.is_empty()
        && destination.iter().all(|column| {
            source.contains(&column.name)
                || (table == "approval_requests"
                    && OPTIONAL_REQUEST_COLUMNS.contains(&column.name.as_str())
                    && (!column.not_null || column.has_default)
                    && !column.primary_key)
        });
    if !complete {
        return Ok(false);
    }
    let columns: Vec<&str> = destination
        .iter()
        .map(|column| column.name.as_str())
        .filter(|name| source.iter().any(|known| known == name))
        .collect();
    let quoted = quote_columns(&columns, ", ");
    // Restoring approval_requests fires outbox triggers. The complete outbox
    // copies that follow replace those generated rows with the originals.
    dst.execute(&format!("delete from \"{table}\""), [])?;
    let mut select = src.prepare(&format!("select {quoted} from \"{table}\""))?;
    let mut insert = dst.prepare(&format!(
        "insert into \"{table}\" ({quoted}) values ({})",
        placeholders(columns.len())
    ))?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let values = (0..columns.len())
            .map(|index| row.get::<_, SqlValue>(index))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        insert.execute(rusqlite::params_from_iter(values))?;
    }
    Ok(true)
}

struct Column {
    name: String,
    not_null: bool,
    has_default: bool,
    primary_key: bool,
}

fn table_info(connection: &Connection, table: &str) -> rusqlite::Result<Vec<Column>> {
    let mut statement = connection.prepare(&format!("pragma table_info(\"{table}\")"))?;
    let rows = statement.query_map([], |row| {
        Ok(Column {
            name: row.get(1)?,
            not_null: row.get::<_, i64>(3)? != 0,
            has_default: row.get::<_, SqlValue>(4)? != SqlValue::Null,
            primary_key: row.get::<_, i64>(5)? != 0,
        })
    })?;
    Ok(rows
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter(|column| !column.name.is_empty())
        .collect())
}

fn quote_columns(columns: &[&str], separator: &str) -> String {
    columns
        .iter()
        .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(separator)
}

fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

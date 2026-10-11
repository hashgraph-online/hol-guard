//! Artifact snapshots, diffs, inventory, capabilities and provenance cache.
//! Python supplies every instant and the JSON text of structured values.
//! Action normalization is the shared native lattice, never recomputed in
//! Python. Structured columns come back as raw text for Python to decode.

use guard_contracts::{normalize_guard_action_result, GuardAction};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_one, value_error, Row, StoreError, StoreResult,
};
use crate::MAX_NATIVE_RESPONSE_BYTES;

/// One reply stays at half the transport cap so the envelope and re-encoding fit.
const REPLY_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES / 2;
/// A single row may use the cap minus room for the page envelope.
const SINGLE_ROW_LIMIT_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 64 * 1024;
const PAGE_ROWS: i64 = 4096;
const ROW_EXCEEDS_RESPONSE: &str = "artifact_row_exceeds_resident_response";
const SEQUENCE_OVERFLOW: &str = "aibom_trust_attestation_sequence_overflow";

const INCONSISTENT: &str = "authoritative_decision_inconsistent";
const INVENTORY_COLUMNS: &str =
    "artifact_id, harness, artifact_name, artifact_type, source_scope, \
     config_path, publisher, origin_url, launch_command, transport, first_seen_at, last_seen_at, \
     last_changed_at, last_approved_at, removed_at, present, last_policy_action, artifact_hash";

fn opt(value: Option<&str>) -> Value {
    value.map_or(Value::Null, Value::from)
}

/// `_canonical_inventory_action`: the action and, when the input was not a
/// recognized action, the stable contract error.
fn canonical(raw: &Value, reject_unknown: bool) -> StoreResult<(GuardAction, bool)> {
    let normalized = normalize_guard_action_result(raw, GuardAction::RequireReapproval);
    if reject_unknown && normalized.reason_code.is_some() {
        return value_error(INCONSISTENT);
    }
    Ok((normalized.action, normalized.reason_code.is_some()))
}

fn grants_approval(action: GuardAction) -> bool {
    matches!(action, GuardAction::Allow | GuardAction::Warn)
}

/// `_inventory_payload_from_row`.
fn inventory_payload(row: &Map<String, Value>) -> StoreResult<Value> {
    let (action, contract_error) =
        canonical(row.get("last_policy_action").unwrap_or(&Value::Null), false)?;
    let mut payload = Map::new();
    for key in [
        "artifact_id",
        "harness",
        "artifact_name",
        "artifact_type",
        "source_scope",
        "config_path",
    ] {
        payload.insert(key.to_owned(), cell_text(row, key));
    }
    for key in ["publisher", "origin_url", "launch_command", "transport"] {
        payload.insert(key.to_owned(), row.get(key).cloned().unwrap_or(Value::Null));
    }
    payload.insert("first_seen_at".to_owned(), cell_text(row, "first_seen_at"));
    payload.insert("last_seen_at".to_owned(), cell_text(row, "last_seen_at"));
    payload.insert(
        "last_changed_at".to_owned(),
        row.get("last_changed_at").cloned().unwrap_or(Value::Null),
    );
    let approved_at = if grants_approval(action) {
        row.get("last_approved_at").cloned().unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    payload.insert("last_approved_at".to_owned(), approved_at);
    payload.insert(
        "removed_at".to_owned(),
        row.get("removed_at").cloned().unwrap_or(Value::Null),
    );
    let present = row.get("present").and_then(Value::as_i64).unwrap_or(0) != 0;
    payload.insert("present".to_owned(), Value::from(present));
    payload.insert(
        "last_policy_action".to_owned(),
        Value::from(action.as_str()),
    );
    payload.insert("artifact_hash".to_owned(), cell_text(row, "artifact_hash"));
    if contract_error {
        payload.insert(
            "decision_contract_error".to_owned(),
            Value::from(INCONSISTENT),
        );
    }
    Ok(Value::Object(payload))
}

/// Python `str(value)` for the text columns this table declares NOT NULL.
fn cell_text(row: &Map<String, Value>, key: &str) -> Value {
    match row.get(key) {
        Some(Value::String(text)) => Value::from(text.as_str()),
        Some(Value::Null) | None => Value::from("None"),
        Some(other) => Value::from(other.to_string()),
    }
}

pub(crate) fn save_snapshot(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (artifact_id, harness) = (args.str("artifact_id")?, args.str("harness")?);
    let (hash, now) = (args.str("artifact_hash")?, args.str("now")?);
    exec(
        connection,
        "insert into artifact_snapshots (artifact_id, harness, snapshot_json, artifact_hash, recorded_at) \
         values (?, ?, ?, ?, ?) \
         on conflict(artifact_id, harness) do update set \
           snapshot_json = excluded.snapshot_json, \
           artifact_hash = excluded.artifact_hash, \
           recorded_at = excluded.recorded_at",
        &[
            Value::from(artifact_id),
            Value::from(harness),
            Value::from(args.str("snapshot_json")?),
            Value::from(hash),
            Value::from(now),
        ],
    )?;
    exec(
        connection,
        "insert into artifact_hashes (artifact_id, harness, artifact_hash, recorded_at) \
         values (?, ?, ?, ?)",
        &[
            Value::from(artifact_id),
            Value::from(harness),
            Value::from(hash),
            Value::from(now),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn get_snapshot(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select snapshot_json from artifact_snapshots where artifact_id = ? and harness = ?",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

pub(crate) fn list_snapshots(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let harness = args.str("harness")?;
    let mut params = vec![Value::from(harness)];
    let after = snapshot_after(args, &mut params)?;
    params.push(Value::from(PAGE_ROWS));
    let rows = query_all(
        connection,
        &format!(
            "select artifact_id, snapshot_json from artifact_snapshots \
             where harness = ?{after} order by artifact_id asc limit ?"
        ),
        &params,
    )?;
    bound_page(&rows, |row| Ok(Value::Object(row.clone())), snapshot_cursor)
}

pub(crate) fn delete_snapshot(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "delete from artifact_snapshots where artifact_id = ? and harness = ?",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn record_diff(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into artifact_diffs ( \
           artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at \
         ) values (?, ?, ?, ?, ?, ?)",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
            Value::from(args.str("changed_fields_json")?),
            opt(args.opt_str("previous_hash")?),
            Value::from(args.str("current_hash")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn record_inventory_artifact(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    let (action, _) = canonical(args.raw("policy_action").unwrap_or(&Value::Null), true)?;
    let approved = args.flag("approved")?;
    if approved && !grants_approval(action) {
        return value_error(INCONSISTENT);
    }
    let (artifact_id, harness, now) = (
        args.str("artifact_id")?,
        args.str("harness")?,
        args.str("now")?,
    );
    let existing = query_one(
        connection,
        "select first_seen_at from artifact_inventory where artifact_id = ? and harness = ?",
        &[Value::from(artifact_id), Value::from(harness)],
    )?;
    let first_seen = existing
        .as_ref()
        .and_then(|row| row.get("first_seen_at"))
        .and_then(Value::as_str)
        .unwrap_or(now);
    let changed_at = if args.flag("changed")? {
        Value::from(now)
    } else {
        Value::Null
    };
    let approved_at = if approved {
        Value::from(now)
    } else {
        Value::Null
    };
    exec(
        connection,
        "insert into artifact_inventory ( \
           artifact_id, harness, artifact_name, artifact_type, source_scope, config_path, publisher, \
           origin_url, launch_command, transport, first_seen_at, last_seen_at, last_changed_at, \
           last_approved_at, removed_at, present, last_policy_action, artifact_hash \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         on conflict(artifact_id, harness) do update set \
           artifact_name = excluded.artifact_name, \
           artifact_type = excluded.artifact_type, \
           source_scope = excluded.source_scope, \
           config_path = excluded.config_path, \
           publisher = excluded.publisher, \
           origin_url = excluded.origin_url, \
           launch_command = excluded.launch_command, \
           transport = excluded.transport, \
           last_seen_at = excluded.last_seen_at, \
           last_changed_at = coalesce(excluded.last_changed_at, artifact_inventory.last_changed_at), \
           last_approved_at = excluded.last_approved_at, \
           removed_at = null, \
           present = 1, \
           last_policy_action = excluded.last_policy_action, \
           artifact_hash = excluded.artifact_hash",
        &[
            Value::from(artifact_id),
            Value::from(harness),
            Value::from(args.str("artifact_name")?),
            Value::from(args.str("artifact_type")?),
            Value::from(args.str("source_scope")?),
            Value::from(args.str("config_path")?),
            opt(args.opt_str("publisher")?),
            opt(args.opt_str("origin_url")?),
            opt(args.opt_str("launch_command")?),
            opt(args.opt_str("transport")?),
            Value::from(first_seen),
            Value::from(now),
            changed_at,
            approved_at,
            Value::Null,
            Value::from(1),
            Value::from(action.as_str()),
            Value::from(args.str("artifact_hash")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn mark_removed(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (action, _) = canonical(args.raw("policy_action").unwrap_or(&Value::Null), true)?;
    let now = args.str("now")?;
    let action_text = Value::from(action.as_str());
    exec(
        connection,
        "update artifact_inventory \
         set last_seen_at = ?, last_changed_at = ?, removed_at = ?, present = 0, \
             last_approved_at = case when ? in ('allow', 'warn') then last_approved_at else null end, \
             last_policy_action = ?, artifact_hash = ? \
         where artifact_id = ? and harness = ?",
        &[
            Value::from(now),
            Value::from(now),
            Value::from(now),
            action_text.clone(),
            action_text,
            Value::from(args.str("artifact_hash")?),
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn list_inventory(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut sql = format!("select {INVENTORY_COLUMNS} from artifact_inventory");
    let mut params = Vec::new();
    let mut where_added = false;
    if let Some(harness) = args.opt_str("harness")? {
        sql.push_str(" where harness = ?");
        params.push(Value::from(harness));
        where_added = true;
    }
    let filtered = where_added;
    sql.push_str(&inventory_after(args, &mut params, filtered)?);
    sql.push_str(if filtered {
        " order by artifact_name asc, artifact_id asc limit ?"
    } else {
        " order by harness asc, artifact_name asc, artifact_id asc limit ?"
    });
    params.push(Value::from(PAGE_ROWS));
    let rows = query_all(connection, &sql, &params)?;
    bound_page(&rows, inventory_payload, |row| {
        if filtered {
            json!({
                "artifact_name": text_cell(row, "artifact_name"),
                "artifact_id": text_cell(row, "artifact_id"),
            })
        } else {
            json!({
                "harness": text_cell(row, "harness"),
                "artifact_name": text_cell(row, "artifact_name"),
                "artifact_id": text_cell(row, "artifact_id"),
            })
        }
    })
}

pub(crate) fn find_inventory_item(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let sql = format!(
        "select {INVENTORY_COLUMNS} from artifact_inventory where artifact_id = ? \
         order by last_seen_at desc limit 1"
    );
    match query_one(connection, &sql, &[Value::from(args.str("artifact_id")?)])? {
        Some(row) => inventory_payload(&row),
        None => Ok(Value::Null),
    }
}

pub(crate) fn save_capability(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into artifact_capabilities (artifact_id, harness, capability_json, updated_at) \
         values (?, ?, ?, ?) \
         on conflict(artifact_id, harness) do update set \
           capability_json = excluded.capability_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
            Value::from(args.str("capability_json")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn get_capability(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select capability_json from artifact_capabilities where artifact_id = ? and harness = ?",
        &[
            Value::from(args.str("artifact_id")?),
            Value::from(args.str("harness")?),
        ],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

pub(crate) fn upsert_provenance(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into provenance_cache (artifact_hash, payload_json, updated_at) values (?, ?, ?) \
         on conflict(artifact_hash) do update set \
           payload_json = excluded.payload_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(args.str("artifact_hash")?),
            Value::from(args.str("payload_json")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

/// `next_aibom_trust_attestation_sequence`: unreadable or negative state
/// restarts the count. A nonnegative integer that does not fit in `i64`,
/// including a Unicode decimal-digit string, is an error: the stored sequence
/// is left unchanged and is never handed out twice.
pub(crate) fn next_attestation_sequence(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    const KEY: &str = "aibom_trust_attestation_sequence";
    let now = args.str("now")?;
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(KEY)],
    )?;
    let current = match stored_sequence(row.as_ref())? {
        StoredSequence::Restart => 0,
        StoredSequence::Value(value) => value,
    };
    let Some(next) = current.checked_add(1) else {
        return value_error(SEQUENCE_OVERFLOW);
    };
    exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do update set \
           payload_json = excluded.payload_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(KEY),
            Value::from(format!("{{\"sequence\": {next}}}")),
            Value::from(now),
        ],
    )?;
    Ok(Value::from(next))
}

enum StoredSequence {
    Restart,
    Value(i64),
}

fn stored_sequence(row: Option<&Row>) -> StoreResult<StoredSequence> {
    let Some(text) = row
        .and_then(|row| row.get("payload_json"))
        .and_then(Value::as_str)
    else {
        return Ok(StoredSequence::Restart);
    };
    let payload = match serde_json::from_str::<Value>(text) {
        Ok(payload) => payload,
        Err(_) => {
            if raw_sequence_exceeds_i64(text) {
                return value_error(SEQUENCE_OVERFLOW);
            }
            return Ok(StoredSequence::Restart);
        }
    };
    match payload.get("sequence") {
        Some(raw) => sequence_value(raw),
        None => Ok(StoredSequence::Restart),
    }
}

fn sequence_value(raw: &Value) -> StoreResult<StoredSequence> {
    match raw {
        Value::Bool(flag) => Ok(StoredSequence::Value(i64::from(*flag))),
        Value::Number(number) => match number.as_i64() {
            Some(value) if value >= 0 => Ok(StoredSequence::Value(value)),
            Some(_) => Ok(StoredSequence::Restart),
            None if number.as_u64().is_some() => value_error(SEQUENCE_OVERFLOW),
            None if number_exceeds_i64(number) => value_error(SEQUENCE_OVERFLOW),
            None => Ok(StoredSequence::Restart),
        },
        Value::String(text) => match decimal_i64(text) {
            Digits::Absent => Ok(StoredSequence::Restart),
            Digits::Value(value) => Ok(StoredSequence::Value(value)),
            Digits::Overflow => value_error(SEQUENCE_OVERFLOW),
        },
        _ => Ok(StoredSequence::Restart),
    }
}

/// `true` for a JSON number at or above `2^63`. `2.0` stays below that line,
/// so the recorded float restart is unchanged.
fn number_exceeds_i64(number: &serde_json::Number) -> bool {
    matches!(
        number.as_f64(),
        Some(value) if value.is_finite() && value >= (i64::MAX as f64)
    )
}

enum Digits {
    Absent,
    Value(i64),
    Overflow,
}

/// Nonnegative integer spelled with Unicode decimal digits. Other text restarts.
///
/// `char::to_digit` in this toolchain does not classify non-ASCII decimal
/// digits, so the ranges are the `Nd` blocks Python's `int()` accepts.
fn decimal_i64(text: &str) -> Digits {
    if text.is_empty() {
        return Digits::Absent;
    }
    let mut value: i64 = 0;
    for ch in text.chars() {
        let Some(digit) = unicode_decimal(ch) else {
            return Digits::Absent;
        };
        let Some(scaled) = value.checked_mul(10) else {
            return Digits::Overflow;
        };
        let Some(next) = scaled.checked_add(i64::from(digit)) else {
            return Digits::Overflow;
        };
        value = next;
    }
    Digits::Value(value)
}

/// Sorted `(first, last, digit of first)` for every Unicode decimal-digit block.
const DECIMAL_RANGES: &[(u32, u32, u32)] = &[
    (0x30, 0x39, 0),
    (0x660, 0x669, 0),
    (0x6f0, 0x6f9, 0),
    (0x7c0, 0x7c9, 0),
    (0x966, 0x96f, 0),
    (0x9e6, 0x9ef, 0),
    (0xa66, 0xa6f, 0),
    (0xae6, 0xaef, 0),
    (0xb66, 0xb6f, 0),
    (0xbe6, 0xbef, 0),
    (0xc66, 0xc6f, 0),
    (0xce6, 0xcef, 0),
    (0xd66, 0xd6f, 0),
    (0xde6, 0xdef, 0),
    (0xe50, 0xe59, 0),
    (0xed0, 0xed9, 0),
    (0xf20, 0xf29, 0),
    (0x1040, 0x1049, 0),
    (0x1090, 0x1099, 0),
    (0x17e0, 0x17e9, 0),
    (0x1810, 0x1819, 0),
    (0x1946, 0x194f, 0),
    (0x19d0, 0x19d9, 0),
    (0x1a80, 0x1a89, 0),
    (0x1a90, 0x1a99, 0),
    (0x1b50, 0x1b59, 0),
    (0x1bb0, 0x1bb9, 0),
    (0x1c40, 0x1c49, 0),
    (0x1c50, 0x1c59, 0),
    (0xa620, 0xa629, 0),
    (0xa8d0, 0xa8d9, 0),
    (0xa900, 0xa909, 0),
    (0xa9d0, 0xa9d9, 0),
    (0xa9f0, 0xa9f9, 0),
    (0xaa50, 0xaa59, 0),
    (0xabf0, 0xabf9, 0),
    (0xff10, 0xff19, 0),
    (0x104a0, 0x104a9, 0),
    (0x10d30, 0x10d39, 0),
    (0x10d40, 0x10d49, 0),
    (0x11066, 0x1106f, 0),
    (0x110f0, 0x110f9, 0),
    (0x11136, 0x1113f, 0),
    (0x111d0, 0x111d9, 0),
    (0x112f0, 0x112f9, 0),
    (0x11450, 0x11459, 0),
    (0x114d0, 0x114d9, 0),
    (0x11650, 0x11659, 0),
    (0x116c0, 0x116c9, 0),
    (0x116d0, 0x116d9, 0),
    (0x116da, 0x116e3, 0),
    (0x11730, 0x11739, 0),
    (0x118e0, 0x118e9, 0),
    (0x11950, 0x11959, 0),
    (0x11bf0, 0x11bf9, 0),
    (0x11c50, 0x11c59, 0),
    (0x11d50, 0x11d59, 0),
    (0x11da0, 0x11da9, 0),
    (0x11f50, 0x11f59, 0),
    (0x16130, 0x16139, 0),
    (0x16a60, 0x16a69, 0),
    (0x16ac0, 0x16ac9, 0),
    (0x16b50, 0x16b59, 0),
    (0x16d70, 0x16d79, 0),
    (0x1ccf0, 0x1ccf9, 0),
    (0x1d7ce, 0x1d7d7, 0),
    (0x1d7d8, 0x1d7e1, 0),
    (0x1d7e2, 0x1d7eb, 0),
    (0x1d7ec, 0x1d7f5, 0),
    (0x1d7f6, 0x1d7ff, 0),
    (0x1e140, 0x1e149, 0),
    (0x1e2f0, 0x1e2f9, 0),
    (0x1e4f0, 0x1e4f9, 0),
    (0x1e5f1, 0x1e5fa, 0),
    (0x1e950, 0x1e959, 0),
    (0x1fbf0, 0x1fbf9, 0),
];

fn unicode_decimal(ch: char) -> Option<u32> {
    let cp = u32::from(ch);
    let index = DECIMAL_RANGES.partition_point(|&(start, _, _)| start <= cp);
    let &(start, end, base) = DECIMAL_RANGES.get(index.checked_sub(1)?)?;
    (cp <= end).then_some(base + (cp - start))
}

/// `true` when `text` is unparsable JSON whose `sequence` member is an integer
/// above `i64::MAX`. Smaller or non-integer members keep the restart behavior.
fn raw_sequence_exceeds_i64(text: &str) -> bool {
    let Some(index) = text.find("\"sequence\"") else {
        return false;
    };
    let rest = text[index + "\"sequence\"".len()..].trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    let rest = rest.trim_start();
    if !rest.starts_with(|ch: char| ch.is_ascii_digit()) {
        return false;
    }
    let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    digits.parse::<i64>().is_err()
}

fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len().saturating_add(1))
}

fn text_cell(row: &Row, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn snapshot_cursor(row: &Row) -> Value {
    json!({ "artifact_id": text_cell(row, "artifact_id") })
}

fn snapshot_after(args: &Args, params: &mut Vec<Value>) -> StoreResult<&'static str> {
    let Some(cursor) = args.opt_object("after")? else {
        return Ok("");
    };
    let artifact_id = cursor
        .get("artifact_id")
        .and_then(Value::as_str)
        .ok_or(invalid_args())?;
    params.push(Value::from(artifact_id));
    Ok(" and artifact_id > ?")
}

fn inventory_after(args: &Args, params: &mut Vec<Value>, filtered: bool) -> StoreResult<String> {
    let Some(cursor) = args.opt_object("after")? else {
        return Ok(String::new());
    };
    let artifact_name = cursor
        .get("artifact_name")
        .and_then(Value::as_str)
        .ok_or(invalid_args())?;
    let artifact_id = cursor
        .get("artifact_id")
        .and_then(Value::as_str)
        .ok_or(invalid_args())?;
    let joiner = if filtered { " and " } else { " where " };
    if filtered {
        params.extend([
            Value::from(artifact_name),
            Value::from(artifact_name),
            Value::from(artifact_id),
        ]);
        return Ok(format!(
            "{joiner}(artifact_name > ? or (artifact_name = ? and artifact_id > ?))"
        ));
    }
    let harness = cursor
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(invalid_args())?;
    params.extend([
        Value::from(harness),
        Value::from(harness),
        Value::from(artifact_name),
        Value::from(harness),
        Value::from(artifact_name),
        Value::from(artifact_id),
    ]);
    Ok(format!(
        "{joiner}(harness > ? or (harness = ? and artifact_name > ?) \
         or (harness = ? and artifact_name = ? and artifact_id > ?))"
    ))
}

fn invalid_args() -> StoreError {
    StoreError::Invalid("native_guard_store_args_invalid")
}

/// A byte-bounded page. `next` is the cursor of the last row in this page, or
/// null when the ordered result is exhausted. A row that cannot fit in a
/// response by itself is an error, so it is not dropped from a shorter page.
fn bound_page(
    rows: &[Row],
    mut encode: impl FnMut(&Row) -> StoreResult<Value>,
    cursor_of: impl Fn(&Row) -> Value,
) -> StoreResult<Value> {
    let mut included: Vec<Value> = Vec::new();
    let mut used: usize = 64;
    let mut last: Option<&Row> = None;
    for row in rows {
        let value = encode(row)?;
        let size = encoded_len(&value);
        if included.is_empty() && size > SINGLE_ROW_LIMIT_BYTES {
            return value_error(ROW_EXCEEDS_RESPONSE);
        }
        if !included.is_empty() && used.saturating_add(size) > REPLY_BUDGET_BYTES {
            break;
        }
        used = used.saturating_add(size);
        included.push(value);
        last = Some(row);
    }
    let exhausted = included.len() == rows.len() && (rows.len() as i64) < PAGE_ROWS;
    let next = match last {
        Some(row) if !exhausted => cursor_of(row),
        _ => Value::Null,
    };
    Ok(json!({ "rows": included, "next": next }))
}

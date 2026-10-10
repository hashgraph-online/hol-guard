//! Guard client attachments (leases) and surface-open markers. Python passes
//! the current instant and the lease identifier; lease arithmetic and the
//! liveness filter are decided here.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, runtime_error, StoreError, StoreResult};
use crate::guard_store_json::{add_seconds_isoformat, epoch_micros, py_repr_str};

const ATTACHMENT_COLUMNS: &str = "client_id, surface, session_id, metadata_json, lease_id, \
     lease_expires_at, attached_at, last_seen_at";
const MICROS: i64 = 1_000_000;

fn opt(value: Option<&str>) -> Value {
    value.map_or(Value::Null, Value::from)
}

fn invalid_isoformat<T>(text: &str) -> StoreResult<T> {
    Err(StoreError::Value(format!(
        "Invalid isoformat string: {}",
        py_repr_str(text)
    )))
}

/// `(datetime.fromisoformat(now) + timedelta(seconds=max(lease_seconds, 1))).isoformat()`
fn lease_expiry(now: &str, lease_seconds: i64) -> StoreResult<String> {
    let delta = lease_seconds.max(1).saturating_mul(MICROS);
    match add_seconds_isoformat(now, delta) {
        Some(expiry) => Ok(expiry),
        None => invalid_isoformat(now),
    }
}

fn fetch_attachment(connection: &Connection, client_id: &str) -> StoreResult<Value> {
    let sql =
        format!("select {ATTACHMENT_COLUMNS} from guard_client_attachments where client_id = ?");
    Ok(query_one(connection, &sql, &[Value::from(client_id)])?.map_or(Value::Null, Value::Object))
}

pub(crate) fn attach_client(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let client_id = args.str("client_id")?;
    let now = args.str("now")?;
    let lease_expires_at = lease_expiry(now, args.int("lease_seconds")?)?;
    exec(
        connection,
        "insert into guard_client_attachments ( \
           client_id, surface, session_id, metadata_json, lease_id, lease_expires_at, \
           attached_at, last_seen_at \
         ) values (?, ?, ?, ?, ?, ?, ?, ?) \
         on conflict(client_id) do update set \
           surface = excluded.surface, \
           session_id = excluded.session_id, \
           metadata_json = excluded.metadata_json, \
           lease_id = excluded.lease_id, \
           lease_expires_at = excluded.lease_expires_at, \
           last_seen_at = excluded.last_seen_at",
        &[
            Value::from(client_id),
            Value::from(args.str("surface")?),
            opt(args.opt_str("session_id")?),
            Value::from(args.str("metadata_json")?),
            Value::from(args.str("lease_id")?),
            Value::from(lease_expires_at),
            Value::from(now),
            Value::from(now),
        ],
    )?;
    match fetch_attachment(connection, client_id)? {
        Value::Null => runtime_error(&format!(
            "Guard client attachment {client_id} was not persisted."
        )),
        row => Ok(row),
    }
}

pub(crate) fn renew_attachment(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let client_id = args.str("client_id")?;
    let now = args.str("now")?;
    let lease_expires_at = lease_expiry(now, args.int("lease_seconds")?)?;
    let changed = exec(
        connection,
        "update guard_client_attachments set last_seen_at = ?, lease_expires_at = ? \
         where client_id = ? and lease_id = ?",
        &[
            Value::from(now),
            Value::from(lease_expires_at),
            Value::from(client_id),
            Value::from(args.str("lease_id")?),
        ],
    )?;
    if changed <= 0 {
        return Ok(Value::Null);
    }
    fetch_attachment(connection, client_id)
}

pub(crate) fn get_attachment(connection: &Connection, args: &Args) -> StoreResult<Value> {
    fetch_attachment(connection, args.str("client_id")?)
}

/// Attachments still live at `now`: a lease decides when present, otherwise the
/// last heartbeat must fall inside the activity window.
pub(crate) fn list_attachments(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut sql = format!("select {ATTACHMENT_COLUMNS} from guard_client_attachments");
    let mut filters = Vec::new();
    let mut params = Vec::new();
    if let Some(surface) = args.opt_str("surface")? {
        filters.push("surface = ?");
        params.push(Value::from(surface));
    }
    if let Some(session_id) = args.opt_str("session_id")? {
        filters.push("session_id = ?");
        params.push(Value::from(session_id));
    }
    if !filters.is_empty() {
        sql.push_str(" where ");
        sql.push_str(&filters.join(" and "));
    }
    sql.push_str(" order by last_seen_at desc, client_id asc");
    let rows = query_all(connection, &sql, &params)?;
    let now_text = args.str("now")?;
    let Some(now) = epoch_micros(now_text) else {
        return Err(StoreError::Invalid("native_guard_store_args_invalid"));
    };
    let cutoff = now - i128::from(args.int("active_within_seconds")?.max(0)) * i128::from(MICROS);
    let mut live = Vec::new();
    for row in rows {
        let stored = |name: &str| row.get(name).and_then(Value::as_str).unwrap_or("");
        let alive = match row.get("lease_expires_at").filter(|value| !value.is_null()) {
            Some(lease) => {
                let text = lease.as_str().unwrap_or("");
                let Some(expires_at) = epoch_micros(text) else {
                    return invalid_isoformat(text);
                };
                expires_at >= now
            }
            None => {
                let Some(last_seen) = epoch_micros(stored("last_seen_at")) else {
                    return invalid_isoformat(stored("last_seen_at"));
                };
                last_seen >= cutoff
            }
        };
        if alive {
            live.push(Value::Object(row));
        }
    }
    Ok(Value::Array(live))
}

pub(crate) fn record_surface_open(connection: &Connection, args: &Args) -> StoreResult<Value> {
    exec(
        connection,
        "insert into guard_surface_opens (surface, open_key, opened_at) values (?, ?, ?) \
         on conflict(surface, open_key) do update set opened_at = excluded.opened_at",
        &[
            Value::from(args.str("surface")?),
            Value::from(args.str("open_key")?),
            Value::from(args.str("now")?),
        ],
    )?;
    Ok(Value::Null)
}

pub(crate) fn has_surface_open(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select 1 as present from guard_surface_opens where surface = ? and open_key = ?",
        &[
            Value::from(args.str("surface")?),
            Value::from(args.str("open_key")?),
        ],
    )?;
    Ok(Value::Bool(row.is_some()))
}

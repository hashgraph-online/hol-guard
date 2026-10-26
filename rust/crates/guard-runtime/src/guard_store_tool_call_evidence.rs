//! `record_tool_call_evidence`: the inventory row, receipt and runtime event of
//! one decided MCP tool call in a single store transaction.
//!
//! The three writes were separate store calls (two resident round trips and a
//! Python connection), so a call paid three commits and two extra hops before
//! its response left the proxy. The same statements now run under one
//! `BEGIN IMMEDIATE`, so they commit or roll back together. Every field is
//! shaped by the caller exactly as the separate methods expect it; this adds no
//! decision of its own.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, StoreResult};
use crate::guard_store_inventory as inventory;
use crate::guard_store_receipt_writes as receipt_writes;

pub(crate) fn record_tool_call_evidence(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    inventory::record_inventory_artifact(connection, &Args(args.object("inventory")?))?;
    receipt_writes::add_receipt(connection, args)?;
    exec(
        connection,
        "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
        &[
            Value::from(args.str("event_name")?),
            Value::from(args.str("event_payload_json")?),
            Value::from(args.str("event_occurred_at")?),
        ],
    )?;
    Ok(Value::Null)
}

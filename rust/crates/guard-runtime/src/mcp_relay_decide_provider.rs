//! The provider lookups a relayed call names, read from the store it is
//! decided against.
//!
//! A call whose tool is reviewed as a provider action (`requires_action_review`)
//! asks the proxy twice more: for the provider actions the operator has shut
//! off (`read_mcp_provider_choices`) and for the hash of the provider
//! catalogue the call's approval was bound to
//! (`read_mcp_provider_authority_hash`). Both read the local CLI tables, so
//! the resident answers them itself from the connection the decision already
//! holds — including the store that holds no saved policy at all, where a
//! provider grant is the only thing steering the call.
//!
//! The Python reader migrates an older store before reading it. The resident
//! never writes, so a store that is not at the current schema is left to the
//! proxy, as is a grant whose connector marker does not name the identity the
//! grant is bound to.

use super::store::STORE_UNREADABLE;
use crate::guard_store_observed_mcp::{marker_source, require_current_schema};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const PROVIDER_INVALID: &str = "mcp_relay_provider_invalid";

/// `read_native_provider_choices`: every blocked provider action of a
/// connector the operator has answered for, keyed by its policy selector.
const CHOICES_SQL: &str = "select o.server_command, o.identity_hash, p.tool_slug, p.state \
     from local_mcp_provider_grant p \
     join local_cli_observation o on o.cli_id = p.cli_id and o.identity_hash = p.identity_hash \
     join local_cli_grant g on g.cli_id = p.cli_id and g.identity_hash = p.identity_hash \
     where o.surface = 'mcp' and g.state in ('allowed', 'blocked') and p.state = 'block'";

/// `read_provider_authority`: the rows the hash covers, in the order the
/// Python reader hashes them.
const AUTHORITY_SQL: &str = "select a.cli_id, a.identity_hash, a.digest \
     from local_mcp_provider_authority a \
     join local_cli_observation o on o.cli_id = a.cli_id and o.identity_hash = a.identity_hash \
     where o.surface = 'mcp' order by a.cli_id, a.identity_hash";

/// The observation the proxy returns for a provider lookup, or `None` when
/// `need` is not one.
pub(super) fn answer(
    connection: Option<&Connection>,
    need: &Value,
) -> Option<Result<Value, &'static str>> {
    match need.get("kind").and_then(Value::as_str)? {
        "provider_choices" => Some(choices(connection)),
        "provider_authority_hash" => Some(authority(connection)),
        _ => None,
    }
}

/// The store this lookup may be read from: `None` for one that holds no
/// local CLI schema, where both answers are empty.
fn readable(connection: Option<&Connection>) -> Result<Option<&Connection>, &'static str> {
    let Some(connection) = connection else {
        return Ok(None);
    };
    match require_current_schema(connection) {
        Ok(true) => Ok(Some(connection)),
        Ok(false) => Ok(None),
        Err(_) => Err(STORE_UNREADABLE),
    }
}

fn choices(connection: Option<&Connection>) -> Result<Value, &'static str> {
    let mut choices = Map::new();
    let Some(connection) = readable(connection)? else {
        return Ok(Value::Object(choices));
    };
    let mut statement = connection
        .prepare_cached(CHOICES_SQL)
        .map_err(|_| STORE_UNREADABLE)?;
    let mut rows = statement.query([]).map_err(|_| STORE_UNREADABLE)?;
    while let Some(row) = rows.next().map_err(|_| STORE_UNREADABLE)? {
        let cells: Vec<String> = (0..4)
            .map(|index| text(row.get_ref(index).map_err(|_| STORE_UNREADABLE)?))
            .collect::<Result<_, _>>()?;
        let source = marker_source(&cells[0]).ok_or(PROVIDER_INVALID)?;
        if source.identity_hash() != cells[1] {
            return Err(PROVIDER_INVALID);
        }
        let selector = source.action_selector(&cells[2]).ok_or(PROVIDER_INVALID)?;
        choices.insert(selector, Value::String(cells[3].clone()));
    }
    Ok(Value::Object(choices))
}

fn authority(connection: Option<&Connection>) -> Result<Value, &'static str> {
    let Some(connection) = readable(connection)? else {
        return Ok(json!({ "hash": Value::Null }));
    };
    let mut statement = connection
        .prepare_cached(AUTHORITY_SQL)
        .map_err(|_| STORE_UNREADABLE)?;
    let mut rows = statement.query([]).map_err(|_| STORE_UNREADABLE)?;
    let mut covered: Vec<Value> = Vec::new();
    while let Some(row) = rows.next().map_err(|_| STORE_UNREADABLE)? {
        let cells: Vec<Value> = (0..3)
            .map(|index| cell(row.get_ref(index).map_err(|_| STORE_UNREADABLE)?))
            .collect::<Result<_, _>>()?;
        covered.push(Value::Array(cells));
    }
    if covered.is_empty() {
        return Ok(json!({ "hash": Value::Null }));
    }
    // `json.dumps(rows, separators=(",", ":"))`, which serde writes the same
    // way for the text these columns hold.
    let canonical = serde_json::to_string(&Value::Array(covered)).map_err(|_| PROVIDER_INVALID)?;
    Ok(json!({ "hash": hex::encode(Sha256::digest(canonical.as_bytes())) }))
}

/// A cell the Python reader reads as text.
fn text(value: ValueRef<'_>) -> Result<String, &'static str> {
    match value {
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| PROVIDER_INVALID),
        _ => Err(PROVIDER_INVALID),
    }
}

/// A hashed cell. `json.dumps` writes a non-ASCII character as an escape
/// sequence where serde writes it literally, so a row carrying one is left to
/// the proxy rather than hashed differently here.
fn cell(value: ValueRef<'_>) -> Result<Value, &'static str> {
    match value {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Text(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) if text.is_ascii() => Ok(Value::String(text.to_owned())),
            _ => Err(PROVIDER_INVALID),
        },
        _ => Err(PROVIDER_INVALID),
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_provider_tests.rs"]
mod tests;

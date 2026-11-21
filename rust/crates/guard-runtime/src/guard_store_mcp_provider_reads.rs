//! The provider half of the observed-MCP read surface: the saved deny choices
//! the resident replays, the authority digest the daemon compares against, and
//! one page of a connection's discovered provider actions.
//!
//! Every read here is bounded by the caller's own page arguments and by the
//! connection's observation row, so a corrupt or absent row ends the read with
//! the same `ValueError` the Python store raised rather than a partial page.

use guard_contracts::MAX_NATIVE_RESPONSE_BYTES;
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, text, value_error, Row, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_observed_mcp::{is_local_cli_id, marker_source, require_current_schema};

/// The parser's own page ceiling; a wider page would outgrow the response cap.
const MAX_ACTION_LIMIT: i64 = 100;
/// A page stops here so one connection's large schemas cannot build a reply
/// the resident has to refuse, which the caller only ever sees as the store
/// being unavailable. The slack covers the envelope the reply is framed in,
/// and the actions a page drops come back on its next offset.
const PAGE_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 128 * 1024;
const MAX_SEARCH_CHARS: usize = 128;

/// Bytes `value` adds to the reply the resident encodes.
fn encoded_bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(0, |encoded| encoded.len())
}

fn cell(row: &Row, name: &str) -> Value {
    row.get(name).cloned().unwrap_or(Value::Null)
}

fn cells(row: &Row, names: &[&str]) -> Value {
    Value::Array(names.iter().map(|name| cell(row, name)).collect())
}

/// `bool(cell)` over the cell types SQLite hands back.
pub(crate) fn truthy(row: &Row, name: &str) -> bool {
    match row.get(name) {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        _ => false,
    }
}

/// The identity hash of the one `mcp` observation a local CLI id names.
pub(crate) fn mcp_observation_identity(
    connection: &Connection,
    cli_id: &str,
) -> StoreResult<Option<String>> {
    let row = query_one(
        connection,
        "select identity_hash from local_cli_observation where cli_id = ? and surface = 'mcp'",
        &[Value::from(cli_id)],
    )?;
    Ok(row.map(|row| text(&row, "identity_hash").to_owned()))
}

/// Saved provider denials, keyed by the selector the resident matches against.
/// Only a connection the user already decided on contributes a choice.
pub(crate) fn provider_choices(connection: &Connection) -> StoreResult<Value> {
    let mut choices = Map::new();
    if !require_current_schema(connection)? {
        return Ok(Value::Object(choices));
    }
    let rows = query_all(
        connection,
        "select o.server_command, o.identity_hash, p.tool_slug, p.state \
         from local_mcp_provider_grant p \
         join local_cli_observation o on o.cli_id = p.cli_id and o.identity_hash = p.identity_hash \
         join local_cli_grant g on g.cli_id = p.cli_id and g.identity_hash = p.identity_hash \
         where o.surface = 'mcp' and g.state in ('allowed', 'blocked') and p.state = 'block'",
        &[],
    )?;
    for row in &rows {
        let Some(source) = marker_source(text(row, "server_command")) else {
            return value_error("invalid provider authority identity");
        };
        if source.identity_hash() != text(row, "identity_hash") {
            return value_error("invalid provider authority identity");
        }
        let Some(selector) = source.action_selector(text(row, "tool_slug")) else {
            return value_error("invalid provider action identity");
        };
        choices.insert(selector, cell(row, "state"));
    }
    Ok(Value::Object(choices))
}

/// One digest over every observed connection's provider authority row, so the
/// daemon can tell a stale catalog from a current one without reading it.
pub(crate) fn provider_authority_hash(connection: &Connection) -> StoreResult<Value> {
    if !require_current_schema(connection)? {
        return Ok(Value::Null);
    }
    let rows = query_all(
        connection,
        "select a.cli_id, a.identity_hash, a.digest from local_mcp_provider_authority a \
         join local_cli_observation o on o.cli_id = a.cli_id and o.identity_hash = a.identity_hash \
         where o.surface = 'mcp' order by a.cli_id, a.identity_hash",
        &[],
    )?;
    if rows.is_empty() {
        return Ok(Value::Null);
    }
    let material = Value::Array(
        rows.iter()
            .map(|row| cells(row, &["cli_id", "identity_hash", "digest"]))
            .collect(),
    );
    // A cell the authority writer could not have produced is refused rather
    // than hashed, so a corrupt row can never answer as a current digest.
    let Some(serialized) = dumps_sorted(&material) else {
        return value_error("invalid provider authority identity");
    };
    Ok(Value::from(format!(
        "{:x}",
        Sha256::digest(serialized.as_bytes())
    )))
}

/// One searched page of a connection's provider actions, with the declarations
/// the caller classifies after the read transaction ends.
pub(crate) fn provider_actions(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    let limit = args.int("limit")?;
    let offset = args.int("offset")?;
    let search = args.opt_str("search")?.unwrap_or_default();
    let expected_token = args.opt_str("expected_token")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid provider connection");
    }
    if !require_current_schema(connection)? {
        return value_error("provider connection not found");
    }
    let Some(identity_hash) = mcp_observation_identity(connection, cli_id)? else {
        return value_error("provider connection not found");
    };
    if !(1..=MAX_ACTION_LIMIT).contains(&limit)
        || offset < 0
        || search.chars().count() > MAX_SEARCH_CHARS
    {
        return value_error("invalid provider catalog page");
    }
    let scope = [Value::from(cli_id), Value::from(identity_hash.as_str())];

    // The token covers the whole catalog, not the page, so a change outside
    // the visible rows still invalidates a draft built on it.
    let mut fingerprint = Sha256::new();
    fingerprint.update(identity_hash.as_bytes());
    for row in query_all(
        connection,
        "select a.tool_slug, a.toolkit, a.authority_hash, a.full_schema, a.revision, \
         a.description, a.updated_at, coalesce(g.state, 'review') as state \
         from local_mcp_provider_action a \
         left join local_mcp_provider_grant g on g.cli_id = a.cli_id \
         and g.identity_hash = a.identity_hash and g.tool_slug = a.tool_slug \
         where a.cli_id = ? and a.identity_hash = ? order by a.tool_slug",
        &scope,
    )? {
        let Some(serialized) = dumps_sorted(&cells(
            &row,
            &[
                "tool_slug",
                "toolkit",
                "authority_hash",
                "full_schema",
                "revision",
                "description",
                "updated_at",
                "state",
            ],
        )) else {
            return value_error("invalid provider catalog page");
        };
        fingerprint.update(serialized.as_bytes());
    }
    let token = format!("{:x}", fingerprint.finalize());
    if expected_token.is_some_and(|expected| expected != token) {
        return value_error("provider_catalog_changed");
    }

    let escaped = search
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = Value::from(format!("%{escaped}%"));
    let rows = query_all(
        connection,
        "select a.tool_slug, a.toolkit, a.description, a.full_schema, a.revision, a.updated_at, \
         coalesce(g.state, 'review') as state, a.input_schema_json \
         from local_mcp_provider_action a \
         left join local_mcp_provider_grant g on g.cli_id = a.cli_id \
         and g.identity_hash = a.identity_hash and g.tool_slug = a.tool_slug \
         where a.cli_id = ? and a.identity_hash = ? \
         and (a.tool_slug like ? escape '\\' or a.toolkit like ? escape '\\' \
         or a.description like ? escape '\\') \
         order by a.toolkit asc, a.tool_slug asc limit ? offset ?",
        &[
            scope[0].clone(),
            scope[1].clone(),
            pattern.clone(),
            pattern.clone(),
            pattern,
            Value::from(limit + 1),
            Value::from(offset),
        ],
    )?;
    let page = &rows[..rows.len().min(limit as usize)];

    let mut declarations = Vec::with_capacity(page.len());
    let mut actions: Vec<Value> = Vec::with_capacity(page.len());
    let mut bytes = 0;
    for row in page {
        let Ok(schema) = serde_json::from_str::<Value>(text(row, "input_schema_json")) else {
            return value_error("invalid provider catalog page");
        };
        let declaration = json!({
            "name": cell(row, "tool_slug"),
            "schema": schema,
            "provider": "composio",
            "full_schema": truthy(row, "full_schema"),
        });
        let action = json!({
            "tool_slug": cell(row, "tool_slug"),
            "toolkit": cell(row, "toolkit"),
            "description": cell(row, "description"),
            "full_schema": truthy(row, "full_schema"),
            "revision": cell(row, "revision"),
            "updated_at": cell(row, "updated_at"),
            "permission_state": cell(row, "state"),
            // Reading the catalog never grants; the user decides per action.
            "allow_supported": false,
            "account_binding": "unverified",
            "source": "observed-provider-result",
        });
        bytes += encoded_bytes(&declaration) + encoded_bytes(&action);
        // One action over the budget still comes back, so the next page always
        // starts past it rather than stalling on an action it cannot skip.
        if !actions.is_empty() && bytes > PAGE_BUDGET_BYTES {
            break;
        }
        declarations.push(declaration);
        actions.push(action);
    }
    let next_offset = if rows.len() > actions.len() {
        Value::from(offset + actions.len() as i64)
    } else {
        Value::Null
    };
    Ok(json!({
        "page": {
            "actions": actions,
            "next_offset": next_offset,
            "coverage": "discovery-subset",
            "catalog_token": token,
        },
        "declarations": declarations,
    }))
}

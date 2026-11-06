//! The local CLI inventory read: every observed connector and every device
//! grant, as one list the surfaces render.
//!
//! The Python caller ran a schema ensure before reading, so a store that
//! predates a column still answered. This read never writes, so a missing
//! table reads as no rows and a missing column reads as null, which is the
//! same inventory that ensure would have produced.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::MAX_NATIVE_RESPONSE_BYTES;
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, value_error, Row, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_local_cli_inventory_item::Enrichment;
use crate::guard_store_local_cli_inventory_rows::{
    merge_item, observation_item, py_text, with_suggestions,
};

/// The observation columns the item shape needs, in `_observation_from_row`
/// order.
const OBSERVATION_COLUMNS: [&str; 16] = [
    "cli_id",
    "identity_hash",
    "kind",
    "name",
    "interpreter_name",
    "example_label",
    "observed_count",
    "last_seen_at",
    "source_path",
    "help_status",
    "surface",
    "server_identity_hash",
    "source_label",
    "server_command",
    "remote_origin",
    "declared_sources_json",
];

const GRANT_ONLY_PREFIX: &str = "local-cli.";

/// One inventory page stops here so a device with many connectors cannot
/// build a reply the resident has to refuse, which the caller only ever sees
/// as the store being unavailable. The slack covers the envelope the reply is
/// framed in. Nothing is dropped: the page names the offset the caller reads
/// from next, and the caller walks the offsets until the reply names none.
const PAGE_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 128 * 1024;

/// `list_local_cli_items`: observations merged with grants, ranked,
/// capability-annotated and, for MCP connectors, described.
///
/// `offset` names the first item of the page, defaulting to the start of the
/// list. The reply is `{"items": [...], "next_offset": int | null,
/// "snapshot": str}`. `snapshot` fingerprints the ranked list the offsets
/// index into; a caller reading past the first page sends back the one it was
/// given, and when the list has changed since, the reply is
/// `{"restart": true, "snapshot": str}` instead, so a walk never stitches two
/// orderings together and skips or repeats an item.
///
/// Ranking needs every connector, but only its short observation and grant
/// rows. Everything sized by a catalog is read and described for the listed
/// items alone, so walking every page does that work once per item.
pub(crate) fn list_items(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let offset = match args.raw("offset") {
        None => 0,
        Some(_) => match usize::try_from(args.int("offset")?) {
            Ok(offset) => offset,
            Err(_) => return value_error("offset must not be negative"),
        },
    };
    let expected = args.opt_str("snapshot")?;
    let observation_rows = observations(connection)?;
    let grant_rows = grants(connection)?;
    let authority_revision = authority_revision(connection)?;

    let mut items: Vec<Map<String, Value>> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for row in &observation_rows {
        let item = observation_item(row);
        let cli_id = item.get("cli_id").map(py_text).unwrap_or_default();
        seen.insert(cli_id.clone());
        items.push(merge_item(item, grant_rows.get(&cli_id)));
    }
    for (cli_id, grant) in &grant_rows {
        if seen.contains(cli_id) {
            continue;
        }
        items.push(grant_only_item(cli_id, grant));
    }

    with_suggestions(&mut items);
    mark_shared_enrolled_servers(&mut items, &grant_rows);

    let snapshot = inventory_snapshot(&items, authority_revision);
    if expected.is_some_and(|expected| expected != snapshot) {
        return Ok(json!({ "restart": true, "snapshot": snapshot }));
    }
    let enrichment = Enrichment::load(connection, authority_revision)?;
    let mut page = inventory_page(items, offset, |item| enrichment.enrich(connection, item))?;
    page.insert("snapshot".to_owned(), Value::from(snapshot));
    Ok(Value::Object(page))
}

/// A digest of the ranked list before enrichment: its order, every field the
/// ranking read, and the authority revision each item is stamped with. Two
/// pages that carry the same digest index into the same list.
fn inventory_snapshot(items: &[Map<String, Value>], authority_revision: i64) -> String {
    let mut digest = Sha256::new();
    digest.update(authority_revision.to_string().as_bytes());
    for item in items {
        digest.update(b"\n");
        if let Ok(encoded) = serde_json::to_vec(item) {
            digest.update(encoded);
        }
    }
    hex::encode(digest.finalize())
}

/// The items from `offset` that fit one reply, each enriched just before it
/// is measured, and the offset the caller reads from next. One item over the
/// budget still comes back, so a page always advances rather than stalling on
/// an item it cannot skip. Only the listed items, and the one that did not
/// fit, are enriched.
pub(crate) fn inventory_page<F>(
    items: Vec<Map<String, Value>>,
    offset: usize,
    mut enrich: F,
) -> StoreResult<Map<String, Value>>
where
    F: FnMut(&mut Map<String, Value>) -> StoreResult<()>,
{
    let total = items.len();
    let mut listed = Vec::new();
    let mut bytes = 0;
    for mut item in items.into_iter().skip(offset) {
        enrich(&mut item)?;
        bytes += serde_json::to_vec(&item).map_or(0, |encoded| encoded.len());
        if !listed.is_empty() && bytes > PAGE_BUDGET_BYTES {
            break;
        }
        listed.push(Value::Object(item));
    }
    let next = offset.saturating_add(listed.len());
    let mut page = Map::new();
    page.insert("items".to_owned(), Value::Array(listed));
    page.insert(
        "next_offset".to_owned(),
        if next < total {
            Value::from(next)
        } else {
            Value::Null
        },
    );
    Ok(page)
}

/// Observation rows in display order, with the columns a store that predates
/// a migration does not have read as null.
fn observations(connection: &Connection) -> StoreResult<Vec<Row>> {
    if !table_exists(connection, "local_cli_observation")? {
        return Ok(Vec::new());
    }
    let present = column_names(connection, "local_cli_observation")?;
    let projection = OBSERVATION_COLUMNS
        .iter()
        .map(|column| {
            if present.contains(*column) {
                (*column).to_owned()
            } else {
                format!("null as {column}")
            }
        })
        .collect::<Vec<String>>()
        .join(", ");
    let order = if present.contains("last_seen_at") {
        "order by last_seen_at desc, cli_id asc"
    } else {
        "order by cli_id asc"
    };
    query_all(
        connection,
        &format!("select {projection} from local_cli_observation {order}"),
        &[],
    )
}

/// Device grants by CLI id. A grant row whose id is not text is a row no
/// surface can address, so the read refuses rather than listing it.
fn grants(connection: &Connection) -> StoreResult<BTreeMap<String, Map<String, Value>>> {
    let mut grants = BTreeMap::new();
    if !table_exists(connection, "local_cli_grant")? {
        return Ok(grants);
    }
    let rows = query_all(
        connection,
        "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant",
        &[],
    )?;
    for row in rows {
        let Some(cli_id) = row.get("cli_id").and_then(Value::as_str) else {
            return value_error("invalid local CLI row");
        };
        grants.insert(cli_id.to_owned(), row.clone());
    }
    Ok(grants)
}

fn authority_revision(connection: &Connection) -> StoreResult<i64> {
    if !table_exists(connection, "local_cli_authority")? {
        return Ok(0);
    }
    let row = query_one(
        connection,
        "select revision from local_cli_authority where singleton = 1",
        &[],
    )?;
    let Some(row) = row else {
        return Ok(0);
    };
    match row.get("revision").and_then(Value::as_i64) {
        Some(revision) => Ok(revision),
        None => value_error("invalid local CLI row"),
    }
}

/// `mark_shared_enrolled_servers`: flag un-enrolled MCP records kept because
/// an enrolled record shares their server.
fn mark_shared_enrolled_servers(
    items: &mut [Map<String, Value>],
    enrolled_ids: &BTreeMap<String, Map<String, Value>>,
) {
    let mut servers: BTreeSet<String> = BTreeSet::new();
    for item in items.iter() {
        if !is_mcp(item) || !enrolled(item, enrolled_ids) {
            continue;
        }
        let server = item
            .get("server_identity_hash")
            .filter(|value| truthy(value))
            .or_else(|| item.get("identity_hash"));
        let Some(server) = server.filter(|value| !value.is_null()) else {
            continue;
        };
        if let Some(key) = dumps_sorted(server) {
            servers.insert(key);
        }
    }
    let shares: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            is_mcp(item)
                && !enrolled(item, enrolled_ids)
                && item
                    .get("server_identity_hash")
                    .and_then(dumps_sorted)
                    .is_some_and(|key| servers.contains(&key))
        })
        .map(|(index, _)| index)
        .collect();
    for index in shares {
        items[index].insert("shares_enrolled_server".to_owned(), Value::from(true));
    }
}

/// An MCP record is the only kind a shared server can cover.
pub(crate) fn is_mcp(item: &Map<String, Value>) -> bool {
    item.get("surface").and_then(Value::as_str) == Some("mcp")
}

/// Whether this record's own CLI id carries a device grant.
fn enrolled(
    item: &Map<String, Value>,
    enrolled_ids: &BTreeMap<String, Map<String, Value>>,
) -> bool {
    item.get("cli_id")
        .and_then(Value::as_str)
        .is_some_and(|cli_id| enrolled_ids.contains_key(cli_id))
}

/// Python's truth test on a stored cell: null, an empty string and zero all
/// fall back to the connector's own identity.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::String(text) => !text.is_empty(),
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::Array(entries) => !entries.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// A grant with no observation still lists, so a device decision never
/// disappears because its connector has not been seen again.
fn grant_only_item(cli_id: &str, grant: &Map<String, Value>) -> Map<String, Value> {
    let label = cli_id.strip_prefix(GRANT_ONLY_PREFIX).unwrap_or(cli_id);
    let mut item = Map::new();
    item.insert("cli_id".to_owned(), Value::from(cli_id));
    item.insert("name".to_owned(), Value::from(label));
    item.insert("kind".to_owned(), Value::from("executable"));
    item.insert(
        "identity_hash".to_owned(),
        grant.get("identity_hash").cloned().unwrap_or(Value::Null),
    );
    item.insert("example_label".to_owned(), Value::from(label));
    item.insert("interpreter_name".to_owned(), Value::Null);
    item.insert("observed_count".to_owned(), Value::from(0));
    item.insert("last_seen_at".to_owned(), Value::Null);
    item.insert("source_path".to_owned(), Value::Null);
    item.insert("help_status".to_owned(), Value::Null);
    item.insert("surface".to_owned(), Value::from("cli"));
    item.insert("server_identity_hash".to_owned(), Value::Null);
    item.insert("source_label".to_owned(), Value::Null);
    item.insert(
        "state".to_owned(),
        grant.get("state").cloned().unwrap_or(Value::Null),
    );
    item.insert("stale".to_owned(), Value::from(false));
    item.insert(
        "grant_revision".to_owned(),
        grant.get("revision").cloned().unwrap_or(Value::Null),
    );
    item
}

pub(crate) fn table_exists(connection: &Connection, table: &str) -> StoreResult<bool> {
    let row = query_one(
        connection,
        "select 1 as present from sqlite_master where type = 'table' and name = ?",
        &[Value::from(table)],
    )?;
    Ok(row.is_some())
}

pub(crate) fn column_names(connection: &Connection, table: &str) -> StoreResult<BTreeSet<String>> {
    let rows = query_all(
        connection,
        "select name from pragma_table_info(?)",
        &[Value::from(table)],
    )?;
    Ok(rows
        .iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}

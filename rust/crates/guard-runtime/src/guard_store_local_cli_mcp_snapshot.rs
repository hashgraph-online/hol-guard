//! The `store_mcp_catalog` write half: `write_mcp_catalog`,
//! `_skill_metadata_snapshot`, `_fresh_until` and `rebuild_tool_authority`.
//! The snapshot, the per-tool authority digests it derives and the command ids
//! it hands back for review are one write, so `guard_store_local_cli_catalog`
//! runs it inside the same `begin immediate` that settles the command rows: a
//! snapshot that advanced without its digests would let a saved grant bind to
//! a schema the user never saw.

use std::collections::{BTreeSet, HashMap, HashSet};

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_db::{exec, int, query_one, text, value_error, StoreResult};
use crate::guard_store_json::{add_micros_aware_isoformat, dumps_sorted, py_strip};
use crate::local_mcp_grant_identity::slug_command_id;
use crate::mcp_tool_call_identity_build::tool_definition_authority_hash;

/// `_MAX_SNAPSHOT_BYTES` / `_MAX_SNAPSHOT_TOOLS`.
const MAX_SNAPSHOT_BYTES: usize = 2_000_000;
const MAX_SNAPSHOT_TOOLS: usize = 10_000;
/// `_skill_metadata_snapshot` keeps at most a thousand known skills.
const MAX_SKILL_ENTRIES: usize = 1_000;
/// `mcp_skills.{_EXTENSION, _MIN_SKILLS_VERSION}`.
const SKILLS_EXTENSION: &str = "io.modelcontextprotocol/skills";
const MIN_SKILLS_VERSION: (i64, u32, u32) = (2026, 7, 28);

/// A name-keyed view that keeps Python dict ordering: re-assigning a name
/// leaves it where it first appeared, so the stored `tools` list holds the
/// previous inventory's order with this round's definitions substituted in.
struct Ordered<'a> {
    order: Vec<&'a str>,
    by_name: HashMap<&'a str, &'a Value>,
}

impl<'a> Ordered<'a> {
    fn empty() -> Self {
        Self {
            order: Vec::new(),
            by_name: HashMap::new(),
        }
    }

    fn insert(&mut self, name: &'a str, value: &'a Value) {
        if self.by_name.insert(name, value).is_none() {
            self.order.push(name);
        }
    }

    fn values(&self) -> Vec<&'a Value> {
        self.order.iter().map(|name| self.by_name[name]).collect()
    }

    fn len(&self) -> usize {
        self.order.len()
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// `write_mcp_catalog`. Returns the command ids whose authority moved, for the
/// review sweep the caller runs once the command rows are settled.
pub(crate) fn write_mcp_catalog(
    connection: &Connection,
    cli_id: &str,
    catalog: &Map<String, Value>,
    identity_hash: Option<&str>,
    seen_at: Option<&str>,
    expected_revision: Option<i64>,
) -> StoreResult<Vec<String>> {
    let observation = query_one(
        connection,
        "select identity_hash, surface from local_cli_observation where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    let (Some(identity_hash), Some(seen_at), Some(observation)) = (
        identity_hash.filter(|value| !value.is_empty()),
        seen_at.filter(|value| !value.is_empty()),
        observation,
    ) else {
        return value_error("MCP catalog requires an observed identity and refresh time");
    };
    if text(&observation, "identity_hash") != identity_hash
        || text(&observation, "surface") != "mcp"
    {
        return value_error("MCP catalog identity changed during discovery");
    }

    let prior_row = query_one(
        connection,
        "select identity_hash, catalog_json, revision, last_complete_at \
         from local_mcp_catalog where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    let same_identity = prior_row
        .as_ref()
        .is_some_and(|row| text(row, "identity_hash") == identity_hash);
    let current_revision = match &prior_row {
        Some(row) if same_identity => int(row, "revision"),
        _ => 0,
    };
    if expected_revision.is_some_and(|expected| expected != current_revision) {
        return value_error("mcp_catalog_revision_conflict");
    }
    let revision = prior_row.as_ref().map_or(1, |row| int(row, "revision") + 1);
    let mut last_complete_at = match &prior_row {
        Some(row) if same_identity => row.get("last_complete_at").cloned(),
        _ => None,
    };
    let prior = match &prior_row {
        Some(row) if same_identity => decode_snapshot(row.get("catalog_json")),
        _ => None,
    };
    let empty = Map::new();
    let prior = prior.as_ref().and_then(Value::as_object).unwrap_or(&empty);

    let complete = matches!(catalog.get("complete"), Some(Value::Bool(true)));
    let listed_tools = match catalog.get("tools") {
        Some(Value::Array(items)) => items.as_slice(),
        None | Some(Value::Null) => &[],
        Some(_) => return value_error("invalid MCP catalog tool identity"),
    };
    let previous_tools = prior.get("tools").and_then(Value::as_array);
    let mut previous_by_name: HashMap<&str, &Value> = HashMap::new();
    for tool in previous_tools.into_iter().flatten() {
        if let Some(Value::String(name)) = tool.as_object().and_then(|tool| tool.get("name")) {
            previous_by_name.insert(name.as_str(), tool);
        }
    }

    let mut tools = Ordered::empty();
    // An incomplete inventory adds to what is already known rather than
    // replacing it: an unfinished page is not evidence a tool is gone.
    if !complete {
        for tool in previous_tools.into_iter().flatten() {
            if let Some(Value::String(name)) = tool.as_object().and_then(|tool| tool.get("name")) {
                tools.insert(name.as_str(), tool);
            }
        }
    }
    // Python collects all three as sets, so a server that lists one name
    // twice still reports it once.
    let mut review_ids: BTreeSet<String> = BTreeSet::new();
    let mut added: BTreeSet<&str> = BTreeSet::new();
    let mut authority_changed: BTreeSet<&str> = BTreeSet::new();
    let mut listed: HashSet<&str> = HashSet::new();
    for tool in listed_tools {
        let Some(Value::String(name)) = tool.as_object().and_then(|tool| tool.get("name")) else {
            return value_error("invalid MCP catalog tool identity");
        };
        if name.is_empty() || py_strip(name) != name.as_str() {
            return value_error("invalid MCP catalog tool identity");
        }
        let previous = previous_by_name.get(name.as_str());
        listed.insert(name.as_str());
        match previous {
            None => {
                added.insert(name.as_str());
            }
            Some(previous) => {
                if authority_shape(previous)? != authority_shape(tool)? {
                    authority_changed.insert(name.as_str());
                }
            }
        }
        if added.contains(name.as_str()) || authority_changed.contains(name.as_str()) {
            review_ids.insert(slug_command_id(name));
        }
        tools.insert(name.as_str(), tool);
    }
    let mut missing: Vec<&str> = previous_by_name
        .keys()
        .copied()
        .filter(|name| !listed.contains(name))
        .collect();
    missing.sort_unstable();
    if complete {
        review_ids.extend(missing.iter().copied().map(slug_command_id));
    }
    if tools.len() > MAX_SNAPSHOT_TOOLS {
        return value_error("MCP catalog snapshot exceeds its tool limit");
    }
    let ttl_ms = catalog.get("cache_ttl_ms");
    let received_at = catalog
        .get("cache_received_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(seen_at);
    let payload = json!({
        "tools": tools.values(),
        "complete": complete,
        "stale": !complete && !prior.is_empty(),
        "reason": catalog.get("reason").cloned().unwrap_or(Value::Null),
        "pages": catalog.get("pages").cloned().unwrap_or(Value::Null),
        "cache_scope": catalog.get("cache_scope").cloned().unwrap_or(Value::Null),
        "cache_ttl_ms": ttl_ms.cloned().unwrap_or(Value::Null),
        "fresh_until": if complete { fresh_until(received_at, ttl_ms) } else { Value::Null },
        "listed_count": listed_tools.len(),
        "known_count": tools.len(),
        "changes": {
            "added": added,
            "changed": authority_changed,
            "removed": if complete { missing.clone() } else { Vec::new() },
            "stale": if complete { Vec::new() } else { missing.clone() },
        },
        "protocol_version": inherited(catalog, prior, "protocol_version", true),
        "server_info": inherited(catalog, prior, "server_info", false),
        "capabilities": inherited(catalog, prior, "capabilities", false),
        "skills_catalog": skill_metadata_snapshot(catalog, prior, identity_hash),
    });
    let Some(raw) = dumps_sorted(&payload) else {
        // `allow_nan=False`: a non-finite number in a tool definition is not
        // storable evidence, and Python raises the same `ValueError`.
        return value_error("MCP catalog snapshot is not representable");
    };
    if raw.len() > MAX_SNAPSHOT_BYTES {
        return value_error("MCP catalog snapshot exceeds its byte limit");
    }
    if complete {
        last_complete_at = Some(Value::from(seen_at));
    }
    exec(
        connection,
        "insert into local_mcp_catalog \
         (cli_id, identity_hash, catalog_json, revision, updated_at, last_complete_at) \
         values (?, ?, ?, ?, ?, ?) \
         on conflict(cli_id) do update set identity_hash = excluded.identity_hash, \
         catalog_json = excluded.catalog_json, revision = excluded.revision, \
         updated_at = excluded.updated_at, last_complete_at = excluded.last_complete_at",
        &[
            Value::from(cli_id),
            Value::from(identity_hash),
            Value::from(raw.as_str()),
            Value::from(revision),
            Value::from(seen_at),
            last_complete_at.unwrap_or(Value::Null),
        ],
    )?;
    rebuild_tool_authority(connection, cli_id, identity_hash, &raw, revision)?;
    Ok(review_ids.into_iter().collect())
}

/// `catalog.<key> or prior.get(<key>)` for the protocol version, and
/// `catalog.<key> if ... is not None else prior.get(<key>)` for the two
/// structured fields: an empty protocol version is no version, but an empty
/// `server_info` object is an answer.
fn inherited(
    catalog: &Map<String, Value>,
    prior: &Map<String, Value>,
    key: &str,
    falsy_inherits: bool,
) -> Value {
    let current = catalog.get(key);
    let keep = match current {
        None | Some(Value::Null) => false,
        Some(Value::String(text)) if falsy_inherits => !text.is_empty(),
        Some(_) => true,
    };
    if keep {
        return current.cloned().unwrap_or(Value::Null);
    }
    prior.get(key).cloned().unwrap_or(Value::Null)
}

/// `_fresh_until`. A zero or absent TTL provides no freshness window rather
/// than an expired deadline, and a naive instant names no moment at all.
pub(crate) fn fresh_until(received_at: &str, ttl_ms: Option<&Value>) -> Value {
    // `type(ttl_ms) is not int` — Python's `bool` is not an `int` here.
    let Some(Value::Number(number)) = ttl_ms else {
        return Value::Null;
    };
    let Some(ttl_ms) = number.as_i64() else {
        return Value::Null;
    };
    if !(1..=86_400_000).contains(&ttl_ms) {
        return Value::Null;
    }
    add_micros_aware_isoformat(received_at, ttl_ms * 1_000).map_or(Value::Null, Value::from)
}

/// `_skill_metadata_snapshot`: what this connection declared and which skills
/// are known, kept apart from the tool inventory because a skill names a
/// resource rather than an executable surface.
fn skill_metadata_snapshot(
    catalog: &Map<String, Value>,
    prior: &Map<String, Value>,
    identity_hash: &str,
) -> Value {
    let skills = match catalog.get("skills") {
        Some(Value::Array(items)) => items.as_slice(),
        _ => &[],
    };
    let origin_of = |entry: &Value| {
        entry
            .get("connection_identity_hash")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let origin_changed = skills
        .iter()
        .any(|entry| origin_of(entry).as_deref() != Some(identity_hash));
    let mut complete =
        matches!(catalog.get("skills_complete"), Some(Value::Bool(true))) && !origin_changed;
    let mut reason = if origin_changed {
        Some(Value::from("skill_origin_changed"))
    } else {
        catalog.get("skills_reason").cloned()
    };

    let mut known = Ordered::empty();
    if !complete {
        if let Some(Value::Array(entries)) = prior.get("skills_catalog").and_then(|previous| {
            previous
                .as_object()
                .and_then(|previous| previous.get("entries"))
        }) {
            for entry in entries {
                if let Some(Value::String(uri)) = entry.as_object().and_then(|row| row.get("uri")) {
                    known.insert(uri.as_str(), entry);
                }
            }
        }
    }
    for entry in skills {
        if origin_of(entry).as_deref() != Some(identity_hash) {
            continue;
        }
        let Some(Value::String(uri)) = entry.as_object().and_then(|row| row.get("uri")) else {
            continue;
        };
        if !known.by_name.contains_key(uri.as_str()) && known.len() >= MAX_SKILL_ENTRIES {
            // Past capacity the inventory is partial by construction, so it
            // reports itself incomplete instead of silently dropping skills.
            complete = false;
            reason = Some(Value::from("skill_catalog_capacity"));
            continue;
        }
        known.insert(uri.as_str(), entry);
    }
    let reason = match reason {
        Some(Value::String(text)) if !text.is_empty() => Value::String(text),
        _ if complete => Value::Null,
        _ => Value::from("skills_not_checked"),
    };
    json!({
        "declared": skills_declared(catalog.get("capabilities"), catalog.get("protocol_version")),
        "complete": complete,
        "stale": !complete && !known.is_empty(),
        "reason": reason,
        "known_count": known.len(),
        "entries": known.values(),
        "activation_supported": false,
    })
}

/// `mcp_skills_declared`: the server has to name the skills extension and
/// serve resources, on a protocol version that has the extension at all.
fn skills_declared(capabilities: Option<&Value>, protocol_version: Option<&Value>) -> bool {
    let Some(Value::String(version)) = protocol_version else {
        return false;
    };
    let Some(parsed) = iso_date(version) else {
        return false;
    };
    if parsed < MIN_SKILLS_VERSION {
        return false;
    }
    let Some(Value::Object(capabilities)) = capabilities else {
        return false;
    };
    let declared = capabilities
        .get("extensions")
        .and_then(Value::as_object)
        .and_then(|extensions| extensions.get(SKILLS_EXTENSION))
        .is_some_and(Value::is_object);
    declared && capabilities.get("resources").is_some_and(Value::is_object)
}

/// `_PROTOCOL_VERSION.fullmatch` then `date.fromisoformat`: the shape first,
/// then whether that shape names a day that exists.
pub(crate) fn iso_date(text: &str) -> Option<(i64, u32, u32)> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return None;
    }
    let year: i64 = text[..4].parse().ok()?;
    let month: u32 = text[5..7].parse().ok()?;
    let day: u32 = text[8..10].parse().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (1..=days).contains(&day).then_some((year, month, day))
}

/// `_authority_shape`: the fields a saved grant is bound to, so widening a
/// schema or changing an annotation moves the tool back to review.
fn authority_shape(tool: &Value) -> StoreResult<String> {
    let shape = json!({
        "inputSchema": tool.get("inputSchema"),
        "outputSchema": tool.get("outputSchema"),
        "annotations": tool.get("annotations"),
    });
    match dumps_sorted(&shape) {
        Some(text) => Ok(text),
        None => value_error("MCP catalog snapshot is not representable"),
    }
}

/// `rebuild_tool_authority`: rebuild inside the catalog transaction, where
/// invalid or missing evidence leaves the tool with no authority row at all
/// and so permits nothing.
fn rebuild_tool_authority(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
    raw: &str,
    revision: i64,
) -> StoreResult<()> {
    exec(
        connection,
        "delete from local_mcp_tool_authority where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    let Some(payload) = decode_snapshot(Some(&Value::from(raw))) else {
        return Ok(());
    };
    let Some(tools) = payload.get("tools").and_then(Value::as_array) else {
        return Ok(());
    };
    if tools.len() > MAX_SNAPSHOT_TOOLS {
        return Ok(());
    }
    let mut rows: Vec<(&str, String)> = Vec::with_capacity(tools.len());
    let mut seen: HashSet<&str> = HashSet::with_capacity(tools.len());
    for tool in tools {
        let Some(tool) = tool.as_object() else {
            continue;
        };
        let Some(digest) = tool_definition_authority_hash(tool) else {
            continue;
        };
        let Some(Value::String(name)) = tool.get("name") else {
            continue;
        };
        // A name listed twice has no single authority, so the whole table is
        // left empty rather than binding a grant to one of two definitions.
        if !seen.insert(name.as_str()) {
            return Ok(());
        }
        rows.push((name.as_str(), digest));
    }
    for (name, digest) in rows {
        exec(
            connection,
            "insert into local_mcp_tool_authority values (?, ?, ?, ?, ?)",
            &[
                Value::from(cli_id),
                Value::from(identity_hash),
                Value::from(name),
                Value::from(revision),
                Value::from(digest),
            ],
        )?;
    }
    Ok(())
}

/// `_decode_snapshot`: stored text is evidence only when it still parses as a
/// bounded inventory.
pub(crate) fn decode_snapshot(raw: Option<&Value>) -> Option<Value> {
    let Some(Value::String(raw)) = raw else {
        return None;
    };
    if raw.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let payload: Value = serde_json::from_str(raw).ok()?;
    let object = payload.as_object()?;
    if !object.get("complete").is_some_and(Value::is_boolean) {
        return None;
    }
    if object.get("tools").and_then(Value::as_array)?.len() > MAX_SNAPSHOT_TOOLS {
        return None;
    }
    Some(payload)
}

//! `observed_mcp_tool_actions` — compiles the operator's exact choices for
//! MCP connectors observed on a harness into native policy selectors.
//!
//! An observed connector is enrolled under the `observed-mcp:<harness>:<namespace>`
//! marker. Its grant and per-tool states become `<harness>:<tool>` actions,
//! and a blocked connector or a blocked "other tools" fallback becomes a
//! `<harness>:<namespace>*` block. Only catalogued tools can be allowed: the
//! fallback may block new tools but never grants a tool the operator has not
//! seen.

use guard_command::mcp_decision::build_mcp_server_identity;
use guard_contracts::MAX_NATIVE_RESPONSE_BYTES;
use guard_policy_snapshot::normalized_harness_selector;
use rusqlite::Connection;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, Row, StoreError, StoreResult};
use crate::guard_store_local_cli_grants as local_cli_grants;
use crate::local_store_read;

const OBSERVED_MCP_PREFIX: &str = "observed-mcp:";
const OTHER_COMMAND_ID: &str = "other";
const MAX_TOOL_NAME_CHARS: usize = 160;
const MAX_NAME_CHARS: usize = 120;
const MAX_NAMESPACE_CHARS: usize = 155;
const MAX_CLI_ID_SEGMENTS: usize = 9;

/// `ObservedMcpTool`, reduced to the fields the compiler reads.
struct ObservedTool {
    namespace: String,
    qualified_name: String,
    harness: String,
}

impl ObservedTool {
    /// Names that slug to the same text keep separate permissions.
    fn command_id(&self) -> String {
        let digest = Sha256::digest(self.qualified_name.as_bytes());
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("tool-{}", &hex[..24])
    }

    fn server_identity_hash(&self) -> String {
        let command = format!("{OBSERVED_MCP_PREFIX}{}:{}", self.harness, self.namespace);
        build_mcp_server_identity("", &command, &[], "observed", None, &[]).identity_hash
    }
}

/// `_TOKEN`: `[A-Za-z0-9_.-]{1,120}`.
fn token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_NAME_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// `_FLATTENED_NAME_HARNESSES`: harnesses that present an MCP tool under a
/// single flattened name.
const FLATTENED_NAME_HARNESSES: [&str; 1] = ["omp"];

/// `_flattened_tool`: Oh My Pi presents `mcp__<server>__<tool>` as
/// `mcp__<server>_<tool>`, with the server's dashes turned into underscores.
/// Nothing in the name says where the server ends, so the connector the tool
/// was catalogued under supplies the boundary.
fn flattened_tool(harness: &str, tool_name: &str, namespace: &str) -> Option<ObservedTool> {
    if !FLATTENED_NAME_HARNESSES.contains(&harness)
        || tool_name.chars().count() > MAX_TOOL_NAME_CHARS
    {
        return None;
    }
    let rest = tool_name.strip_prefix("mcp__")?;
    if rest.contains("__") {
        return None;
    }
    let server = namespace.strip_prefix("mcp__")?.strip_suffix("__")?;
    let flat = server.replace('-', "_");
    // A server whose flattened form already ends in `_` cannot be told apart
    // from the same server joined to a `_`-led tool name.
    if flat.ends_with('_') {
        return None;
    }
    let name = rest.strip_prefix(&flat)?.strip_prefix('_')?;
    if name.starts_with('_') || !token(name) {
        return None;
    }
    Some(ObservedTool {
        namespace: namespace.to_owned(),
        qualified_name: tool_name.to_owned(),
        harness: harness.to_owned(),
    })
}

/// `observed_mcp_tool`: parse a fully qualified MCP name and keep the
/// connector boundary.
fn observed_mcp_tool(harness: &str, tool_name: &str) -> Option<ObservedTool> {
    // `str.strip` also drops the ASCII information separators.
    let harness = harness
        .trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
        .to_lowercase();
    if !token(&harness) || tool_name.chars().count() > MAX_TOOL_NAME_CHARS {
        return None;
    }
    let rest = tool_name.strip_prefix("mcp__")?;
    let harness = normalized_harness_selector(&harness)?;
    let parts: Vec<&str> = rest.split("__").collect();
    if parts.len() < 2 || !parts.iter().all(|part| token(part)) {
        return None;
    }
    let split = if parts[0] == "codex_apps" && parts.len() >= 3 {
        2
    } else {
        1
    };
    if parts[split..].join("__").chars().count() > MAX_NAME_CHARS {
        return None;
    }
    let namespace = format!("mcp__{}__", parts[..split].join("__"));
    if namespace.chars().count() > MAX_NAMESPACE_CHARS {
        return None;
    }
    Some(ObservedTool {
        namespace,
        qualified_name: tool_name.to_owned(),
        harness,
    })
}

/// The connector an `observed-mcp:<harness>:<namespace>` marker names
/// (`_source`, `store_mcp_provider_permissions.py`). The namespace must parse
/// back to itself, so a marker cannot name a connector it does not identify.
pub(crate) struct MarkerSource {
    harness: String,
    namespace: String,
}

impl MarkerSource {
    /// The MCP server identity the connector is enrolled under.
    pub(crate) fn identity_hash(&self) -> String {
        ObservedTool {
            namespace: self.namespace.clone(),
            qualified_name: String::new(),
            harness: self.harness.clone(),
        }
        .server_identity_hash()
    }

    /// `provider_action_selector(source, slug)`: one provider action of this
    /// connector, across every account it serves.
    pub(crate) fn action_selector(&self, slug: &str) -> Option<String> {
        let mut bytes = slug.bytes();
        let first = bytes.next()?;
        if !first.is_ascii_alphanumeric()
            || slug.len() > 128
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return None;
        }
        Some(format!(
            "{}:{}:composio:all-accounts:{slug}",
            self.harness, self.namespace
        ))
    }
}

pub(crate) fn marker_source(marker: &str) -> Option<MarkerSource> {
    let (harness, namespace) = marker.strip_prefix(OBSERVED_MCP_PREFIX)?.split_once(':')?;
    let tool = observed_mcp_tool(harness, &format!("{namespace}probe"))?;
    (tool.namespace == namespace).then_some(MarkerSource {
        harness: tool.harness,
        namespace: tool.namespace,
    })
}

/// `is_local_cli_id`: `local-cli.[a-z0-9]+(-[a-z0-9]+){0,8}`.
pub(crate) fn is_local_cli_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("local-cli.") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('-').collect();
    segments.len() <= MAX_CLI_ID_SEGMENTS
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn text(row: &Row, name: &str) -> Option<String> {
    row.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Oldest schema with every column these reads use. Version 12 only added
/// the declaration columns, which these reads never touch.
const MIN_READ_SCHEMA_VERSION: i64 = 11;

/// The Python writer migrates an older store before this read; a store from
/// a newer Guard, or one whose schema marker is damaged, stays unread.
pub(crate) fn require_current_schema(connection: &Connection) -> StoreResult<bool> {
    let unreadable = |_| StoreError::Invalid("native_guard_store_local_cli_schema_unreadable");
    if !local_store_read::table_exists(connection, "local_cli_observation").map_err(unreadable)? {
        return Ok(false);
    }
    match local_store_read::schema_version(connection).map_err(unreadable)? {
        Some(version)
            if (MIN_READ_SCHEMA_VERSION..=local_store_read::SUPPORTED_SCHEMA_VERSION)
                .contains(&version) =>
        {
            Ok(true)
        }
        _ => Err(StoreError::Invalid(
            "native_guard_store_local_cli_schema_unreadable",
        )),
    }
}

/// The label an observed tool is read from: the tool name a receipt or a
/// paused request recorded, which is `raw_command_text` without its `tool:`
/// prefix when it carries one and the artifact name otherwise. Every
/// observable MCP tool name starts with `mcp__`, including the flattened
/// spelling Oh My Pi uses, so the scan never reads a row without it.
const OBSERVED_LABEL: &str = "substr(case when substr(raw_command_text, 1, 5) = 'tool:' \
     then substr(raw_command_text, 6) else artifact_name end, 1, 5) = 'mcp__'";
/// A quarter of the response cap for each of the two histories, so together
/// they leave room for the envelope the resident frames them in and neither
/// one can starve the other. A history past its budget keeps its newest rows:
/// an older connector is rediscovered the next time the harness calls one of
/// its tools.
const OBSERVED_LIST_BUDGET_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES / 4;

fn projected(rows: &[Row], fields: &[&str]) -> Vec<Value> {
    let mut budget = OBSERVED_LIST_BUDGET_BYTES;
    let mut projected = Vec::new();
    for row in rows {
        let item: Map<String, Value> = fields
            .iter()
            .map(|field| {
                (
                    (*field).to_owned(),
                    row.get(*field).cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
        let bytes = serde_json::to_vec(&item).map_or(0, |encoded| encoded.len());
        // A row too large to carry is left out rather than ending the read: the
        // scan reads each row on its own, so one outsized command text costs
        // its own connector and not every older one behind it.
        let Some(remaining) = budget.checked_sub(bytes) else {
            continue;
        };
        budget = remaining;
        projected.push(Value::Object(item));
    }
    projected
}

/// `observed_mcp_history(limit)`: the paused requests and receipts the
/// connector scan reads, projected to the handful of fields it parses.
///
/// The scan used to page whole approval rows and whole receipts through the
/// resident to read a tool name and a timestamp from each. On a store with a
/// few hundred of either, the receipts alone encoded past the response cap
/// and the whole refresh failed with `native_guard_store_unavailable`, which
/// the Extensions surface showed as "Could not check host configuration".
/// Reading only the four fields the scan parses keeps the reply small enough
/// that a long history cannot stop connector discovery.
pub(crate) fn observed_mcp_history(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let limit = Value::from(args.int("limit")?.max(0));
    let approvals = query_all(
        connection,
        &format!(
            "select harness, artifact_name, raw_command_text, last_seen_at, created_at \
             from approval_requests where {OBSERVED_LABEL} \
             order by coalesce(last_seen_at, created_at) desc limit ?"
        ),
        &[limit.clone()],
    )?;
    let receipts = query_all(
        connection,
        &format!(
            "select harness, artifact_name, raw_command_text, timestamp \
             from runtime_receipts where {OBSERVED_LABEL} \
             order by timestamp desc limit ?"
        ),
        &[limit],
    )?;
    Ok(Value::Object(
        [
            (
                "approvals".to_owned(),
                Value::Array(projected(
                    &approvals,
                    &[
                        "harness",
                        "artifact_name",
                        "raw_command_text",
                        "last_seen_at",
                        "created_at",
                    ],
                )),
            ),
            (
                "receipts".to_owned(),
                Value::Array(projected(
                    &receipts,
                    &["harness", "artifact_name", "raw_command_text", "timestamp"],
                )),
            ),
        ]
        .into_iter()
        .collect(),
    ))
}

pub(crate) fn observed_mcp_tool_actions(connection: &Connection) -> StoreResult<Value> {
    let mut actions = Map::new();
    if !require_current_schema(connection)? {
        return Ok(Value::Object(actions));
    }
    // `list_local_cli_items`: every MCP observation in display order, and
    // whether a grant for another identity marks it stale. Rows whose cells
    // are not text are skipped here, so one malformed row cannot fail the
    // whole read.
    let items = query_all(
        connection,
        "select o.cli_id, o.identity_hash, o.server_command, \
                (g.identity_hash is not null and g.identity_hash is not o.identity_hash) as stale \
         from local_cli_observation as o \
         left join local_cli_grant as g on g.cli_id = o.cli_id \
         where o.surface = 'mcp' and typeof(o.cli_id) = 'text' \
           and typeof(o.identity_hash) = 'text' and typeof(o.server_command) = 'text' \
         order by o.last_seen_at desc, o.cli_id asc",
        &[],
    )?;
    for item in items {
        compile_item(connection, &item, &mut actions)?;
    }
    Ok(Value::Object(actions))
}

/// Two flattened names can land on one selector: the connector `mcp__a__`
/// joined to a tool `b_c`, and the connector `mcp__a-b__` joined to a tool
/// `c`, both read as `omp:mcp__a_b_c`. A qualified name could not collide
/// this way, because it carries the boundary itself. The runtime cannot tell
/// the two tools apart either, so the selector keeps the strictest choice any
/// connector made for it rather than whichever connector compiled last.
fn record_action(actions: &mut Map<String, Value>, selector: String, state: &str) {
    fn strictness(state: &str) -> u8 {
        match state {
            "block" => 3,
            "review" => 2,
            "allow" => 1,
            _ => 0,
        }
    }
    let kept = actions
        .get(&selector)
        .and_then(Value::as_str)
        .is_some_and(|recorded| strictness(recorded) >= strictness(state));
    if !kept {
        actions.insert(selector, Value::from(state));
    }
}

fn compile_item(
    connection: &Connection,
    item: &Row,
    actions: &mut Map<String, Value>,
) -> StoreResult<()> {
    if item.get("stale").and_then(Value::as_i64) != Some(0) {
        return Ok(());
    }
    if !text(item, "cli_id").is_some_and(|cli_id| is_local_cli_id(&cli_id)) {
        return Ok(());
    }
    let Some(marker) = text(item, "server_command") else {
        return Ok(());
    };
    let Some((harness, namespace)) = marker
        .strip_prefix(OBSERVED_MCP_PREFIX)
        .and_then(|rest| rest.split_once(':'))
    else {
        return Ok(());
    };
    let Some(example) = observed_mcp_tool(harness, &format!("{namespace}probe")) else {
        return Ok(());
    };
    if example.namespace != namespace {
        return Ok(());
    }
    let server_hash = example.server_identity_hash();
    if text(item, "identity_hash").as_deref() != Some(server_hash.as_str()) {
        return Ok(());
    }
    let Some((grant_cli_id, state)) = granted_connector(connection, &server_hash)? else {
        return Ok(());
    };
    let namespace_block = format!("{harness}:{namespace}*");
    if state.as_deref() == Some("blocked") {
        record_action(actions, namespace_block, "block");
        block_catalogued_flattened_tools(
            connection,
            &grant_cli_id,
            &example,
            namespace,
            harness,
            actions,
        )?;
        return Ok(());
    }
    let states = local_cli_grants::command_states(connection, &grant_cli_id)?;
    if states.get(OTHER_COMMAND_ID).map(String::as_str) == Some("block") {
        record_action(actions, namespace_block, "block");
    }
    for (command_id, usage) in command_catalog(connection, &grant_cli_id)? {
        if command_id == OTHER_COMMAND_ID {
            continue;
        }
        let Some(tool) = observed_mcp_tool(harness, &usage)
            .or_else(|| flattened_tool(&example.harness, &usage, namespace))
        else {
            continue;
        };
        if tool.namespace != namespace || tool.command_id() != command_id {
            continue;
        }
        if let Some(state @ ("allow" | "review" | "block")) =
            states.get(&command_id).map(String::as_str)
        {
            record_action(actions, format!("{harness}:{}", tool.qualified_name), state);
        }
    }
    Ok(())
}

/// A flattened name carries no connector boundary, so the connector's own
/// `<namespace>*` selector never matches one. Name each tool the operator saw
/// when they blocked the connector, so the block reaches them too.
fn block_catalogued_flattened_tools(
    connection: &Connection,
    grant_cli_id: &str,
    example: &ObservedTool,
    namespace: &str,
    harness: &str,
    actions: &mut Map<String, Value>,
) -> StoreResult<()> {
    if !FLATTENED_NAME_HARNESSES.contains(&example.harness.as_str()) {
        return Ok(());
    }
    for (command_id, usage) in command_catalog(connection, grant_cli_id)? {
        if command_id == OTHER_COMMAND_ID {
            continue;
        }
        let Some(tool) = flattened_tool(&example.harness, &usage, namespace) else {
            continue;
        };
        if tool.command_id() != command_id {
            continue;
        }
        record_action(
            actions,
            format!("{harness}:{}", tool.qualified_name),
            "block",
        );
    }
    Ok(())
}

/// `read_local_mcp_grant(server_identity_hash)`: the newest observation of
/// the server and its grant, when the grant still binds that observation.
fn granted_connector(
    connection: &Connection,
    server_hash: &str,
) -> StoreResult<Option<(String, Option<String>)>> {
    let observation = query_one(
        connection,
        "select case when typeof(cli_id) = 'text' then cli_id end as cli_id, identity_hash \
         from local_cli_observation \
         where surface = 'mcp' and identity_hash = ? \
           and (server_identity_hash = ? or server_identity_hash is null) \
         order by last_seen_at desc, cli_id asc limit 1",
        &[Value::from(server_hash), Value::from(server_hash)],
    )?;
    let Some(observation) = observation else {
        return Ok(None);
    };
    let (Some(cli_id), Some(identity_hash)) = (
        text(&observation, "cli_id"),
        text(&observation, "identity_hash"),
    ) else {
        return Ok(None);
    };
    let grant = query_one(
        connection,
        "select case when typeof(identity_hash) = 'text' then identity_hash end as identity_hash, \
                case when typeof(state) = 'text' then state end as state \
         from local_cli_grant where cli_id = ?",
        &[Value::from(cli_id.as_str())],
    )?;
    let Some(grant) = grant else {
        return Ok(None);
    };
    if grant.get("identity_hash").and_then(Value::as_str) != Some(identity_hash.as_str()) {
        return Ok(None);
    }
    Ok(Some((cli_id, text(&grant, "state"))))
}

/// Well-formed catalog commands in catalog order, as `(command_id, usage)`.
fn command_catalog(connection: &Connection, cli_id: &str) -> StoreResult<Vec<(String, String)>> {
    Ok(local_cli_grants::command_catalog(connection, cli_id)?
        .iter()
        .filter_map(|row| Some((text(row, "command_id")?, text(row, "usage")?)))
        .collect())
}

#[cfg(test)]
#[path = "guard_store_observed_mcp_vectors_tests.rs"]
mod vectors_tests;

#[cfg(test)]
#[path = "guard_store_observed_mcp_history_tests.rs"]
mod history_tests;

#[cfg(test)]
#[path = "guard_store_observed_mcp_flattened_tests.rs"]
mod flattened_tests;

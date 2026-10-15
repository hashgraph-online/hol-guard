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
use guard_policy_snapshot::normalized_harness_selector;
use rusqlite::Connection;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

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

/// The Python writer migrates an older store before this read; a store from
/// a newer Guard, or one whose schema marker is damaged, stays unread.
fn require_current_schema(connection: &Connection) -> StoreResult<bool> {
    let unreadable = |_| StoreError::Invalid("native_guard_store_local_cli_schema_unreadable");
    if !local_store_read::table_exists(connection, "local_cli_observation").map_err(unreadable)? {
        return Ok(false);
    }
    match local_store_read::schema_version(connection).map_err(unreadable)? {
        Some(local_store_read::SUPPORTED_SCHEMA_VERSION) => Ok(true),
        _ => Err(StoreError::Invalid(
            "native_guard_store_local_cli_schema_unreadable",
        )),
    }
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
        actions.insert(namespace_block, Value::from("block"));
        return Ok(());
    }
    let states = local_cli_grants::command_states(connection, &grant_cli_id)?;
    if states.get(OTHER_COMMAND_ID).map(String::as_str) == Some("block") {
        actions.insert(namespace_block, Value::from("block"));
    }
    for (command_id, usage) in command_catalog(connection, &grant_cli_id)? {
        if command_id == OTHER_COMMAND_ID {
            continue;
        }
        let Some(tool) = observed_mcp_tool(harness, &usage) else {
            continue;
        };
        if tool.namespace != namespace || tool.command_id() != command_id {
            continue;
        }
        if let Some(state @ ("allow" | "review" | "block")) =
            states.get(&command_id).map(String::as_str)
        {
            actions.insert(
                format!("{harness}:{}", tool.qualified_name),
                Value::from(state),
            );
        }
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

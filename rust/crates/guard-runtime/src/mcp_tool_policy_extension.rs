//! In-process this-device grant and catalog-contribution decision for a live
//! MCP `tools/call`.
//!
//! The caller supplies the non-authoritative inputs recorded on the artifact
//! (see `McpExtensionInputV1`); the store is read here, so the policy flow no
//! longer asks Python for an `extension_decision` observation. A refusal to
//! answer is never an allow: an otherwise allowed or reviewed call is held in
//! review while the device holds any grant rows.

use guard_contracts::{
    ContributedMcpDecisionRequestV1, LocalMcpGrantRequestV1, McpExtensionInputV1,
    CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA, LOCAL_MCP_GRANT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use crate::local_store_read;

type Decided = (String, String, String);
/// A static reason code, never request text.
type Code = &'static str;

/// Name why a decision went unanswered. Only static codes are written, so the
/// resident's stderr never carries request content.
fn unanswered(stage: &str, code: Code) {
    eprintln!("mcp_extension_unanswered stage={stage} code={code}");
}

fn store_code(error: local_store_read::StoreReadError) -> Code {
    match error {
        local_store_read::StoreReadError::PathInvalid => "store_path_invalid",
        local_store_read::StoreReadError::StoreUnavailable => "store_unavailable",
        local_store_read::StoreReadError::SchemaInvalid => "store_schema_invalid",
    }
}

const GRANT_REFINABLE: [&str; 4] = ["allow", "review", "require-reapproval", "warn"];
const HOLDABLE: [&str; 3] = ["allow", "warn", "review"];

/// `Value::Null` when no extension applies, else `{action, source, summary}`.
pub(crate) fn extension_decision(ext: &McpExtensionInputV1, action: &str) -> Value {
    let decided = match local_grant(ext, action) {
        Ok(Some(found)) => Some(found),
        Ok(None) => contributed_or_hold(ext, action),
        Err(code) => {
            unanswered("local_grant", code);
            hold_unverified(ext, action)
        }
    };
    match decided {
        Some((action, source, summary)) => {
            json!({"action": action, "source": source, "summary": summary})
        }
        None => Value::Null,
    }
}

fn decided(action: &str, source: &str, summary: &str) -> Option<Decided> {
    Some((action.to_owned(), source.to_owned(), summary.to_owned()))
}

/// `Err` means the resident has no answer for the grant state, and says why.
fn local_grant(ext: &McpExtensionInputV1, action: &str) -> Result<Option<Decided>, Code> {
    if !GRANT_REFINABLE.contains(&action) {
        return Ok(None);
    }
    if ext.local_unavailable {
        return Err("local_unavailable");
    }
    let request = LocalMcpGrantRequestV1 {
        schema: LOCAL_MCP_GRANT_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: ext.store_path.clone(),
        guard_home: ext.guard_home.clone(),
        current_action: action.to_owned(),
        harness: ext.harness.clone(),
        tool_name: ext.tool_name.clone(),
        server: ext.server.clone(),
        connection_identity_hash: ext.connection_identity_hash.clone(),
        tool_authority_hash: ext.tool_authority_hash.clone(),
        launcher_path: ext.launcher_path.clone(),
        launcher_home: ext.launcher_home.clone(),
    };
    let payload = crate::local_mcp_grant_op::decide(&request)?;
    Ok(match payload.get("state").and_then(Value::as_str) {
        Some("blocked") => decided(
            "block",
            "local-mcp-extension",
            "This MCP tool is blocked by a custom extension on this device.",
        ),
        Some("allowed") => decided(
            "allow",
            "local-mcp-extension",
            "This MCP tool is allowed by a custom extension on this device.",
        ),
        Some("review") => decided(
            "review",
            "local-mcp-extension",
            "This tool is not in the reviewed catalog. Review its authority before execution.",
        ),
        _ => None,
    })
}

fn contributed_once(ext: &McpExtensionInputV1, action: &str) -> Result<Option<Decided>, Code> {
    if ext.layers_unavailable {
        return Err("layers_unavailable");
    }
    let request = ContributedMcpDecisionRequestV1 {
        schema: CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: ext.store_path.clone(),
        guard_home: ext.guard_home.clone(),
        current_action: action.to_owned(),
        server_identity: ext.server_identity.clone(),
        artifact_transport: ext.artifact_transport.clone(),
        server_name: ext.server_name.clone(),
        tool_name: ext.contributed_tool_name.clone(),
        layers: ext.layers.clone(),
    };
    let payload = crate::contributed_mcp_decision_op::decide(&request)?;
    if payload.get("state").and_then(Value::as_str) != Some("decided") {
        return Ok(None);
    }
    let text = |key| payload.get(key).and_then(Value::as_str).map(str::to_owned);
    match (text("action"), text("source"), text("reason")) {
        (Some(action), Some(source), Some(reason)) => Ok(Some((action, source, reason))),
        _ => Err("contributed_payload_invalid"),
    }
}

/// The contributed decision. With no answer, an allowed or reviewed call is
/// held in review rather than guessed at or allowed.
fn contributed_or_hold(ext: &McpExtensionInputV1, action: &str) -> Option<Decided> {
    let held = |code: Code| {
        unanswered("contributed", code);
        if !HOLDABLE.contains(&action) {
            return None;
        }
        // A review is held too: with no decisive answer, a time-bounded
        // approval could upgrade it to allow past a catalog block that was not
        // checked. Stricter actions are left alone.
        decided(
            "review",
            "catalog-mcp-extension",
            "This device's catalog MCP defaults could not be verified. Review this tool call before execution.",
        )
    };
    match contributed_once(ext, action) {
        Err(code) => held(code),
        Ok(Some(found)) => Some(found),
        Ok(None) if action == "review" => match contributed_once(ext, "allow") {
            Err(code) => held(code),
            Ok(Some(found)) if found.0 == "review" => Some(found),
            Ok(_) => None,
        },
        Ok(None) => None,
    }
}

/// The resident gave no grant answer: hold an allow for review while grants
/// exist. MCP grants also produce review-only outcomes, and each needs a grant
/// row, so any row holds an otherwise allowed call, and a call already under
/// review stays decisively in review so a temporary approval cannot upgrade it
/// past a stored block.
fn hold_unverified(ext: &McpExtensionInputV1, action: &str) -> Option<Decided> {
    let contributed = contributed_or_hold(ext, action);
    if let Some(found) = &contributed {
        if found.0 == "block" || found.0 == "review" {
            return contributed;
        }
    }
    let effective = contributed
        .as_ref()
        .map_or(action, |found| found.0.as_str());
    if HOLDABLE.contains(&effective) && may_hold_mcp_grants(ext) {
        return decided(
            "review",
            "local-mcp-extension",
            "This device's MCP grants could not be verified. Review this tool call before execution.",
        );
    }
    contributed
}

/// Whether any device grant row exists. An unreadable store counts as one, and
/// so does a schema marker that is damaged or newer than this build reads: its
/// rows cannot be trusted to be absent.
fn may_hold_mcp_grants(ext: &McpExtensionInputV1) -> bool {
    let probe = || -> Result<bool, Code> {
        let path = local_store_read::require_store_path(&ext.store_path, &ext.guard_home)
            .map_err(store_code)?;
        let Some(connection) = local_store_read::open_read_only(&path).map_err(store_code)? else {
            return Ok(false);
        };
        match local_store_read::schema_version(&connection).map_err(store_code)? {
            Some(version) if version > local_store_read::SUPPORTED_SCHEMA_VERSION => {
                return Ok(true);
            }
            _ => {}
        }
        for table in ["local_cli_grant", "local_cli_command_grant"] {
            if !local_store_read::table_exists(&connection, table).map_err(store_code)? {
                continue;
            }
            let found: bool = connection
                .query_row(
                    &format!("select exists(select 1 from {table})"),
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| "grant_probe_failed")?;
            if found {
                return Ok(true);
            }
        }
        Ok(false)
    };
    probe().unwrap_or_else(|code| {
        unanswered("grant_probe", code);
        true
    })
}

#[cfg(test)]
#[path = "mcp_tool_policy_extension_tests.rs"]
mod tests;

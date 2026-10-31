//! Two bounded reads over what a connection's own MCP results proposed: the
//! provider workflows a search result suggested, and the skills its catalog
//! snapshot listed. Neither read activates anything; both describe what the
//! user would still have to decide.

use std::collections::HashSet;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    placeholders, query_all, query_one, text, value_error, Row, StoreError, StoreResult,
};
use crate::guard_store_json::py_str;
use crate::guard_store_mcp_provider_reads::{mcp_observation_identity, truthy};
use crate::guard_store_observed_mcp::{is_local_cli_id, require_current_schema};

const WORKFLOW_PAGE: usize = 10;
const MAX_WORKFLOW_OFFSET: i64 = 50;
const SKILL_PAGE: usize = 50;
const MAX_SKILL_OFFSET: i64 = 1000;
const MAX_SKILL_ENTRIES: usize = 1000;
const MAX_SEARCH_CHARS: usize = 128;
const MAX_SNAPSHOT_BYTES: usize = 2_000_000;
const MAX_SNAPSHOT_TOOLS: usize = 10_000;
const ROLES: [&str; 2] = ["primary", "supporting"];

/// A proposal whose stored metadata is not the shape the writer produces is a
/// broken row, not a page the user should be asked to decide on.
const METADATA_INVALID: StoreError =
    StoreError::Invalid("native_guard_store_workflow_metadata_invalid");

struct Proposal {
    proposal_id: Value,
    seen_at: Value,
    guidance_present: Value,
    slugs: [Vec<String>; 2],
}

fn parse_proposal(row: &Row) -> StoreResult<Proposal> {
    let metadata: Value =
        serde_json::from_str(text(row, "proposal_json")).map_err(|_| METADATA_INVALID)?;
    let metadata = metadata.as_object().ok_or(METADATA_INVALID)?;
    let mut slugs = [Vec::new(), Vec::new()];
    for (index, role) in ROLES.iter().enumerate() {
        let listed = metadata
            .get(*role)
            .and_then(Value::as_array)
            .ok_or(METADATA_INVALID)?;
        for slug in listed {
            slugs[index].push(slug.as_str().ok_or(METADATA_INVALID)?.to_owned());
        }
    }
    Ok(Proposal {
        proposal_id: row.get("proposal_id").cloned().unwrap_or(Value::Null),
        seen_at: row.get("seen_at").cloned().unwrap_or(Value::Null),
        guidance_present: metadata
            .get("guidance_present")
            .cloned()
            .ok_or(METADATA_INVALID)?,
        slugs,
    })
}

/// A page cursor as Python read it. Its page checks were written
/// `type(offset) is not int`, so a boolean or a fractional cursor named a page
/// that cannot exist rather than a broken call, and only an omitted cursor
/// broke the method contract.
fn cursor(args: &Args<'_>, key: &str) -> StoreResult<Option<i64>> {
    Ok(args
        .raw(key)
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?
        .as_i64())
}

/// One page of connection-bound proposed provider dependencies. Nothing here
/// is activated or granted: each requirement reports what the user has already
/// decided, or that the action was never observed at all.
pub(crate) fn workflow_proposals(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    let offset = cursor(args, "offset")?;
    if !is_local_cli_id(cli_id) {
        return value_error("invalid provider connection");
    }
    let Some(offset) = offset.filter(|offset| (0..=MAX_WORKFLOW_OFFSET).contains(offset)) else {
        return value_error("invalid_provider_workflow_page");
    };
    if !require_current_schema(connection)? {
        return value_error("provider_connection_unavailable");
    }
    let Some(identity_hash) = mcp_observation_identity(connection, cli_id)? else {
        return value_error("provider_connection_unavailable");
    };
    let scope = [Value::from(cli_id), Value::from(identity_hash.as_str())];
    let rows = query_all(
        connection,
        "select proposal_id, proposal_json, seen_at from local_mcp_workflow_proposal \
         where cli_id = ? and identity_hash = ? \
         order by seen_at desc, proposal_id limit ? offset ?",
        &[
            scope[0].clone(),
            scope[1].clone(),
            Value::from(WORKFLOW_PAGE as i64 + 1),
            Value::from(offset),
        ],
    )?;
    let page = &rows[..rows.len().min(WORKFLOW_PAGE)];
    let proposals = page
        .iter()
        .map(parse_proposal)
        .collect::<StoreResult<Vec<_>>>()?;

    let mut seen = HashSet::new();
    let mut slugs: Vec<String> = Vec::new();
    for proposal in &proposals {
        for role in &proposal.slugs {
            for slug in role {
                if seen.insert(slug.as_str()) {
                    slugs.push(slug.clone());
                }
            }
        }
    }
    // One bounded authority snapshot for the whole page; even SQLite's older
    // 999-variable limit covers the parser's maximum 10 x 50 action ids.
    let mut actions: Map<String, Value> = Map::new();
    if !slugs.is_empty() {
        let mut params = scope.to_vec();
        params.extend(slugs.iter().map(|slug| Value::from(slug.as_str())));
        let sql = format!(
            "select a.tool_slug, a.full_schema, a.revision, g.state \
             from local_mcp_provider_action a \
             left join local_mcp_provider_grant g on g.cli_id = a.cli_id \
             and g.identity_hash = a.identity_hash and g.tool_slug = a.tool_slug \
             where a.cli_id = ? and a.identity_hash = ? and a.provider = 'composio' \
             and a.tool_slug in ({})",
            placeholders(slugs.len())
        );
        for row in query_all(connection, &sql, &params)? {
            actions.insert(
                text(&row, "tool_slug").to_owned(),
                json!({
                    "schema_observed": truthy(&row, "full_schema"),
                    "revision": row.get("revision").cloned().unwrap_or(Value::Null),
                    "denied": text(&row, "state") == "block",
                }),
            );
        }
    }

    let rendered: Vec<Value> = proposals
        .iter()
        .map(|proposal| {
            let mut requirements = Vec::new();
            for (index, role) in ROLES.iter().enumerate() {
                for slug in &proposal.slugs[index] {
                    let action = actions.get(slug.as_str());
                    requirements.push(json!({
                        "tool_slug": slug,
                        "role": role,
                        "state": match action {
                            None => "unresolved",
                            Some(action) if action["denied"] == Value::Bool(true) => "saved-deny",
                            Some(_) => "ask",
                        },
                        "schema_observed": action
                            .map_or(Value::Bool(false), |action| action["schema_observed"].clone()),
                        "action_revision": action
                            .map_or(Value::Null, |action| action["revision"].clone()),
                    }));
                }
            }
            json!({
                "proposal_id": proposal.proposal_id,
                "source": "composio-search-guidance",
                "guidance_present": proposal.guidance_present,
                "seen_at": proposal.seen_at,
                "requirements": requirements,
                // A proposal never satisfies itself; the user still decides.
                "requirements_complete": false,
                "permissions_granted": false,
                "account_binding": "unverified",
            })
        })
        .collect();
    let next_offset = if rows.len() > page.len() {
        Value::from(offset + WORKFLOW_PAGE as i64)
    } else {
        Value::Null
    };
    Ok(json!({"proposals": rendered, "next_offset": next_offset}))
}

/// The catalog snapshot a connection recorded, refused unless it is the shape
/// the writer produces and every entry belongs to this connection.
fn decode_snapshot(raw: Option<&Value>) -> Option<Map<String, Value>> {
    let encoded = raw?.as_str()?;
    if encoded.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let Value::Object(payload) = serde_json::from_str::<Value>(encoded).ok()? else {
        return None;
    };
    if !payload.get("complete").is_some_and(Value::is_boolean)
        || payload.get("tools")?.as_array()?.len() > MAX_SNAPSHOT_TOOLS
    {
        return None;
    }
    Some(payload)
}

fn field(entry: &Value, name: &str) -> String {
    entry.get(name).and_then(py_str).unwrap_or_default()
}

fn sort_key(entry: &Value) -> (String, String) {
    (field(entry, "name"), field(entry, "uri"))
}

/// One searched page of the skills a connection's catalog listed. Listing a
/// skill is not activating it, so the page says so explicitly.
pub(crate) fn mcp_skill_page(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let cli_id = args.str("cli_id")?;
    let offset = cursor(args, "offset")?;
    let search = args.opt_str("search")?.unwrap_or_default();
    let requested_revision = args.raw("expected_revision");
    let expected_revision = requested_revision.and_then(Value::as_i64);
    if !is_local_cli_id(cli_id) || !require_current_schema(connection)? {
        return value_error("mcp_skills_unavailable");
    }
    let Some(identity_hash) = mcp_observation_identity(connection, cli_id)? else {
        return value_error("mcp_skills_unavailable");
    };
    let Some(offset) = offset.filter(|offset| (0..=MAX_SKILL_OFFSET).contains(offset)) else {
        return value_error("invalid_mcp_skill_page");
    };
    if search.chars().count() > MAX_SEARCH_CHARS
        || (requested_revision.is_some() && expected_revision.is_none_or(|revision| revision < 1))
    {
        return value_error("invalid_mcp_skill_page");
    }
    let Some(row) = query_one(
        connection,
        "select catalog_json, revision from local_mcp_catalog where cli_id = ? and identity_hash = ?",
        &[Value::from(cli_id), Value::from(identity_hash.as_str())],
    )?
    else {
        return value_error("mcp_skills_unavailable");
    };
    let Some(snapshot) = decode_snapshot(row.get("catalog_json")) else {
        return value_error("mcp_skills_unavailable");
    };
    let revision = row.get("revision").cloned().unwrap_or(Value::Null);
    if expected_revision.is_some_and(|expected| revision.as_i64() != Some(expected)) {
        return value_error("mcp_skill_catalog_changed");
    }
    let entries = snapshot
        .get("skills_catalog")
        .and_then(Value::as_object)
        .and_then(|catalog| catalog.get("entries"))
        .and_then(Value::as_array);
    let Some(entries) = entries.filter(|entries| entries.len() <= MAX_SKILL_ENTRIES) else {
        return value_error("mcp_skills_unavailable");
    };
    // An entry recorded against another connection would leak that connection's
    // catalog through this one, so the whole snapshot is refused.
    if entries.iter().any(|entry| {
        entry.as_object().is_none_or(|entry| {
            entry.get("connection_identity_hash") != Some(&Value::from(identity_hash.as_str()))
        })
    }) {
        return value_error("mcp_skills_unavailable");
    }

    let needle = caseless::default_case_fold_str(search);
    let mut selected: Vec<&Value> = entries
        .iter()
        .filter(|entry| {
            let haystack = format!(
                "{} {} {}",
                field(entry, "name"),
                field(entry, "description"),
                field(entry, "uri")
            );
            caseless::default_case_fold_str(&haystack).contains(&needle)
        })
        .collect();
    selected.sort_by_key(|entry| sort_key(entry));
    let start = (offset as usize).min(selected.len());
    let end = start.saturating_add(SKILL_PAGE).min(selected.len());
    let next_offset = if end < selected.len() {
        Value::from(offset + SKILL_PAGE as i64)
    } else {
        Value::Null
    };
    Ok(json!({
        "entries": selected[start..end],
        "revision": revision,
        "next_offset": next_offset,
        "known_count": entries.len(),
        "matched_count": selected.len(),
        // Reading the catalog never turns a skill on.
        "activation_supported": false,
    }))
}

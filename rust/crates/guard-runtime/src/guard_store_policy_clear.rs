//! `clear_policy_decisions` — the resident's own policy clear.
//!
//! One transaction deletes the decisions that match the caller's filters and,
//! when the caller ships the policy-integrity key, advances the integrity
//! generation over the local rows that remain, exactly as `upsert_policy`
//! does after a save. The control state stays with the caller, which persists
//! the pending state before this call and the final state after.
//!
//! A clear by `decision_ids` deletes only those rows; an empty list deletes
//! nothing. Otherwise a clear by `artifact_id` widens to every artifact row the dashboard shows
//! as the same remembered command, as `remembered_artifact_decision_ids` did,
//! so one click removes the whole displayed row.
//!
//! `unsigned_only` asks for a clear that removes no local row. When the
//! filters match one and no key came with the call, nothing is deleted and
//! the answer is `{"needs_signing": true}`: the caller begins a generation
//! and clears again with the key. The check and the delete share one
//! transaction, so a row written between them cannot slip out unsigned.

use std::collections::BTreeSet;

use guard_policy_snapshot::policy_integrity::REMOTE_POLICY_SOURCES;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, placeholders, query_all, value_error, Row, StoreResult};
use crate::guard_store_policy_source_context::policy_source_contexts;
use crate::guard_store_policy_upsert::{advance_generation, signing_material};
use crate::policy_decision_lookup_op::{normalized_workspace_path, workspace_policy_key};

const POLICY_SCOPES: [&str; 5] = ["global", "harness", "workspace", "artifact", "publisher"];
const APPROVAL_GATE_POLICY_SOURCE: &str = "approval-gate";

/// `GuardStore.clear_policy_decisions` (`store_policy_integrity_runtime.py`).
pub(crate) fn clear_policy_decisions(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let Some((conditions, params)) = filters(connection, args)? else {
        return Ok(json!({"cleared": 0, "next_control_state": null}));
    };
    let filter = if conditions.is_empty() {
        String::new()
    } else {
        conditions.join(" and ")
    };
    let signing = signing_material(args)?;
    if signing.is_none()
        && args.flag("unsigned_only")?
        && local_matches(connection, &filter, &params)? > 0
    {
        return Ok(json!({"needs_signing": true}));
    }
    let mut sql = "delete from policy_decisions".to_owned();
    if !filter.is_empty() {
        sql.push_str(" where ");
        sql.push_str(&filter);
    }
    let cleared = exec(connection, &sql, &params)?;
    let next_control_state = match signing {
        Some(material) => advance_generation(
            connection,
            &material.key,
            material.key_id,
            args.str("now")?,
            material.current_generation,
            &[],
        )?,
        None => Value::Null,
    };
    Ok(json!({"cleared": cleared, "next_control_state": next_control_state}))
}

/// How many local (not remotely synced) rows the filters match.
fn local_matches(connection: &Connection, filter: &str, params: &[Value]) -> StoreResult<i64> {
    let mut sql = format!(
        "select count(*) as local from policy_decisions where source not in ({})",
        placeholders(REMOTE_POLICY_SOURCES.len())
    );
    if !filter.is_empty() {
        sql.push_str(" and ");
        sql.push_str(filter);
    }
    let mut bound: Vec<Value> = REMOTE_POLICY_SOURCES.iter().map(|s| json!(s)).collect();
    bound.extend_from_slice(params);
    Ok(query_all(connection, &sql, &bound)?
        .first()
        .and_then(|row| row.get("local").and_then(Value::as_i64))
        .unwrap_or(0))
}

type Filters = (Vec<String>, Vec<Value>);

/// The `where` clauses and their parameters; `None` when an empty
/// `decision_ids` list can match nothing.
fn filters(connection: &Connection, args: &Args) -> StoreResult<Option<Filters>> {
    let harness = args.opt_str("harness")?;
    let mut artifact_id = args.opt_str("artifact_id")?;
    let mut artifact_hash = args.opt_str("artifact_hash")?;
    let mut artifact_id_is_null = args.flag("artifact_id_is_null")?;
    let mut artifact_hash_is_null = args.flag("artifact_hash_is_null")?;
    let mut conditions = Vec::new();
    let mut params = Vec::new();
    let mut decision_ids = match args.raw("decision_ids") {
        Some(_) => Some(
            args.ints("decision_ids")?
                .into_iter()
                .collect::<BTreeSet<i64>>(),
        ),
        None => None,
    };
    if let (Some(target), None) = (artifact_id, &decision_ids) {
        let siblings = remembered_artifact_decision_ids(connection, harness, target)?;
        if !siblings.is_empty() {
            decision_ids = Some(siblings.into_iter().collect());
            artifact_id = None;
            artifact_hash = None;
            artifact_id_is_null = false;
            artifact_hash_is_null = false;
        }
    }
    if let Some(ids) = decision_ids {
        if ids.is_empty() {
            return Ok(None);
        }
        conditions.push(format!("decision_id in ({})", placeholders(ids.len())));
        params.extend(ids.into_iter().map(Value::from));
    }
    if let Some(harness) = harness {
        conditions.push("harness = ?".to_owned());
        params.push(json!(harness));
    }
    if let Some(source) = args.opt_str("source")? {
        conditions.push("source = ?".to_owned());
        params.push(json!(source));
    }
    if let Some(scope) = args.opt_str("scope")? {
        if !POLICY_SCOPES.contains(&scope) {
            return value_error(&format!("Invalid policy scope: {scope}"));
        }
        conditions.push("scope = ?".to_owned());
        params.push(json!(scope));
    }
    if let Some(artifact_id) = artifact_id {
        conditions.push("artifact_id = ?".to_owned());
        params.push(json!(artifact_id));
    } else if artifact_id_is_null {
        conditions.push("artifact_id is null".to_owned());
    }
    if let Some(artifact_hash) = artifact_hash {
        conditions.push("artifact_hash = ?".to_owned());
        params.push(json!(artifact_hash));
    } else if artifact_hash_is_null {
        conditions.push("artifact_hash is null".to_owned());
    }
    if let Some(workspace) = args.opt_str("workspace")? {
        // `_stored_workspace_policy_key`: an already-keyed value matches
        // itself; otherwise the hashed key, or the raw path older rows kept.
        let Some(key) = workspace_policy_key(Some(workspace)) else {
            return value_error("Workspace policy key cannot be empty");
        };
        conditions.push("(workspace = ? or workspace = ?)".to_owned());
        params.push(json!(key));
        params.push(json!(normalized_workspace_path(workspace)));
    }
    if let Some(publisher) = args.opt_str("publisher")? {
        conditions.push("publisher = ?".to_owned());
        params.push(json!(publisher));
    }
    Ok(Some((conditions, params)))
}

/// `remembered_artifact_decision_ids` (`store_policy_list.py`) over
/// `list_policy_decisions(harness)`: the artifact rows that share the target
/// row's harness, action, source and remembered command.
fn remembered_artifact_decision_ids(
    connection: &Connection,
    harness: Option<&str>,
    artifact_id: &str,
) -> StoreResult<BTreeSet<i64>> {
    let mut sql = "select decision_id, harness, scope, artifact_id, artifact_hash, workspace, \
                   action, reason, source, updated_at from policy_decisions \
                   where not (source = ? and expires_at is not null)"
        .to_owned();
    let mut params = vec![json!(APPROVAL_GATE_POLICY_SOURCE)];
    if let Some(harness) = harness {
        sql.push_str(" and harness = ?");
        params.push(json!(harness));
    }
    sql.push_str(" order by updated_at desc");
    let rows = query_all(connection, &sql, &params)?;
    let Some(target) = rows
        .iter()
        .position(|row| text(row, "artifact_id") == artifact_id)
    else {
        return Ok(BTreeSet::new());
    };
    if text(&rows[target], "scope") != "artifact" {
        return Ok(BTreeSet::new());
    }
    let commands = remembered_commands(connection, &rows);
    let key = |index: usize| {
        let row = &rows[index];
        let command = commands[index]
            .clone()
            .filter(|command| !command.is_empty())
            .unwrap_or_else(|| text(row, "artifact_id"));
        (
            text(row, "harness"),
            text(row, "action"),
            text(row, "source"),
            command,
        )
    };
    let wanted = key(target);
    Ok((0..rows.len())
        .filter(|index| text(&rows[*index], "scope") == "artifact" && key(*index) == wanted)
        .filter_map(|index| rows[index].get("decision_id").and_then(Value::as_i64))
        .collect())
}

/// Each row's remembered command, as `_attach_policy_source_contexts` adds
/// it. A lookup that fails leaves every row without one, as it did there.
fn remembered_commands(connection: &Connection, rows: &[Row]) -> Vec<Option<String>> {
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            let field = |key: &str| row.get(key).cloned().unwrap_or(Value::Null);
            json!({
                "harness": text(row, "harness"),
                "artifact_id": field("artifact_id"),
                "artifact_hash": field("artifact_hash"),
                "workspace": field("workspace"),
                "reason": field("reason"),
                "action": field("action"),
                "updated_at": field("updated_at"),
            })
        })
        .collect();
    let mut request = Map::new();
    request.insert("items".to_owned(), Value::Array(items));
    let contexts = policy_source_contexts(connection, &Args(&request))
        .ok()
        .and_then(|contexts| contexts.as_array().cloned())
        .filter(|contexts| contexts.len() == rows.len());
    match contexts {
        Some(contexts) => contexts
            .iter()
            .map(|context| {
                context
                    .get("remembered_command")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect(),
        None => vec![None; rows.len()],
    }
}

/// `str(item.get(key) or "")`.
fn text(row: &Row, key: &str) -> String {
    match row.get(key) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
#[path = "guard_store_policy_clear_tests.rs"]
mod tests;

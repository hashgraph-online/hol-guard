//! `GuardStore.resolve_matching_approval_requests`: one scope sweep that
//! selects the pending requests a harness, artifact, publisher, workspace or
//! global decision covers, keeps the ones whose stored surfaces accept a user
//! resolution and resolves them in the caller's write transaction. The
//! approval gate stays with the caller, which checks it before the sweep.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_approval_page_reads::ORDER;
use crate::guard_store_approval_read_scope::project;
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, placeholders, query_all, text, Row, StoreResult};
use crate::guard_store_json::py_strip;
use crate::guard_store_policy_source_labels::artifact_family_key;
use crate::guard_store_silent_review::py_str;

/// `_SCOPED_RUNTIME_EXACT_FAMILIES`: families whose requests match by exact
/// artifact id only.
const RUNTIME_EXACT_FAMILIES: [&str; 5] = [
    "file-read",
    "mcp-tool",
    "package-request",
    "prompt",
    "tool-action",
];
/// `_MAX_RESOLVED_SCOPE_IDS`: ids the sweep reports; it resolves them all.
const MAX_REPORTED_IDS: usize = 200;
/// `_SQLITE_ID_BATCH_SIZE` and `_APPROVAL_RESOLUTION_BATCH_SIZE`.
const ID_BATCH: usize = 500;
/// The columns the resolvability projection reads.
const PROJECTION_COLUMNS: &str =
    "request_id, policy_action, decision_v2_json, action_envelope_json";

pub(crate) fn resolve_matching_approval_requests(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let harness = args.opt_str("harness")?;
    let artifact_id = args.opt_str("artifact_id")?;
    let artifact_hash = args.opt_str("artifact_hash")?;
    let resolution = resolution(args)?;
    let rows = match args.str("scope")? {
        "workspace" => {
            let (Some(harness), Some(workspace)) = (harness, args.opt_str("workspace")?) else {
                return Ok(Value::Array(Vec::new()));
            };
            query_all(
                connection,
                &format!(
                    "select {PROJECTION_COLUMNS}, artifact_id, artifact_hash, config_path \
                     from approval_requests where status = 'pending' and harness = ? {ORDER}"
                ),
                &[Value::from(harness)],
            )?
            .into_iter()
            .map(|row| {
                Ok((
                    within_workspace(&py_str(row.get("config_path"))?, workspace),
                    row,
                ))
            })
            .collect::<StoreResult<Vec<_>>>()?
            .into_iter()
            .filter(|(within, row)| {
                *within
                    && artifact_id.is_none_or(|artifact_id| {
                        stored(row, "artifact_id") == Some(artifact_id)
                            && artifact_hash
                                .is_none_or(|hash| stored(row, "artifact_hash") == Some(hash))
                    })
            })
            .map(|(_, row)| row)
            .collect()
        }
        scope => {
            let publisher = args.opt_str("publisher")?;
            let Some((conditions, params)) =
                scope_conditions(scope, harness, artifact_id, artifact_hash, publisher)
            else {
                return Ok(Value::Array(Vec::new()));
            };
            let clause = std::iter::once("status = 'pending'".to_owned())
                .chain(conditions)
                .collect::<Vec<_>>()
                .join(" and ");
            query_all(
                connection,
                &format!(
                    "select {PROJECTION_COLUMNS} from approval_requests where {clause} {ORDER}"
                ),
                &params,
            )?
        }
    };
    let ids = resolvable_ids(&rows, guard_home)?;
    resolve_ids(connection, &ids, &resolution)?;
    Ok(Value::from(
        ids.into_iter().take(MAX_REPORTED_IDS).collect::<Vec<_>>(),
    ))
}

/// `_approval_scope_conditions`. Native pretool requests share one artifact
/// id per tool; the action hash tells them apart, so a sweep that names the
/// hash requires it too, except for families matched by exact artifact id.
fn scope_conditions(
    scope: &str,
    harness: Option<&str>,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    publisher: Option<&str>,
) -> Option<(Vec<String>, Vec<Value>)> {
    let action = |mut conditions: Vec<String>, mut params: Vec<Value>| {
        conditions.push("artifact_id = ?".to_owned());
        params.push(Value::from(artifact_id));
        if let Some(hash) = artifact_hash {
            conditions.push("artifact_hash = ?".to_owned());
            params.push(Value::from(hash));
        }
        Some((conditions, params))
    };
    let exact = |mut conditions: Vec<String>, mut params: Vec<Value>| {
        conditions.push("artifact_id = ?".to_owned());
        params.push(Value::from(artifact_id));
        Some((conditions, params))
    };
    match scope {
        "global" if runtime_exact(artifact_id) => exact(Vec::new(), Vec::new()),
        "global" if artifact_id.is_some() => action(Vec::new(), Vec::new()),
        "global" => Some((Vec::new(), Vec::new())),
        "harness" => {
            let by_harness = (vec!["harness = ?".to_owned()], vec![Value::from(harness?)]);
            if runtime_exact(artifact_id) {
                return exact(by_harness.0, by_harness.1);
            }
            match artifact_family_key(artifact_id) {
                Some(family) => {
                    let family = family.strip_prefix("family:").unwrap_or(&family);
                    let (mut conditions, mut params) = by_harness;
                    conditions.push("artifact_id like ?".to_owned());
                    params.push(Value::from(format!("%:{family}:%")));
                    Some((conditions, params))
                }
                None if artifact_id.is_none() => Some(by_harness),
                None => action(by_harness.0, by_harness.1),
            }
        }
        "artifact" => {
            artifact_id?;
            action(vec!["harness = ?".to_owned()], vec![Value::from(harness?)])
        }
        "publisher" => Some((
            vec!["harness = ?".to_owned(), "publisher = ?".to_owned()],
            vec![Value::from(harness?), Value::from(publisher?)],
        )),
        _ => None,
    }
}

fn stored<'a>(row: &'a Row, name: &str) -> Option<&'a str> {
    row.get(name).and_then(Value::as_str)
}

/// `_runtime_scoped_exact_match_key(artifact_id) is not None`.
fn runtime_exact(artifact_id: Option<&str>) -> bool {
    let Some(artifact_id) = artifact_id else {
        return false;
    };
    if py_strip(artifact_id).is_empty() || artifact_id.starts_with("family:") {
        return false;
    }
    artifact_family_key(Some(artifact_id)).is_some_and(|family| {
        RUNTIME_EXACT_FAMILIES.contains(&family.strip_prefix("family:").unwrap_or(&family))
    })
}

/// The `resolution_action`, `resolution_scope`, `reason` and `resolved_at`
/// a resolution writes, read before any row is selected so a malformed call
/// fails the same way whatever matches.
pub(crate) fn resolution(args: &Args<'_>) -> StoreResult<[Value; 4]> {
    Ok([
        Value::from(args.str("resolution_action")?),
        Value::from(args.str("resolution_scope")?),
        Value::from(args.opt_str("reason")?),
        Value::from(args.str("resolved_at")?),
    ])
}

/// `_resolve_request_ids`: resolves the still-pending requests among `ids`.
pub(crate) fn resolve_ids(
    connection: &Connection,
    ids: &[String],
    resolution: &[Value; 4],
) -> StoreResult<()> {
    for chunk in ids.chunks(ID_BATCH) {
        let mut params = resolution.to_vec();
        params.extend(chunk.iter().map(|id| Value::from(id.as_str())));
        exec(
            connection,
            &format!(
                "update approval_requests set status = 'resolved', resolution_action = ?, \
                 resolution_scope = ?, reason = ?, resolved_at = ? \
                 where request_id in ({}) and status = 'pending'",
                placeholders(chunk.len())
            ),
            &params,
        )?;
    }
    Ok(())
}

/// `resolvable_approval_request_ids`: the rows, in order, whose projected
/// surfaces accept a user resolution. A row the resident cannot project
/// fails the sweep before anything is written.
pub(crate) fn resolvable_ids(rows: &[Row], guard_home: &str) -> StoreResult<Vec<String>> {
    let mut ids = Vec::new();
    for row in rows {
        let projection = project(row, guard_home)?;
        if resolution_block_reason(&projection).is_none() {
            ids.push(text(row, "request_id").to_owned());
        }
    }
    Ok(ids)
}

/// `approval_resolution_block_reason` for a projected row, answered by the
/// one contract function the resident op answers with.
pub(crate) fn resolution_block_reason(projection: &Value) -> Option<&'static str> {
    guard_contracts::approval_resolution_block_reason(
        &projection["contract_error"],
        &projection["policy_action"],
    )
}

/// `_path_within_workspace`.
fn within_workspace(config_path: &str, workspace: &str) -> bool {
    let config = normalized_workspace_path(config_path);
    let workspace = normalized_workspace_path(workspace);
    if config.is_empty() || workspace.is_empty() {
        return false;
    }
    if workspace == "/" {
        return config.starts_with('/');
    }
    config == workspace || config.starts_with(&format!("{workspace}/"))
}

/// `_normalized_workspace_path`: stripped, forward slashes, no trailing
/// slash, and a drive-letter path lower-cased.
fn normalized_workspace_path(value: &str) -> String {
    let mut normalized = py_strip(value).replace('\\', "/");
    while normalized.chars().count() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.chars().nth(1) == Some(':') {
        normalized = normalized.to_lowercase();
    }
    normalized
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_sweep_tests.rs"]
pub(crate) mod tests;

//! `workspace_skills_scan`: the SKILL.md files an install leaves in a
//! workspace, described and risk-scanned against the identity the Guard store
//! holds for each, with the changed ones saved back.
//!
//! The request takes `workspace_dir` (absolute), `now` and `source`
//! (`GuardStore.guard_source`). It answers `{skill_scan: [...]}`: a
//! `scanned` result for each skill with risk signals, and one `unscanned`
//! result when the scan itself could not run, which is never reported as
//! clean. The store stays untouched for a skill the scan could not describe.

use serde_json::{json, Map, Value};

use super::managed_record::store_call;
use super::{Ctx, Failure, Step};
use crate::workspace_skills_scan_op::run_command;

const SNAPSHOT_HARNESS: &str = "skill_scan";

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

/// One op of the runtime's skill scan, or `None` when it could not answer.
fn scan_op(op: &str, workspace: &str, stored: Option<Map<String, Value>>) -> Option<Value> {
    let mut request = json!({ "op": op, "workspace_dir": workspace });
    if let Some(stored) = stored {
        request["stored"] = Value::Object(stored);
    }
    let bytes = run_command(request.to_string().as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// What the install already applied is not undone by a runtime that cannot
/// scan: the skills are reported as unscanned.
fn unavailable() -> Value {
    json!({ "skill_scan": [{
        "skill_path": ".",
        "identity_hash": null,
        "status": "unscanned",
        "risk_count": null,
        "severities": [],
        "signal_ids": [],
        "scan_error": "native_workspace_skills_scan_unavailable",
    }] })
}

/// The identity hash the store holds for one skill path.
fn stored_hash(ctx: &Ctx, source: &str, path: &str) -> Step<Option<String>> {
    let row = store_call(
        ctx,
        source,
        "get_artifact_snapshot",
        json!({ "harness": SNAPSHOT_HARNESS, "artifact_id": format!("skill-path:{path}") }),
    )?;
    Ok(row
        .get("snapshot_json")
        .and_then(Value::as_str)
        .and_then(|snapshot| serde_json::from_str::<Value>(snapshot).ok())
        .and_then(|snapshot| {
            snapshot
                .get("identity_hash")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }))
}

pub(super) fn dispatch(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let workspace = text(fields, "workspace_dir")?;
    let now = text(fields, "now")?;
    let source = text(fields, "source")?;
    let skills = scan_op("list", workspace, None)
        .as_ref()
        .and_then(|listing| listing.get("skills"))
        .and_then(Value::as_array)
        .and_then(|skills| skills.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
        .map(|skills| skills.into_iter().map(str::to_owned).collect::<Vec<_>>());
    let Some(skills) = skills else {
        return Ok(unavailable());
    };
    if skills.is_empty() {
        return Ok(json!({ "skill_scan": [] }));
    }
    let mut stored = Map::new();
    for path in &skills {
        // The install already applied: a store that cannot answer leaves the scan unavailable.
        match stored_hash(ctx, source, path) {
            Ok(Some(hash)) => {
                stored.insert(path.clone(), json!(hash));
            }
            Ok(None) => {}
            Err(_) => return Ok(unavailable()),
        }
    }
    let answer = scan_op("scan", workspace, Some(stored));
    let (Some(results), Some(snapshots)) = (
        answer
            .as_ref()
            .and_then(|answer| answer.get("results"))
            .and_then(Value::as_array),
        answer
            .as_ref()
            .and_then(|answer| answer.get("snapshots"))
            .and_then(Value::as_array),
    ) else {
        return Ok(unavailable());
    };
    let mut rows = Vec::new();
    for row in snapshots {
        let (Some(artifact_id), Some(payload), Some(hash)) = (
            row.get("artifact_id").and_then(Value::as_str),
            row.get("payload"),
            row.get("identity_hash").and_then(Value::as_str),
        ) else {
            return Ok(unavailable());
        };
        rows.push((artifact_id, payload, hash));
    }
    for (artifact_id, payload, hash) in rows {
        // A snapshot that cannot be saved is scanned again next time; the findings
        // already computed are still returned rather than lost with the failure.
        if store_call(
            ctx,
            source,
            "save_artifact_snapshot",
            json!({
                "harness": SNAPSHOT_HARNESS,
                "artifact_id": artifact_id,
                "snapshot_json": payload.to_string(),
                "artifact_hash": hash,
                "now": now,
            }),
        )
        .is_err()
        {
            break;
        }
    }
    let results: Vec<&Value> = results.iter().filter(|result| result.is_object()).collect();
    Ok(json!({ "skill_scan": results }))
}

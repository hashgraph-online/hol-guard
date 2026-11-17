//! Copilot's MCP plan: the launch-only slots `copilot_mcp_plan` reads, its
//! per-target answer, and that answer applied to each config with the proxy
//! relaunches and managed entries Python built.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::copilot::{normcase, MCP_KEYS};
use super::files::{self, Doc, Object};
use super::{Ctx, Failure, Step};
use crate::pyjson::{self, PyVal};

const MALFORMED: &str = "Copilot MCP plan answer is malformed";

/// `_launch_slot`: absent, not an object, or the launch-only pairs.
fn launch_slot(payload: &Object, key: &str) -> Step<Value> {
    let Some((_, servers)) = payload.entries.iter().find(|(name, _)| name == key) else {
        return Ok(Value::Null);
    };
    let Some(servers) = servers.as_dict() else {
        return Ok(json!(false));
    };
    servers
        .iter()
        .map(|(name, config)| {
            let launch = match config.as_dict() {
                None => Value::Null,
                Some(config) => {
                    let mut kept = Map::new();
                    for (field, value) in config
                        .iter()
                        .filter(|(field, _)| field == "command" || field == "args")
                    {
                        kept.insert(field.clone(), value.to_json().ok_or(Failure::Invalid)?);
                    }
                    Value::Object(kept)
                }
            };
            Ok(json!([name, launch]))
        })
        .collect::<Step<Vec<_>>>()
        .map(Value::Array)
}

/// `_plan_mcp_targets`: each target's native plan and the install notes.
pub(super) fn plan_targets(
    ctx: &Ctx,
    targets: &[(PathBuf, Object)],
    managed: &[(String, String, String, PyVal)],
) -> Step<(Vec<Value>, Vec<PyVal>)> {
    let request = json!({
        "workspace": ctx.workspace.is_some(),
        "managed": managed.iter().map(|(name, scope, path, _)| json!([name, scope, normcase(Path::new(path))])).collect::<Vec<_>>(),
        "targets": targets.iter().map(|(path, payload)| Ok(json!({
            "path": normcase(path),
            "name": path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(),
            "mcpServers": launch_slot(payload, MCP_KEYS[0])?,
            "servers": launch_slot(payload, MCP_KEYS[1])?,
        }))).collect::<Step<Vec<_>>>()?,
    });
    let answer =
        crate::copilot_mcp_plan::plan(&request).map_err(|_| Failure::Refusal(MALFORMED.into()))?;
    let plans = answer["targets"]
        .as_array()
        .filter(|plans| plans.len() == targets.len());
    let notes = answer["notes"].as_array().and_then(|notes| {
        notes
            .iter()
            .map(|note| note.as_str().map(files::text))
            .collect::<Option<Vec<_>>>()
    });
    match (plans, notes) {
        (Some(plans), Some(notes)) => Ok((plans.clone(), notes)),
        _ => Err(Failure::Refusal(MALFORMED.into())),
    }
}

/// The servers object a plan's `source` names, as ordered pairs.
pub(super) fn plan_servers<'a>(plan: &Value, payload: &'a Object) -> Step<&'a [(String, PyVal)]> {
    let malformed = || Failure::Refusal(MALFORMED.into());
    match plan["source"].as_str() {
        None if plan["source"].is_null() => Ok(&[]),
        Some(source) if MCP_KEYS.contains(&source) => payload
            .entries
            .iter()
            .find(|(key, _)| key == source)
            .and_then(|(_, servers)| servers.as_dict())
            .ok_or_else(malformed),
        _ => Err(malformed()),
    }
}

pub(super) fn parsed_field(fields: &Map<String, Value>, key: &str) -> Step<PyVal> {
    let raw = fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    pyjson::parse(raw).map_err(|_| Failure::Invalid)
}

/// `[[name, source_scope, config_path, proxy entry], ...]` from Python.
pub(super) fn managed_servers(
    fields: &Map<String, Value>,
) -> Step<Vec<(String, String, String, PyVal)>> {
    let managed = parsed_field(fields, "managed")?;
    managed
        .as_list()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|row| match row.as_list() {
            Some(
                [PyVal::Str(name), PyVal::Str(scope), PyVal::Str(path), entry @ PyVal::Dict(_)],
            ) => Ok((name.clone(), scope.clone(), path.clone(), entry.clone())),
            _ => Err(Failure::Invalid),
        })
        .collect()
}

/// `_apply_mcp_plan` with the relaunches Python built for its refresh rows.
pub(super) fn apply_plan(
    plan: &Value,
    payload: &mut Object,
    managed: &[(String, String, String, PyVal)],
    launches: &[PyVal],
) -> Step<()> {
    let malformed = || Failure::Refusal(MALFORMED.into());
    let key = plan["key"]
        .as_str()
        .filter(|key| MCP_KEYS.contains(key))
        .ok_or_else(malformed)?;
    let mut normalized = Doc(plan_servers(plan, payload)?.to_vec());
    let rows = plan["refresh"]
        .as_array()
        .filter(|rows| rows.len() == launches.len())
        .ok_or_else(malformed)?;
    for (row, launch) in rows.iter().zip(launches) {
        let index = row[0]
            .as_u64()
            .map(|index| index as usize)
            .ok_or_else(malformed)?;
        let (name, config) = normalized.0.get(index).cloned().ok_or_else(malformed)?;
        let mut refreshed = Doc(config.as_dict().ok_or_else(malformed)?.to_vec());
        refreshed
            .set(
                "command",
                launch.get("command").cloned().ok_or_else(malformed)?,
            )
            .set("args", launch.get("args").cloned().ok_or_else(malformed)?);
        match launch.get("env") {
            Some(env) if env.truthy() => {
                refreshed.set("env", env.clone());
            }
            _ => refreshed
                .0
                .retain(|(field, _)| field != "env" && field != "environment"),
        }
        normalized.set(&name, refreshed.value());
    }
    for index in plan["add"].as_array().ok_or_else(malformed)? {
        let index = index
            .as_u64()
            .map(|index| index as usize)
            .ok_or_else(malformed)?;
        let (name, _, _, entry) = managed.get(index).ok_or_else(malformed)?;
        let mut entry = Doc(entry.as_dict().unwrap_or(&[]).to_vec());
        for pair in plan["fields"].as_array().ok_or_else(malformed)? {
            let field = pair[0].as_str().ok_or_else(malformed)?;
            entry.set(
                field,
                pyjson::parse(&pair[1].to_string()).map_err(|_| malformed())?,
            );
        }
        normalized.set(name, entry.value());
    }
    payload.set(key, normalized.value());
    let other = if key == MCP_KEYS[0] {
        MCP_KEYS[1]
    } else {
        MCP_KEYS[0]
    };
    payload.entries.retain(|(name, _)| name != other);
    Ok(())
}

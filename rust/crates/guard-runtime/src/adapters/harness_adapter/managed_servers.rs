//! The managed MCP servers of a detection, as `guard/adapters/mcp_servers.py`
//! chose them: `managed_stdio_servers`, `skipped_stdio_server_names` and the
//! `proxy_launcher_entry` that launches each managed server behind Guard's
//! proxy.
//!
//! Every function reads the detected artifacts as the native detection kinds
//! answer them, including the private MCP arguments and environment a
//! detection carries beside the public, redacted ones.

use serde_json::{json, Map, Value};

use super::{proxy_launch, Ctx, Failure, Step};
use crate::harness_mcp_discovery;
use crate::pyjson::PyVal;

/// `detection_from`'s artifacts: the detected ones, extended with the
/// workspace AIBOM the way `extend_detection_with_workspace_aibom` extends
/// them when the detection asks for it and the install has a workspace.
///
/// Only server artifacts are read from the result, so the portable workspace
/// skills the Python merge sent are not needed here.
pub(super) fn detected(ctx: &Ctx, harness: &str, detection: &Value) -> Step<Vec<Value>> {
    let mut merged = detection
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(Failure::Invalid)?;
    let workspace = match &ctx.workspace {
        Some(workspace) if detection.get("workspace_aibom") == Some(&Value::Bool(true)) => {
            ctx.absolute(workspace)
        }
        _ => return Ok(merged),
    };
    let existing: Vec<Value> = merged
        .iter()
        .map(|artifact| {
            json!({
                "artifact_id": artifact.get("artifact_id"),
                "artifact_type": artifact.get("artifact_type"),
                "harness": artifact.get("harness"),
                "config_path": artifact.get("config_path").filter(|path| path.is_string()),
            })
        })
        .collect();
    let plan = crate::aibom_op::workspace_merge_plan(&json!({
        "harness": harness,
        "workspace_dir": super::path_text(&workspace),
        "existing": existing,
    }))
    .map_err(unavailable)?;
    let invalid = || Failure::Refusal("native_runner_authority_result_invalid".into());
    if plan.get("extra_count").and_then(Value::as_u64) == Some(0) {
        return Ok(merged);
    }
    for replacement in plan
        .get("replacements")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
    {
        let index = replacement
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < merged.len())
            .ok_or_else(invalid)?;
        merged[index] = replacement.get("artifact").cloned().ok_or_else(invalid)?;
    }
    merged.extend(
        plan.get("appended")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .cloned(),
    );
    Ok(merged)
}

/// One managed server: its name, source scope, config path and the launch
/// entry that runs it behind Guard's proxy.
pub(super) type Managed = (String, String, String, PyVal);

fn unavailable(error: &str) -> Failure {
    Failure::Refusal(format!("native_mcp_server_identity_unavailable:{error}"))
}

fn malformed() -> Failure {
    Failure::Refusal("native_mcp_server_select_malformed".into())
}

fn servers(artifacts: &[Value]) -> Vec<&Value> {
    artifacts
        .iter()
        .filter(|artifact| {
            artifact.get("artifact_type").and_then(Value::as_str) == Some("mcp_server")
        })
        .collect()
}

/// `_env_pairs`: the string pairs of a configured env mapping, or null when
/// it is not one.
fn env_pairs(env: Option<&Value>) -> Value {
    match env.and_then(Value::as_object) {
        Some(entries) => Value::Array(
            entries
                .iter()
                .filter_map(|(key, value)| Some(json!([key, value.as_str()?])))
                .collect(),
        ),
        None => Value::Null,
    }
}

fn all_strings(value: &Value) -> Option<&Vec<Value>> {
    value
        .as_array()
        .filter(|items| items.iter().all(Value::is_string))
}

/// `_select_request`: the artifact as the `select` op reads it, with the
/// private arguments and environment in place of the redacted ones.
fn select_request(artifact: &Value) -> Option<Value> {
    let private = artifact
        .get("runtime_private_metadata")
        .and_then(Value::as_object);
    let metadata = artifact.get("metadata");
    let private_field = |key: &str| private.and_then(|private| private.get(key));
    let args = match private_field("mcp_args") {
        Some(args) => all_strings(args)?.clone(),
        None => artifact
            .get("args")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };
    let env = match private.filter(|private| private.contains_key("mcp_env")) {
        Some(private) => private.get("mcp_env"),
        None => metadata.and_then(|metadata| metadata.get("env")),
    };
    let saved_origin = private_field("managed_mcp_origin")
        .and_then(all_strings)
        .map_or(Value::Null, |origin| Value::Array(origin.clone()));
    let saved_guard_home = private_field("managed_guard_home")
        .filter(|home| home.is_string())
        .cloned()
        .unwrap_or(Value::Null);
    let text_of = |key: &str| artifact.get(key).cloned().unwrap_or(Value::Null);
    let flag = |key: &str| metadata.and_then(|metadata| metadata.get(key));
    Some(json!({
        "harness": text_of("harness"),
        "name": text_of("name"),
        "source_scope": text_of("source_scope"),
        "config_path": text_of("config_path"),
        "command": text_of("command"),
        "args": args,
        "transport": text_of("transport"),
        "env": env_pairs(env),
        "guard_managed_proxy": flag("guard_managed_proxy") == Some(&Value::Bool(true)),
        "enabled": flag("enabled") != Some(&Value::Bool(false)),
        "saved_origin": saved_origin,
        "saved_guard_home": saved_guard_home,
    }))
}

fn text(value: Option<&Value>) -> Step<String> {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(malformed)
}

/// `_selected_server` then the `proxy_args` op's server fields: the selected
/// server's own fields under the artifact's harness and name, its env pairs
/// collapsed as a dict assignment collapses them.
fn proxy_fields(artifact: &Value, found: &Value) -> Step<(String, Map<String, Value>)> {
    let name = text(artifact.get("name"))?;
    let args = found
        .get("args")
        .and_then(all_strings)
        .ok_or_else(malformed)?;
    let mut env: Vec<(String, String)> = Vec::new();
    for pair in found
        .get("env")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?
    {
        let (key, value) = match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(key), Value::String(value)]) => (key.clone(), value.clone()),
            _ => return Err(malformed()),
        };
        match env.iter_mut().find(|entry| entry.0 == key) {
            Some(entry) => entry.1 = value,
            None => env.push((key, value)),
        }
    }
    let fields = json!({
        "harness": text(artifact.get("harness"))?,
        "name": name,
        "source_scope": text(found.get("source_scope"))?,
        "config_path": text(found.get("config_path"))?,
        "command": text(found.get("command"))?,
        "args": args,
        "transport": text(found.get("transport"))?,
        "env": env.iter().map(|(key, value)| json!([key, value])).collect::<Vec<_>>(),
    });
    match fields {
        Value::Object(fields) => Ok((name, fields)),
        _ => Err(malformed()),
    }
}

/// `_kept`: each server artifact the `select` op answered, in detection
/// order, beside the server it found. `include_proxy` also recovers the
/// original servers behind Guard's own proxies, for observation only.
fn kept(artifacts: &[Value], include_proxy: bool) -> Step<Vec<(&Value, Value)>> {
    let mut chosen = Vec::new();
    let mut requests = Vec::new();
    for artifact in servers(artifacts) {
        if let Some(request) = select_request(artifact) {
            chosen.push(artifact);
            requests.push(request);
        }
    }
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let answer = harness_mcp_discovery::dispatch(&json!({
        "op": "select",
        "include_proxy": include_proxy,
        "artifacts": requests,
    }))
    .map_err(unavailable)?;
    let found = answer
        .get("servers")
        .and_then(Value::as_array)
        .filter(|found| found.len() == chosen.len())
        .ok_or_else(malformed)?;
    Ok(chosen
        .into_iter()
        .zip(found)
        .filter(|(_, found)| !found.is_null())
        .map(|(artifact, found)| (artifact, found.clone()))
        .collect())
}

/// `managed_stdio_servers` and `proxy_launcher_entry` under `proxy_command`:
/// each local stdio server Guard can wrap, in detection order, with the
/// entry that launches it behind the proxy.
pub(super) fn managed(ctx: &Ctx, artifacts: &[Value], proxy_command: &str) -> Step<Vec<Managed>> {
    let mut managed = Vec::new();
    for (artifact, found) in kept(artifacts, false)? {
        let (name, fields) = proxy_fields(artifact, &found)?;
        let entry = proxy_launch::entry(ctx, proxy_command, &fields)?;
        managed.push((
            name,
            text(found.get("source_scope"))?,
            text(found.get("config_path"))?,
            PyVal::Dict(entry),
        ));
    }
    Ok(managed)
}

/// `observable_stdio_servers_with_proxy`: the name, source scope and config
/// path of every server discovery observes, including the originals behind
/// Guard's proxies, which install never wraps again.
pub(super) fn observed(artifacts: &[Value]) -> Step<Vec<[String; 3]>> {
    kept(artifacts, true)?
        .into_iter()
        .map(|(artifact, found)| {
            let (name, _) = proxy_fields(artifact, &found)?;
            Ok([
                name,
                text(found.get("source_scope"))?,
                text(found.get("config_path"))?,
            ])
        })
        .collect()
}

/// `skipped_stdio_server_names`: the named servers Guard cannot manage
/// through its proxy, in detection order.
pub(super) fn skipped(artifacts: &[Value]) -> Step<Vec<String>> {
    let detected = servers(artifacts);
    if detected.is_empty() {
        return Ok(Vec::new());
    }
    let names = detected
        .iter()
        .map(|artifact| text(artifact.get("name")))
        .collect::<Step<Vec<_>>>()?;
    let entries: Vec<Value> = detected
        .iter()
        .zip(&names)
        .map(|(artifact, name)| {
            json!({"name": name, "request": select_request(artifact).unwrap_or(Value::Null)})
        })
        .collect();
    let mut fields = Map::new();
    fields.insert("entries".into(), Value::Array(entries));
    let answer = super::mcp_servers::skipped(&fields)?;
    answer
        .get("skipped")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?
        .iter()
        .map(|position| {
            position
                .as_u64()
                .and_then(|position| names.get(usize::try_from(position).ok()?))
                .cloned()
                .ok_or_else(malformed)
        })
        .collect()
}

/// The managed servers of the detected `artifacts` field, as the Codex
/// install plan reads them: `[{name, source_scope, config_path, entry}]`
/// with each entry as JSON text, then the managed and skipped names.
pub(super) fn wired(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    proxy_command: &str,
) -> Step<(Vec<Value>, Vec<String>, Vec<String>)> {
    let artifacts = fields
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let mut servers = Vec::new();
    let mut names = Vec::new();
    for (name, scope, path, entry) in managed(ctx, artifacts, proxy_command)? {
        servers.push(json!({
            "name": name,
            "source_scope": scope,
            "config_path": path,
            "entry": super::files::render(&entry)?,
        }));
        names.push(name);
    }
    Ok((servers, names, skipped(artifacts)?))
}

#[cfg(test)]
#[path = "tests_managed_servers.rs"]
mod tests;

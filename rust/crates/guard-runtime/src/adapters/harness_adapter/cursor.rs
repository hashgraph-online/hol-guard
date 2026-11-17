//! Cursor: the editor's global `~/.cursor/mcp.json`, its native hooks in
//! `~/.cursor/hooks.json` with the hook script they launch, and the
//! `cursor-agent` CLI.
//!
//! Python keeps what only the Guard process knows and answers it when an op
//! replies `{"reply": {...}}` with one key: `facts` (the attested Guard CLI,
//! the native hook bridge and the interpreters), `probe` (whether `cursor
//! agent --help` runs), `expand` (8.3 short names), `render` (Windows hook
//! command lines), `relaunch` (Guard's proxy argv) and `servers` (which
//! detected servers Guard manages, with their proxy entries). It merges each
//! answer into the request and asks again.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::copilot::sha12;
use super::files::{self, Doc};
use super::{
    common, cursor_editor, cursor_hooks, cursor_rebind, cursor_state, detection, path_answer,
    path_text, which, Ctx, Failure, Spec, Step,
};
use crate::pyjson::{self, PyVal};

pub(super) use super::cursor_ask::{Ask, Attestation, Facts};

pub(super) const HARNESS: &str = "cursor";
pub(super) const SCRIPT_NAME: &str = "hol-guard-cursor-hook.py";
pub(super) const EVENTS: [&str; 6] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "preToolUse",
    "afterShellExecution",
    "afterMCPExecution",
];
pub(super) const BLOCKING: [&str; 4] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "preToolUse",
];
pub(super) const BRIDGE_UNAVAILABLE: &str = "guard_cursor_native_bridge_unavailable";
const MALFORMED: &str = "Cursor hook config answer is malformed";
const SHIM_COMMANDS: [&str; 2] = ["guard-cursor-agent", "guard-cursor"];

pub(super) fn hooks_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".cursor").join("hooks.json")
}

pub(super) fn script_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".cursor").join("hooks").join(SCRIPT_NAME)
}

pub(super) fn managed_dir(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("managed").join(HARNESS)
}

pub(super) fn managed_script_path(ctx: &Ctx) -> PathBuf {
    managed_dir(ctx).join(SCRIPT_NAME)
}

pub(super) fn secret_path(ctx: &Ctx) -> PathBuf {
    ctx.guard_home
        .join("secrets")
        .join("cursor-hook-attestation.key")
}

/// `managed/cursor/{prefix}{sha256(str(target.resolve()))[:12]}.{kind}.json`.
pub(super) fn digest_path(ctx: &Ctx, target: &Path, prefix: &str, kind: &str) -> PathBuf {
    let digest = sha12(&path_text(&ctx.resolved(target)));
    managed_dir(ctx).join(format!("{prefix}{digest}.{kind}.json"))
}

pub(super) fn editor_target(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".cursor").join("mcp.json")
}

pub(super) fn editor_configs(ctx: &Ctx) -> Vec<PathBuf> {
    let mut paths = vec![editor_target(ctx)];
    if let Some(workspace) = &ctx.workspace {
        paths.push(workspace.join(".cursor").join("mcp.json"));
    }
    paths
}

pub(super) fn runtime(message: impl Into<String>) -> Failure {
    Failure::Runtime(message.into())
}

pub(super) fn malformed() -> Failure {
    runtime(MALFORMED)
}

/// `json.loads` of a file's UTF-8 text as an ordered object; `None` when it
/// is unreadable, not JSON or not an object.
pub(super) fn read_object(ctx: &Ctx, path: &Path) -> Option<Vec<(String, PyVal)>> {
    let text = std::fs::read_to_string(ctx.absolute(path)).ok()?;
    parse_object(&text)
}

pub(super) fn parse_object(text: &str) -> Option<Vec<(String, PyVal)>> {
    match pyjson::parse(text) {
        Ok(PyVal::Dict(entries)) => Some(entries),
        _ => None,
    }
}

pub(super) fn get<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

pub(super) fn wire(value: &PyVal) -> Step<Value> {
    value.to_json().ok_or(Failure::Invalid)
}

/// How the Cursor CLI launches: `cursor-agent`, or `cursor agent`.
pub(super) struct CliEntry {
    executable: String,
    subcommand: bool,
}

impl CliEntry {
    fn launch_argv(&self, args: &[Value]) -> Vec<Value> {
        let mut argv = vec![json!(self.executable)];
        let first = args.first().and_then(Value::as_str);
        if !self.subcommand && first == Some("agent") {
            argv.extend(args[1..].iter().cloned());
        } else {
            if self.subcommand && first != Some("agent") {
                argv.push(json!("agent"));
            }
            argv.extend(args.iter().cloned());
        }
        argv
    }
}

/// `resolve_cursor_cli_entry`.
pub(super) fn cli_entry(ask: &Ask) -> Step<Option<CliEntry>> {
    if let Some(executable) = which::which(ask.ctx, "cursor-agent") {
        return Ok(Some(CliEntry {
            executable,
            subcommand: false,
        }));
    }
    let Some(cursor) = which::which(ask.ctx, "cursor") else {
        return Ok(None);
    };
    match ask.fields.get("cursor_probe") {
        None => Err(Ask::reply("probe", json!(cursor))),
        Some(Value::Bool(true)) => Ok(Some(CliEntry {
            executable: cursor,
            subcommand: true,
        })),
        Some(Value::Bool(false)) => Ok(None),
        Some(_) => Err(Failure::Invalid),
    }
}

/// `cursor_cli_command_available`.
fn cli_available(ask: &Ask) -> Step<bool> {
    Ok(cli_entry(ask)?.is_some()
        || which::user_directory_command(ask.ctx, "cursor-agent", &ask.ctx.home, &[]).is_some())
}

fn shim_installed(ctx: &Ctx) -> bool {
    let bin = ctx.absolute(&ctx.guard_home.join("bin"));
    SHIM_COMMANDS.iter().any(|name| bin.join(name).exists())
}

/// Each captured file's bytes, as a prepare snapshot read them.
pub(super) type Captured = [(PathBuf, Option<Vec<u8>>)];

/// `captured_payload`: the object a config holds, `{}` for anything else.
fn captured_object(ctx: &Ctx, path: &Path, contents: Option<&Captured>) -> Vec<(String, PyVal)> {
    let Some(contents) = contents else {
        return read_object(ctx, path).unwrap_or_default();
    };
    contents
        .iter()
        .find(|(known, _)| known == path)
        .and_then(|(_, data)| data.as_deref())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(parse_object)
        .unwrap_or_default()
}

/// `_managed_mcp_origin`: where a server Guard moved into the global config
/// came from, as the editor state recorded it.
fn private_metadata(ctx: &Ctx, artifact: &Value) -> Value {
    let target = editor_target(ctx);
    let config = artifact["config_path"].as_str().unwrap_or_default();
    if artifact["source_scope"] != "global" || Path::new(config) != target {
        return Value::Null;
    }
    let state = std::fs::read_to_string(ctx.absolute(&digest_path(ctx, &target, "", "state")))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    let name = artifact["name"].as_str().unwrap_or_default();
    let mut origin = state["managed_origins"].get(name).cloned();
    if state.get("managed_origins").is_none() {
        if let Some(workspace) = state["workspace_dir"].as_str() {
            if Path::new(workspace).is_absolute() {
                let path = Path::new(workspace).join(".cursor").join("mcp.json");
                origin = Some(json!(["project", path_text(&path)]));
            }
        }
    }
    let valid = origin
        .as_ref()
        .and_then(Value::as_array)
        .is_some_and(|pair| {
            pair.len() == 2
                && pair[0] == "project"
                && pair[1]
                    .as_str()
                    .is_some_and(|path| Path::new(path).is_absolute())
        });
    if state["managed_config_path"].as_str() != Some(path_text(&target).as_str())
        || state["surface"] != "editor"
        || !valid
    {
        return Value::Null;
    }
    json!({
        "managed_mcp_origin": origin,
        "managed_guard_home": path_text(&ctx.guard_home),
    })
}

/// `detect`, reading captured contents when a prepare holds them.
pub(super) fn detect(spec: &Spec, ask: &Ask, contents: Option<&Captured>) -> Step<Value> {
    let ctx = ask.ctx;
    let mut configs = Vec::new();
    for path in editor_configs(ctx) {
        let payload = captured_object(ctx, &path, contents);
        if !payload.is_empty() {
            configs.push(json!({
                "path": path_text(&path),
                "payload": files::render(&PyVal::Dict(payload))?,
            }));
        }
    }
    let mut request = ctx.detection_request(HARNESS);
    request.insert("configs".into(), Value::Array(configs));
    let mut found =
        crate::cursor_detect::detect(&Value::Object(request)).map_err(|_| Failure::Invalid)?;
    if let Some(artifacts) = found["artifacts"].as_array_mut() {
        for artifact in artifacts {
            artifact["runtime_private_metadata"] = private_metadata(ctx, artifact);
        }
    }
    let hooks = hooks_path(ctx);
    let payload = captured_object(ctx, &hooks, contents);
    let nested = match get(&payload, "hooks") {
        Some(PyVal::Dict(nested)) => nested.clone(),
        _ => payload,
    };
    if let Some(command) = cursor_hooks::live_commands(ask, &nested)?
        .into_iter()
        .next()
    {
        found["found_paths"]
            .as_array_mut()
            .ok_or(Failure::Invalid)?
            .push(json!(path_text(&hooks)));
        found["artifacts"]
            .as_array_mut()
            .ok_or(Failure::Invalid)?
            .push(json!({
                "artifact_id": "cursor:global:managed-hooks",
                "name": "HOL Guard Cursor hooks",
                "harness": HARNESS,
                "artifact_type": "guard_hook",
                "source_scope": "global",
                "config_path": path_text(&hooks),
                "command": command.0,
                "args": [],
                "url": null,
                "transport": null,
                "publisher": null,
                "metadata": {},
            }));
    }
    let mut answer = detection(spec, Ok(found), cli_available(ask)?)?;
    answer["warnings"] = json!([]);
    answer["firewall"] = json!(true);
    Ok(answer)
}

fn launch_command(ask: &Ask) -> Step<Value> {
    let args = ask
        .fields
        .get("args")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let argv = match cli_entry(ask)? {
        Some(entry) => entry.launch_argv(args),
        None => std::iter::once(json!("cursor-agent"))
            .chain(args.iter().cloned())
            .collect(),
    };
    Ok(json!({ "argv": argv }))
}

/// How many servers `cursor-agent mcp list` printed, one bulleted line each.
fn reported_artifacts(stdout: &Value) -> Value {
    let Some(stdout) = stdout.as_str() else {
        return Value::Null;
    };
    if stdout.contains("No MCP servers configured") {
        return json!(0);
    }
    // `str.splitlines` boundaries, then `str.strip`.
    let breaks = |c: char| {
        matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    };
    let count = stdout
        .split(breaks)
        .filter(|line| {
            let line = line.trim_start();
            line.starts_with('-') || line.starts_with('\u{2022}') || line.starts_with('*')
        })
        .count();
    json!(count)
}

/// The surface an install or uninstall names.
fn surface(fields: &Map<String, Value>) -> Step<&str> {
    let surface = fields
        .get("surface")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    if matches!(surface, "editor" | "cli" | "all") {
        Ok(surface)
    } else {
        Err(Failure::Refusal(format!(
            "Unsupported Cursor surface: {surface}"
        )))
    }
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    let ask = Ask { ctx, fields };
    match op {
        "policy_path" => path_answer(
            &ctx.workspace
                .as_deref()
                .unwrap_or(&ctx.home)
                .join(".cursor")
                .join("mcp.json"),
        ),
        "surface" => Ok(json!({ "surface": surface(fields)? })),
        "resolved_executable" => {
            Ok(json!({ "path": cli_entry(&ask)?.map(|entry| entry.executable) }))
        }
        "detect" => detect(spec, &ask, None),
        "launch_command" => launch_command(&ask),
        "runtime_probe" => match fields.get("stdout") {
            None => Ok(json!({
                "argv": cli_entry(&ask)?.map(|entry| entry.launch_argv(&[json!("mcp"), json!("list")])),
            })),
            Some(stdout) => Ok(json!({ "reported_artifacts": reported_artifacts(stdout) })),
        },
        "cli_shim_installed" => Ok(json!({ "value": shim_installed(ctx) })),
        "cli_detected" => Ok(json!({ "value": cli_available(&ask)? || shim_installed(ctx) })),
        "cli_manifest" => cli_manifest(ctx, fields),
        "cli_uninstalled" => {
            let mut doc = Doc::default();
            doc.set("harness", files::text(HARNESS))
                .set("active", PyVal::Bool(false))
                .set("surface", files::text("cli"))
                .spread(&files::shim_manifest(fields)?);
            files::manifest_answer(doc)
        }
        "all_manifest" => cursor_editor::all_manifest(fields),
        "install" | "prepare_install" | "hooks_install" | "verify" | "uninstall" => {
            cursor_editor::dispatch(spec, op, &ask)
        }
        "hook_state" => {
            Ok(json!({ "state": files::render(&cursor_state::hook_state(&ask)?.value())? }))
        }
        "health" => Ok(json!({ "verified": cursor_state::health(&ask)? })),
        "rebind" => cursor_rebind::rebind(&ask),
        "frozen_hook_script" => Ok(json!({
            "accepted": super::cursor_files::live_script(ctx, Path::new(
                fields.get("script").and_then(Value::as_str).ok_or(Failure::Invalid)?,
            )),
        })),
        _ => common(spec, op, ctx),
    }
}

/// The CLI surface's manifest over the two shims and the shell profile.
fn cli_manifest(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let parsed = |key: &str| -> Step<Vec<(String, PyVal)>> {
        let raw = fields
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?;
        parse_object(raw).ok_or(Failure::Invalid)
    };
    let (agent, cursor, profile) = (
        parsed("agent_shim")?,
        parsed("cursor_shim")?,
        parsed("profile")?,
    );
    let bin = path_text(&ctx.guard_home.join("bin"));
    let mut notes = files::shim_notes(&agent);
    notes.push(files::text(
        "Use guard-cursor-agent for the standalone cursor-agent binary.",
    ));
    notes.push(files::text(
        "Use guard-cursor agent ... when launching through the Cursor app CLI.",
    ));
    notes.push(files::text(format!("Guard launcher shims live in {bin}.")));
    let truthy = |key: &str| get(&profile, key).is_some_and(PyVal::truthy);
    if truthy("changed") {
        notes.push(files::text(
            "Prepended the Guard launcher shim directory to your shell profile.",
        ));
    } else if truthy("restart_shell_required") {
        notes.push(files::text(
            "Restart your shell or open a new terminal so guard-cursor shims are on PATH.",
        ));
    } else if truthy("manual_path_required") {
        notes.push(files::text(format!(
            "Put {bin} first on your PATH so guard-cursor shims run."
        )));
    }
    let field =
        |shim: &[(String, PyVal)], key: &str| get(shim, key).cloned().ok_or(Failure::Invalid);
    let mut doc = Doc::default();
    doc.set("harness", files::text(HARNESS))
        .set("active", PyVal::Bool(true))
        .set("surface", files::text("cli"))
        .set("shim_path", field(&agent, "shim_path")?)
        .set("shim_dir", field(&agent, "shim_dir")?)
        .set("shim_command", field(&agent, "shim_command")?)
        .set(
            "shim_paths",
            PyVal::List(vec![
                field(&agent, "shim_path")?,
                field(&cursor, "shim_path")?,
            ]),
        )
        .set(
            "shim_commands",
            PyVal::List(
                SHIM_COMMANDS
                    .iter()
                    .map(|name| files::text(*name))
                    .collect(),
            ),
        )
        .set(
            "windows_shim_path",
            get(&agent, "windows_shim_path")
                .cloned()
                .unwrap_or(PyVal::Null),
        )
        .set("shell_profile", PyVal::Dict(profile))
        .set("notes", PyVal::List(notes));
    files::manifest_answer(doc)
}

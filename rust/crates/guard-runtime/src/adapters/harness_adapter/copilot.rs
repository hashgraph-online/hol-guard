//! Microsoft Copilot: the CLI's inline hooks in `~/.copilot/config.json`, the
//! VS Code workspace hook file, and the MCP configs Guard routes through its
//! proxy.
//!
//! Python keeps what runs in the Guard process: the bounded hook argv and the
//! hook script it stages, the isolated hook interpreter, the launcher
//! environment, Guard's proxy argv for each server, the shim and the runtime
//! probe subprocess. Install is two asks: `install_detection` answers the
//! detection Python derives the managed servers from, with a digest of what it
//! read and the proxy relaunches the plan needs, and `prepare_install` holds
//! the lifecycle locks, re-reads and refuses when the digest moved, and plans
//! the files. `uninstall` holds the same locks while it restores the MCP
//! configs and rewrites the hooks.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::files::{self, Object};
use super::{
    common, detection, path_answer, path_text, resolved_executable, Ctx, Failure, Spec, Step,
};
use super::{copilot_install, which};
use crate::copilot_detect::strip_jsonc;
use crate::pyjson::PyVal;

pub(super) const HARNESS: &str = "copilot";
pub(super) const HOOK_FILE: &str = "hol-guard-copilot.json";
const HOOK_TIMEOUT_SECONDS: u64 = 25;
pub(super) const MCP_KEYS: [&str; 2] = ["mcpServers", "servers"];

/// Each file an install read, with the bytes it held when it existed.
pub(super) type Captured = [(PathBuf, Option<Vec<u8>>)];
/// The workspace hook file's plan and the normalized file it edits.
pub(super) type WorkspacePlan = (HookPlan, Vec<(String, PyVal)>);
const UNANSWERED: &str = "Guard could not read which Copilot hooks it installed; the native Guard \
                          runtime did not answer. Run `hol-guard doctor copilot` and try again.";

pub(super) fn config_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".copilot").join("config.json")
}

pub(super) fn global_mcp_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".copilot").join("mcp-config.json")
}

pub(super) fn hook_path(ctx: &Ctx) -> Option<PathBuf> {
    let workspace = ctx.workspace.as_ref()?;
    Some(workspace.join(".github").join("hooks").join(HOOK_FILE))
}

pub(super) fn workspace_mcp_paths(ctx: &Ctx) -> Vec<PathBuf> {
    ctx.workspace.as_ref().map_or_else(Vec::new, |workspace| {
        vec![
            workspace.join(".mcp.json"),
            workspace.join(".vscode").join("mcp.json"),
        ]
    })
}

/// The MCP configs Guard rewrites: the workspace's, or the CLI's global one.
pub(super) fn target_mcp_paths(ctx: &Ctx) -> Vec<PathBuf> {
    let workspace = workspace_mcp_paths(ctx);
    if workspace.is_empty() {
        vec![global_mcp_path(ctx)]
    } else {
        workspace
    }
}

/// `os.path.normcase` of a path's text.
pub(super) fn normcase(path: &Path) -> String {
    let text = path_text(path);
    if cfg!(windows) {
        text.replace('/', "\\").to_lowercase()
    } else {
        text
    }
}

pub(super) fn sha12(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))[..12].to_owned()
}

pub(super) fn managed_dir(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("managed").join("copilot")
}

/// `{sha256(str(target.resolve()))[:12]}.{kind}.json` under Guard's home.
pub(super) fn digest_path(ctx: &Ctx, target: &Path, kind: &str) -> PathBuf {
    let digest = sha12(&path_text(&ctx.resolved(target)));
    managed_dir(ctx).join(format!("{digest}.{kind}.json"))
}

/// `"project"` for a path lexically inside the workspace.
pub(super) fn scope_for(ctx: &Ctx, path: &Path) -> &'static str {
    match &ctx.workspace {
        Some(workspace) if path.starts_with(workspace) => "project",
        _ => "global",
    }
}

/// The `.github/hooks/*.json` files of the workspace, sorted.
pub(super) fn hook_dir_files(ctx: &Ctx) -> Vec<PathBuf> {
    let Some(hook) = hook_path(ctx) else {
        return Vec::new();
    };
    let Some(dir) = hook.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(ctx.absolute(dir)) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| dir.join(entry.file_name()))
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "json") && ctx.absolute(path).is_file()
        })
        .collect();
    found.sort();
    found
}

/// `_parse_copilot_json_text`: JSON, then JSONC; `None` unless an object.
pub(super) fn parse_object(text: &str) -> Option<Object> {
    match Object::parse(text) {
        Some(parsed) => parsed.ok(),
        None => Object::parse(&strip_jsonc(text)).and_then(Result::ok),
    }
}

/// `_json_payload`: strict JSON, `{}` for anything that is not an object.
pub(super) fn strict_object(text: &str) -> Object {
    Object::parse(text).and_then(Result::ok).unwrap_or_default()
}

/// The detection sources in Python's order: the config, the global MCP
/// config, the workspace MCP configs and the `.github/hooks` listing.
pub(super) fn sources(ctx: &Ctx, hook_listing: &[PathBuf]) -> Vec<(PathBuf, &'static str)> {
    let mut sources = vec![(config_path(ctx), "config"), (global_mcp_path(ctx), "mcp")];
    sources.extend(
        workspace_mcp_paths(ctx)
            .into_iter()
            .map(|path| (path, "mcp")),
    );
    sources.extend(hook_listing.iter().cloned().map(|path| (path, "hooks")));
    sources
}

/// Run `copilot_detect` over `sources`, with captured contents when given,
/// and spell each found path the way the context did.
pub(super) fn detect_sources(
    spec: &Spec,
    ctx: &Ctx,
    sources: &[(PathBuf, &str)],
    contents: Option<&Captured>,
) -> Step<Value> {
    let anchored = |path: &Path| path_text(&ctx.absolute(path));
    let mut request = json!({
        "harness": HARNESS,
        "sources": sources.iter().map(|(path, kind)| json!({
            "path": anchored(path),
            "scope": scope_for(ctx, path),
            "kind": kind,
        })).collect::<Vec<_>>(),
    });
    if let Some(contents) = contents {
        let captured: Map<String, Value> = sources
            .iter()
            .map(|(path, _)| {
                let data = contents
                    .iter()
                    .find(|(known, _)| known == path)
                    .and_then(|(_, data)| data.as_deref());
                (
                    anchored(path),
                    data.map_or(Value::Null, |bytes| json!(hex::encode(bytes))),
                )
            })
            .collect();
        request["contents"] = Value::Object(captured);
    }
    let available = command_path(spec, ctx).is_some();
    let mut answer = detection(spec, crate::copilot_detect::detect(&request), available)?;
    let restore: Vec<(String, String)> = sources
        .iter()
        .map(|(path, _)| (anchored(path), path_text(path)))
        .filter(|(anchored, original)| anchored != original)
        .collect();
    if !restore.is_empty() {
        restore_value(&restore, &mut answer["config_paths"]);
        if let Some(artifacts) = answer["artifacts"].as_array_mut() {
            for artifact in artifacts {
                restore_value(&restore, &mut artifact["config_path"]);
                restore_value(&restore, &mut artifact["metadata"]);
            }
        }
    }
    answer["warnings"] = json!([]);
    Ok(answer)
}

/// `_restore_value`: every string naming an anchored source back to the
/// caller's spelling.
fn restore_value(restore: &[(String, String)], value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some((_, original)) = restore.iter().find(|(anchored, _)| anchored == text) {
                *text = original.clone();
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| restore_value(restore, item)),
        Value::Object(map) => map
            .values_mut()
            .for_each(|item| restore_value(restore, item)),
        _ => {}
    }
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    detect_sources(spec, ctx, &sources(ctx, &hook_dir_files(ctx)), None)
}

fn candidates(ctx: &Ctx) -> [PathBuf; 1] {
    [ctx.user_home
        .join(".local")
        .join("copilot-cli")
        .join("copilot")]
}

fn command_path(spec: &Spec, ctx: &Ctx) -> Option<String> {
    which::resolve_command(ctx, spec.executable, &candidates(ctx))
}

/// `launch_command`: the CLI reads the workspace `.mcp.json` only when told.
fn launch_command(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let executable = command_path(spec, ctx).unwrap_or_else(|| spec.executable.to_owned());
    let mut argv = vec![json!(executable)];
    if let Some(config) = workspace_mcp_paths(ctx).into_iter().find(|path| {
        path.file_name().is_some_and(|name| name == ".mcp.json") && ctx.absolute(path).is_file()
    }) {
        argv.push(json!("--additional-mcp-config"));
        argv.push(json!(format!("@{}", path_text(&config))));
    }
    argv.extend(
        fields
            .get("args")
            .and_then(Value::as_array)
            .ok_or(Failure::Invalid)?
            .iter()
            .cloned(),
    );
    Ok(json!({ "argv": argv }))
}

/// The `guard hook` arguments of the config and workspace hook commands.
fn hook_spec(ctx: &Ctx) -> Value {
    let mut cli_args = vec![
        "guard".to_owned(),
        "hook".to_owned(),
        "--guard-home".to_owned(),
        path_text(&ctx.guard_home),
        "--harness".to_owned(),
        HARNESS.to_owned(),
    ];
    if !ctx.default_home() {
        cli_args.extend(["--home".to_owned(), path_text(&ctx.home)]);
    }
    let workspace = ctx.workspace.as_ref().map(|workspace| {
        let mut args = cli_args.clone();
        args.extend(["--workspace".to_owned(), path_text(workspace)]);
        args
    });
    json!({
        "cli_args": cli_args,
        "workspace_cli_args": workspace,
        "timeout_seconds": HOOK_TIMEOUT_SECONDS,
    })
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(
            &ctx.workspace
                .as_deref()
                .unwrap_or(&ctx.home)
                .join(".mcp.json"),
        ),
        "resolved_executable" => resolved_executable(spec, ctx, &candidates(ctx)),
        "detect" => detect(spec, ctx),
        "launch_command" => launch_command(spec, ctx, fields),
        "runtime_probe" => Ok(json!({
            "argv": command_path(spec, ctx).map(|path| json!([path, "--help"])),
        })),
        "hook_spec" => Ok(hook_spec(ctx)),
        "install_detection" | "prepare_install" | "uninstall" | "finish_uninstall" => {
            copilot_install::dispatch(spec, op, ctx, fields)
        }
        _ => common(spec, op, ctx),
    }
}

/// Which user hook entries each managed event keeps, and the normalized
/// workspace hook file, as `copilot_hook_config` planned them.
pub(super) struct HookPlan {
    pub(super) bash: String,
    pub(super) powershell: String,
    kept: Vec<(String, Vec<PyVal>)>,
}

impl HookPlan {
    /// Keep the user's entries of each managed event and append Guard's.
    pub(super) fn install(&self, hooks: &mut Vec<(String, PyVal)>, entry: &PyVal) {
        let mut doc = files::Doc(std::mem::take(hooks));
        for (event, entries) in &self.kept {
            let mut list = entries.clone();
            list.push(entry.clone());
            doc.set(event, PyVal::List(list));
        }
        *hooks = doc.0;
    }

    /// Keep the user's entries of each managed event; drop events left empty.
    pub(super) fn uninstall(&self, hooks: &mut Vec<(String, PyVal)>) {
        for (event, entries) in &self.kept {
            if entries.is_empty() {
                hooks.retain(|(name, _)| name != event);
            } else {
                let mut doc = files::Doc(std::mem::take(hooks));
                doc.set(event, PyVal::List(entries.clone()));
                *hooks = doc.0;
            }
        }
    }
}

fn unanswered() -> Failure {
    Failure::Runtime(UNANSWERED.to_owned())
}

/// `inline_hooks_payload`: the config's hooks object, created when absent.
pub(super) fn inline_hooks(payload: &mut Object) -> Vec<(String, PyVal)> {
    match payload
        .entries
        .iter()
        .find(|(key, _)| key == "hooks")
        .map(|(_, value)| value)
    {
        Some(PyVal::Dict(hooks)) => hooks.clone(),
        _ => {
            payload.set("hooks", PyVal::Dict(Vec::new()));
            Vec::new()
        }
    }
}

fn wire(value: &PyVal) -> Step<Value> {
    value.to_json().ok_or_else(unanswered)
}

fn indices(value: &Value, size: usize) -> Step<Vec<usize>> {
    let mut previous: Option<usize> = None;
    let mut out = Vec::new();
    for item in value.as_array().ok_or_else(unanswered)? {
        let index = item.as_u64().ok_or_else(unanswered)? as usize;
        if index >= size || previous.is_some_and(|last| index <= last) {
            return Err(unanswered());
        }
        previous = Some(index);
        out.push(index);
    }
    Ok(out)
}

fn one_plan(answer: &Value, target: &[(String, PyVal)]) -> Step<HookPlan> {
    let text = |key: &str| {
        answer[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(unanswered)
    };
    let mut kept = Vec::new();
    for event in answer["events"].as_array().ok_or_else(unanswered)? {
        let name = event[0].as_str().ok_or_else(unanswered)?;
        let source = target
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.as_list())
            .unwrap_or(&[]);
        let chosen = indices(&event[1], source.len())?;
        kept.push((
            name.to_owned(),
            chosen.into_iter().map(|i| source[i].clone()).collect(),
        ));
    }
    Ok(HookPlan {
        bash: text("bash")?,
        powershell: text("powershell")?,
        kept,
    })
}

/// The workspace hook file as Guard rewrites it: `{"version", "hooks"}`.
fn normalized(payload: &Object, answer: &Value) -> Step<Vec<(String, PyVal)>> {
    let get = |key: &str| {
        payload
            .entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, v)| v)
    };
    let keep_version = answer["version"].as_bool().ok_or_else(unanswered)?;
    let version = if keep_version {
        get("version").cloned().ok_or_else(unanswered)?
    } else {
        PyVal::Int("1".into())
    };
    let hooks = match &answer["hooks"] {
        Value::Null => get("hooks")
            .and_then(PyVal::as_dict)
            .ok_or_else(unanswered)?
            .to_vec(),
        lists => indices(lists, payload.entries.len())?
            .into_iter()
            .map(|index| {
                let (key, value) = &payload.entries[index];
                match value {
                    PyVal::List(_) => Ok((key.clone(), value.clone())),
                    _ => Err(unanswered()),
                }
            })
            .collect::<Step<_>>()?,
    };
    Ok(vec![
        ("version".into(), version),
        ("hooks".into(), PyVal::Dict(hooks)),
    ])
}

/// Plan the config's inline hooks and, when given, the workspace hook file
/// in one `copilot_hook_config` call. The workspace answer is the plan with
/// the normalized file whose `hooks` it edits.
pub(super) fn plan_hooks(
    fields: &Map<String, Value>,
    config: (&[(String, PyVal)], &Value),
    workspace: Option<(&Object, &Value)>,
) -> Step<(HookPlan, Option<WorkspacePlan>)> {
    let mut jobs = vec![json!({
        "parts": config.1,
        "hooks": wire(&PyVal::Dict(config.0.to_vec()))?,
    })];
    if let Some((payload, parts)) = workspace {
        jobs.push(json!({
            "parts": parts,
            "payload": wire(&PyVal::Dict(payload.entries.clone()))?,
            "keys": payload.entries.iter().map(|(key, _)| key).collect::<Vec<_>>(),
        }));
    }
    let request = json!({
        "op": "plan",
        "interpreter": fields.get("interpreter").cloned().unwrap_or(Value::Null),
        "script": fields.get("script").cloned().unwrap_or(Value::Null),
        "jobs": jobs,
    });
    let answer = crate::copilot_hook_config::dispatch(&request).map_err(|_| unanswered())?;
    let plans = answer["jobs"].as_array().ok_or_else(unanswered)?;
    let config_plan = one_plan(plans.first().ok_or_else(unanswered)?, config.0)?;
    let Some((payload, _)) = workspace else {
        return Ok((config_plan, None));
    };
    let answer = plans.get(1).ok_or_else(unanswered)?;
    let normalized = normalized(payload, answer)?;
    let hooks = normalized[1].1.as_dict().unwrap_or(&[]).to_vec();
    Ok((config_plan, Some((one_plan(answer, &hooks)?, normalized))))
}

/// Guard's hook entry for one hooks object.
pub(super) fn hook_entry(ctx: &Ctx, plan: &HookPlan, env: &PyVal) -> PyVal {
    let mut doc = files::Doc::default();
    doc.set("type", files::text("command"))
        .set("bash", files::text(plan.bash.clone()))
        .set("powershell", files::text(plan.powershell.clone()))
        .set("cwd", files::path_value(&ctx.guard_home))
        .set("timeoutSec", PyVal::Int("30".into()));
    if env.truthy() {
        doc.set("env", env.clone());
    }
    doc.value()
}

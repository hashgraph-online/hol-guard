//! z.ai ZCode: Guard's hook groups in both hook surfaces under
//! `~/.zcode/cli` — `config.json`, which the Desktop app reads, and the npm
//! CLI's `setting.json` once that CLI has migrated — with a backup and an
//! install state under the Guard home. `zcode_hook_settings` renders each
//! surface; this module picks the paths, snapshots the files and builds the
//! plan.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, adapter_result, path_value, render, text, Change, Doc};
use super::kimi::{expand_user, guard_hook_args, hook_command, utf8};
use super::{common, detection, path_answer, path_text, which, Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

const CLI_DIR: [&str; 2] = [".zcode", "cli"];
const CONFIG_FILE: &str = "config.json";
/// The npm CLI's file-config and hook surface; the Desktop app reads config.json.
const FILE_CONFIG: &str = "setting.json";
const V2_CONFIG: [&str; 3] = [".zcode", "v2", "config.json"];
const PLUGIN_CACHE: [&str; 2] = ["plugins", "cache"];
const PLUGIN_MARKETPLACES: [&str; 2] = ["plugins", "marketplaces"];
const HOOK_INTERNAL_TIMEOUT_SECONDS: i64 = 25;
const PRETOOL_TIMEOUT_SECONDS: i64 = 30;
const PROMPT_TIMEOUT_SECONDS: i64 = 30;
const BUNDLE_IDENTIFIER: &str = "dev.zcode.app";
/// z.ai process identity hints, read only as a presence signal.
pub(super) const ENV_HINTS: [&str; 8] = [
    "ZCODE_BASE_URL",
    "ZCODE_APP_VERSION",
    "ZCODE_ENV",
    "ZCODE_RUNTIME_ENV",
    "ZCODE_PROCESS_LABEL",
    "ZCODE_RG_BINARY",
    "ZAI_OAUTH_ORIGIN",
    "ZAI_OAUTH_CLIENT_ID",
];
/// Claude Code tool matchers ZCode surfaces; `mcp__.*` keeps MCP calls in view.
const PRETOOL_MATCHERS: [&str; 18] = [
    "Bash",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Grep",
    "WebFetch",
    "WebSearch",
    "mcp__.*",
    "run_terminal_command",
    "run_command",
    "read_file",
    "write_file",
    "search_replace",
    "multi_edit",
    "grep",
    "web_fetch",
    "web_search",
];
const MALFORMED: &str = "ZCode hook settings answer is malformed";
const SIGNAL_ONLY_WARNING: &str = "ZCode runtime was detected through process environment \
                                   signals, but no ~/.zcode/cli/config.json or plugin cache was \
                                   found. Run ZCode once so it can initialize its local config \
                                   before Guard install.";

fn joined(root: &Path, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

/// `ZCODE_HOME`, expanded and resolved, or the context home.
fn zcode_home(ctx: &Ctx) -> PathBuf {
    match ctx.env("ZCODE_HOME").filter(|value| !value.is_empty()) {
        Some(value) => ctx.resolved(&expand_user(ctx, value)),
        None => ctx.home.clone(),
    }
}

fn cli_root(ctx: &Ctx) -> PathBuf {
    joined(&zcode_home(ctx), &CLI_DIR)
}

fn config_path(ctx: &Ctx) -> PathBuf {
    cli_root(ctx).join(CONFIG_FILE)
}

fn file_config_path(ctx: &Ctx) -> PathBuf {
    cli_root(ctx).join(FILE_CONFIG)
}

fn project_cli_root(ctx: &Ctx) -> Option<PathBuf> {
    ctx.workspace
        .as_ref()
        .map(|workspace| joined(workspace, &CLI_DIR))
}

/// `__CFBundleIdentifier` or any z.ai runtime hint in the caller's process.
fn runtime_signal(ctx: &Ctx) -> bool {
    ctx.env("__CFBundleIdentifier")
        .is_some_and(|bundle| bundle.trim() == BUNDLE_IDENTIFIER)
        || ENV_HINTS
            .iter()
            .any(|name| ctx.env(name).is_some_and(|value| !value.is_empty()))
}

fn scope(ctx: &Ctx, path: &Path) -> &'static str {
    match &ctx.workspace {
        Some(workspace) if path.starts_with(workspace) => "project",
        _ => "global",
    }
}

fn roots(ctx: &Ctx, parts: &[&str]) -> Vec<Value> {
    let mut roots = vec![(joined(&cli_root(ctx), parts), "global")];
    if let Some(project) = project_cli_root(ctx) {
        roots.push((joined(&project, parts), "project"));
    }
    roots
        .into_iter()
        .map(|(path, scope)| json!({"path": path_text(&ctx.absolute(&path)), "scope": scope}))
        .collect()
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let mut configs = vec![config_path(ctx), file_config_path(ctx)];
    if let Some(project) = project_cli_root(ctx) {
        configs.push(project.join(CONFIG_FILE));
    }
    let request = json!({
        "harness": spec.harness,
        "configs": configs
            .iter()
            .map(|path| json!({"path": path_text(&ctx.absolute(path)), "scope": scope(ctx, path)}))
            .collect::<Vec<_>>(),
        "v2_config": path_text(&ctx.absolute(&joined(&zcode_home(ctx), &V2_CONFIG))),
        "plugin_roots": roots(ctx, &PLUGIN_CACHE),
        "marketplace_roots": roots(ctx, &PLUGIN_MARKETPLACES),
    });
    let signal = runtime_signal(ctx);
    let available = which::command_available(ctx, spec.executable, Some(&ctx.home), &[]);
    let mut answer = detection(spec, crate::zcode_detect::detect(&request), available)?;
    let found = answer["config_paths"]
        .as_array()
        .is_some_and(|paths| !paths.is_empty());
    let warnings = if signal && !found {
        vec![SIGNAL_ONLY_WARNING]
    } else {
        Vec::new()
    };
    answer["warnings"] = json!(warnings);
    if signal {
        answer["installed"] = json!(true);
    }
    Ok(answer)
}

/// `guard_home/managed/zcode/{config.json.backup, install.state.json}`, each checked.
fn state_paths(ctx: &Ctx) -> Step<(PathBuf, PathBuf)> {
    let state_dir = ctx.guard_home.join("managed").join("zcode");
    let backup = state_dir.join("config.json.backup");
    let state = state_dir.join("install.state.json");
    files::within_root(ctx, &ctx.guard_home, &state_dir, "ZCode state")?;
    files::within_root(ctx, &state_dir, &backup, "ZCode backup")?;
    files::within_root(ctx, &state_dir, &state, "ZCode state")?;
    Ok((backup, state))
}

/// `_json_payload`: the recorded state, `{}` when it is unreadable or not an object.
fn json_payload(bytes: Option<&[u8]>) -> Map<String, Value> {
    match bytes.map(serde_json::from_slice::<Value>) {
        Some(Ok(Value::Object(state))) => state,
        _ => Map::new(),
    }
}

fn read_state(ctx: &Ctx, state: &Path) -> Map<String, Value> {
    let path = ctx.absolute(state);
    if !path.is_file() {
        return Map::new();
    }
    json_payload(std::fs::read(path).ok().as_deref())
}

/// One `zcode_hook_settings` request for a surface.
fn surface_request(
    op: &str,
    text: Option<&str>,
    path: &Path,
    state: &Map<String, Value>,
) -> Map<String, Value> {
    let field = |key: &str| state.get(key).cloned().unwrap_or(Value::Null);
    let mut request = Map::new();
    request.insert("op".into(), json!(op));
    request.insert("text".into(), json!(text));
    request.insert("path".into(), json!(path_text(path)));
    request.insert("history".into(), field("hooks_enabled_before"));
    request.insert("managed_config_path".into(), field("managed_config_path"));
    request
}

fn hook_settings(request: Map<String, Value>, keys: &[&str]) -> Step<Map<String, Value>> {
    let answer = crate::zcode_hook_surface::dispatch(&Value::Object(request))
        .map_err(|error| Failure::Refusal(format!("ZCode hook settings plan failed: {error}")))?;
    match answer {
        Value::Object(answer)
            if (answer.len() == keys.len() && keys.iter().all(|key| answer.contains_key(*key)))
                || (answer.len() == 1 && answer.contains_key("refusal")) =>
        {
            Ok(answer)
        }
        _ => Err(Failure::Refusal(MALFORMED.to_owned())),
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `install_hook_surface`: the surface's new text and its pre-install
/// `hooks.enabled` record.
fn install_surface(
    ctx: &Ctx,
    text: Option<&str>,
    path: &Path,
    state: &Map<String, Value>,
    command: &str,
) -> Step<(String, PyVal)> {
    let mut request = surface_request("install", text, path, state);
    request.insert("desktop".into(), json!(path == config_path(ctx)));
    request.insert("matchers".into(), json!(PRETOOL_MATCHERS));
    request.insert("command".into(), json!(command));
    request.insert(
        "timeouts".into(),
        json!({"PreToolUse": PRETOOL_TIMEOUT_SECONDS, "UserPromptSubmit": PROMPT_TIMEOUT_SECONDS}),
    );
    let answer = hook_settings(request, &["text", "enabled"])?;
    match answer.get("refusal").and_then(Value::as_str) {
        Some("not_object") => {
            return Err(Failure::Refusal(format!(
                "ZCode config must be a JSON object: {}",
                file_name(path)
            )))
        }
        Some("hooks_disabled") => {
            return Err(Failure::Refusal(format!(
                "ZCode user hooks are disabled in {}; explicitly enable them before installing \
                 Guard.",
                file_name(path)
            )))
        }
        _ => {}
    }
    let malformed = || Failure::Refusal(MALFORMED.to_owned());
    let (Some(Value::String(rendered)), Some(Value::String(enabled))) =
        (answer.get("text"), answer.get("enabled"))
    else {
        return Err(malformed());
    };
    let enabled = crate::pyjson::parse(enabled).map_err(|_| malformed())?;
    let well_formed = enabled.as_dict().is_some_and(|fields| {
        fields.len() == 2
            && matches!(enabled.get("present"), Some(PyVal::Bool(_)))
            && enabled.get("value").is_some()
    });
    if !well_formed {
        return Err(malformed());
    }
    Ok((rendered.clone(), enabled))
}

struct Surface {
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
    mode: u32,
}

fn mode_or(ctx: &Ctx, path: &Path, default: u32) -> u32 {
    if ctx.absolute(path).is_file() {
        files::mode(ctx, path).unwrap_or(default)
    } else {
        default
    }
}

fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let (backup, state) = state_paths(ctx)?;
    let backup_before = files::snapshot(ctx, &backup)?;
    let state_before = files::snapshot(ctx, &state)?;
    let previous = if state_before.is_some() {
        read_state(ctx, &state)
    } else {
        Map::new()
    };
    let command = hook_command(ctx, fields)?;
    let (config, file_config) = (config_path(ctx), file_config_path(ctx));
    let mut surfaces = Vec::new();
    let mut history = Doc::default();
    for path in [&config, &file_config] {
        files::within_root(ctx, &zcode_home(ctx), path, "ZCode")?;
        let present = ctx.absolute(path).is_file();
        if !present && *path != config {
            // An absent setting.json means the npm CLI has not migrated yet;
            // its own migration copies Guard's config.json hooks over.
            continue;
        }
        let before = files::snapshot(ctx, path)?;
        let current = match (&before, present) {
            (Some(bytes), true) => Some(utf8(bytes.clone(), "ZCode config")?),
            _ => None,
        };
        let (rendered, enabled) =
            install_surface(ctx, current.as_deref(), path, &previous, &command)?;
        history.set(&path_text(path), enabled);
        surfaces.push(Surface {
            path: path.clone(),
            before,
            after: rendered.into_bytes(),
            mode: mode_or(ctx, path, 0o644),
        });
    }
    let config_key = path_text(&config);
    let file_config_key = path_text(&file_config);
    let recorded = |key: &str| history.0.iter().any(|(name, _)| name == key);
    if !recorded(&file_config_key) {
        // The CLI migration copies config.json, Guard's opt-in included, into
        // setting.json; remember the pre-install value for it too.
        if let Some((_, enabled)) = history.0.iter().find(|(name, _)| *name == config_key) {
            let enabled = enabled.clone();
            history.set(&file_config_key, enabled);
        }
    }
    let config_before = surfaces
        .iter()
        .find(|surface| surface.path == config)
        .and_then(|surface| surface.before.clone());
    let state_mode = if state_before.is_some() {
        mode_or(ctx, &state, 0o644)
    } else {
        0o644
    };
    let backup_mode = if backup_before.is_some() {
        mode_or(ctx, &backup, 0o644)
    } else {
        mode_or(ctx, &config, 0o644)
    };
    let mut record = Doc::default();
    record
        .set("managed_config_path", path_value(&config))
        .set("managed_file_config_path", path_value(&file_config))
        .set("hooks_enabled_before", history.value());
    let state_after = format!("{}\n", render(&record.value())?).into_bytes();
    let backup_after = backup_before.clone().or(config_before);
    let mut changes = vec![Change::at(
        ctx,
        &backup,
        backup_before,
        backup_after,
        backup_mode,
    )];
    let wrote_cli = surfaces.iter().any(|surface| surface.path == file_config);
    for surface in surfaces {
        changes.push(Change::at(
            ctx,
            &surface.path,
            surface.before,
            Some(surface.after),
            surface.mode,
        ));
    }
    changes.push(Change::at(
        ctx,
        &state,
        state_before,
        Some(state_after),
        state_mode,
    ));
    let mut notes: Vec<&str> = if wrote_cli {
        vec![
            "Guard hook entries added to ~/.zcode/cli/config.json (Desktop) and \
             ~/.zcode/cli/setting.json (CLI)",
        ]
    } else {
        vec![
            "Guard hook entries added to ~/.zcode/cli/config.json (Desktop)",
            "The CLI's ~/.zcode/cli/setting.json does not exist yet; its own settings migration \
             carries the hooks over",
        ]
    };
    notes.extend([
        "hooks.enabled was set to true on every written surface; ZCode only runs hooks after \
         that opt-in",
        "User mcp, plugins, and any pre-existing hooks were preserved",
        "Legacy flat hook groups were migrated into hooks.events for current ZCode",
        "Hook entries carry a statusMessage label rendered by ZCode's Hooks settings UI",
    ]);
    let notes = notes.into_iter().map(text).collect();
    let manifest = adapter_result(spec.harness, true, &config, &shim, notes);
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": render(&manifest.value())?,
    }))
}

/// Both hook surfaces, installs from before the dual-surface layout
/// included, planned before anything changes.
fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let (_, state) = state_paths(ctx)?;
    let recorded = read_state(ctx, &state);
    let mut writes = Vec::new();
    for path in [file_config_path(ctx), config_path(ctx)] {
        let absolute = ctx.absolute(&path);
        if !absolute.is_file() {
            continue;
        }
        files::within_root(ctx, &zcode_home(ctx), &path, "ZCode")?;
        let bytes = std::fs::read(&absolute).map_err(|error| Failure::Os(error.to_string()))?;
        let current = utf8(bytes, "ZCode config")?;
        let request = surface_request("uninstall", Some(&current), &path, &recorded);
        let answer = hook_settings(request, &["text"])?;
        let rendered = match answer.get("text") {
            _ if answer.contains_key("refusal") => return Err(Failure::Refusal(MALFORMED.into())),
            Some(Value::String(rendered)) => rendered,
            Some(Value::Null) => continue,
            _ => return Err(Failure::Refusal(MALFORMED.into())),
        };
        // The authorized parent, resolved, and the final name not followed.
        let parent = absolute.parent().unwrap_or(&absolute);
        let parent =
            std::fs::canonicalize(parent).map_err(|error| Failure::Os(error.to_string()))?;
        let target = parent.join(absolute.file_name().unwrap_or_default());
        writes.push(json!({"path": path_text(&target), "text": rendered, "no_follow": true}));
    }
    let deletes: Vec<String> = ctx
        .absolute(&state)
        .is_file()
        .then(|| path_text(&state))
        .into_iter()
        .collect();
    let notes = [
        "Guard-managed hook entries removed from ~/.zcode/cli/config.json and the CLI file-config",
        "User mcp, plugins, and any pre-existing hooks were preserved",
    ];
    Ok(json!({"writes": writes, "deletes": deletes, "finish": {"notes": notes}}))
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => {
            let project = project_cli_root(ctx)
                .map(|root| root.join(CONFIG_FILE))
                .filter(|project| ctx.absolute(project).is_file());
            path_answer(&project.unwrap_or_else(|| config_path(ctx)))
        }
        "detect" => detect(spec, ctx),
        "hook_spec" => Ok(json!({
            "cli_args": guard_hook_args(ctx, spec.harness),
            "timeout_seconds": HOOK_INTERNAL_TIMEOUT_SECONDS,
        })),
        "prepare_install" => prepare_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(ctx),
        "finish_uninstall" => files::finished(spec.harness, &config_path(ctx), fields),
        _ => common(spec, op, ctx),
    }
}

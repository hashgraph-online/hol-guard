//! Kimi Code: Guard's hooks block in `~/.kimi-code/config.toml`.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, adapter_result, manifest_answer, text, Change};
use super::{common, detection, path_answer, path_text, which, Ctx, Failure, Spec, Step};

const KIMI_DIR: &str = ".kimi-code";
const CONFIG_FILE: &str = "config.toml";
const HOOK_TIMEOUT_SECONDS: u64 = 25;
const INSTALLED_NOTE: &str = "Guard hook entries added to ~/.kimi-code/config.toml";
const REMOVED_NOTE: &str = "Guard hook entries removed from ~/.kimi-code/config.toml";

/// `os.path.expanduser` against the caller's home.
pub(crate) fn expand_user(ctx: &Ctx, value: &str) -> PathBuf {
    if value == "~" {
        return ctx.user_home.clone();
    }
    match value
        .strip_prefix("~/")
        .or_else(|| ctx.windows.then(|| value.strip_prefix("~\\")).flatten())
    {
        Some(rest) => ctx.user_home.join(rest),
        None => PathBuf::from(value),
    }
}

/// `KIMI_CODE_HOME`, expanded and resolved, or the context home.
fn kimi_home(ctx: &Ctx) -> PathBuf {
    match ctx.env("KIMI_CODE_HOME").filter(|value| !value.is_empty()) {
        Some(value) => ctx.resolved(&expand_user(ctx, value)),
        None => ctx.home.clone(),
    }
}

fn managed_config(ctx: &Ctx) -> PathBuf {
    kimi_home(ctx).join(KIMI_DIR).join(CONFIG_FILE)
}

/// The `guard hook` arguments every hook-managing adapter starts from.
pub(crate) fn guard_hook_args(ctx: &Ctx, harness: &str) -> Vec<String> {
    let mut args = vec![
        "guard".to_owned(),
        "hook".to_owned(),
        "--guard-home".to_owned(),
        path_text(&ctx.guard_home),
        "--harness".to_owned(),
        harness.to_owned(),
    ];
    if !ctx.default_home() {
        args.extend(["--home".to_owned(), path_text(&ctx.home)]);
    }
    if let Some(workspace) = &ctx.workspace {
        args.extend(["--workspace".to_owned(), path_text(workspace)]);
    }
    args
}

/// The bounded hook argv Python built, joined for the target shell.
pub(crate) fn hook_command(ctx: &Ctx, fields: &Map<String, Value>) -> Step<String> {
    let argv = fields
        .get("hook_argv")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|part| part.as_str().ok_or(Failure::Invalid))
        .collect::<Step<Vec<&str>>>()?;
    if argv.is_empty() {
        return Err(Failure::Invalid);
    }
    Ok(if ctx.windows {
        crate::copilot_hook_config::list2cmdline(&argv)
    } else {
        crate::copilot_hook_config::shlex_join(&argv)
    })
}

/// UTF-8 text, as `bytes.decode("utf-8")` and `read_text` accept it.
pub(crate) fn utf8(bytes: Vec<u8>, label: &str) -> Step<String> {
    String::from_utf8(bytes)
        .map_err(|_| Failure::Refusal(format!("{label} is not valid UTF-8 text.")))
}

fn hook_config(request: Value) -> Step<String> {
    crate::kimi_hook_config::dispatch(&request)
        .map_err(|_| Failure::Invalid)?
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}

fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let config = managed_config(ctx);
    files::within_root(ctx, &ctx.home, &config, "Kimi Code")?;
    let command = hook_command(ctx, fields)?;
    let before = files::snapshot(ctx, &config)?;
    let existing = match &before {
        Some(bytes) => utf8(bytes.clone(), "Kimi Code config")?,
        None => String::new(),
    };
    let updated = hook_config(json!({"op": "install", "text": existing, "hook_command": command}))?;
    let mode = match before {
        Some(_) => files::mode(ctx, &config).ok_or(Failure::Invalid)?,
        None => 0o644,
    };
    let change = Change::at(ctx, &config, before, Some(updated.into_bytes()), mode);
    let manifest = adapter_result(
        spec.harness,
        true,
        &config,
        &shim,
        vec![text(INSTALLED_NOTE)],
    );
    Ok(json!({
        "files": [change.wire()],
        "manifest": files::render(&manifest.value())?,
    }))
}

fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let config = managed_config(ctx);
    let absolute = ctx.absolute(&config);
    let mut writes = Vec::new();
    if absolute.is_file() {
        files::within_root(ctx, &ctx.home, &config, "Kimi Code")?;
        let existing = std::fs::read(&absolute).map_err(|error| Failure::Os(error.to_string()))?;
        let existing = utf8(existing, "Kimi Code config")?;
        let cleaned = hook_config(json!({"op": "uninstall", "text": existing}))?;
        writes.push(json!({"path": path_text(&config), "text": cleaned, "mode": null}));
    }
    Ok(json!({"writes": writes, "deletes": [], "finish": {}}))
}

fn finish_uninstall(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let config = managed_config(ctx);
    manifest_answer(adapter_result(
        spec.harness,
        false,
        &config,
        &shim,
        vec![text(REMOVED_NOTE)],
    ))
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(&match &ctx.workspace {
            Some(workspace) => workspace.join(KIMI_DIR).join(CONFIG_FILE),
            None => managed_config(ctx),
        }),
        "detect" => {
            let mut request = ctx.detection_request(spec.harness);
            request.insert("home".into(), json!(path_text(&kimi_home(ctx))));
            let found = crate::kimi_detect::detect(&Value::Object(request));
            // Kimi Code's installer puts the CLI in ~/.kimi-code/bin, outside the config home.
            let installer: &Path = &ctx.home.join(KIMI_DIR).join("bin");
            let available = which::command_available(
                ctx,
                spec.executable,
                Some(&ctx.home),
                &[installer.into()],
            );
            detection(spec, found, available)
        }
        "hook_spec" => Ok(json!({
            "cli_args": guard_hook_args(ctx, spec.harness),
            "timeout_seconds": HOOK_TIMEOUT_SECONDS,
        })),
        "prepare_install" => prepare_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(ctx),
        "finish_uninstall" => finish_uninstall(spec, ctx, fields),
        _ => common(spec, op, ctx),
    }
}

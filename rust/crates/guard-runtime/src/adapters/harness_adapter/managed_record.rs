//! `managed_install_record`: what `_apply_managed_install_owned` did after
//! each adapter install or uninstall, ported from `cli/install_commands.py`.
//!
//! The caller holds installation ownership and has run every adapter. For
//! each harness it binds the install proof (installs only),
//! writes the managed-install row and reads it back; then it installs the
//! agent safety guidance after an install, or removes it once no harness is
//! active after an uninstall.
//!
//! The caller calls `managed_install_record` once per harness, right after
//! that harness's adapter ran, so a later failure keeps the rows already
//! written, and `managed_install_guidance` once at the end when any row was
//! recorded. Fields: `command` (`install` or `uninstall`), `target` (the
//! canonical harness), `manifest` (its `json.dumps` text), `workspace` (text or null), `now` and
//! `source` (`GuardStore.guard_source`). The row answers with `manifest_json`
//! undecoded.

use std::path::Path;
use std::time::Duration;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use super::files::render;
use super::proof::bind;
use super::{Ctx, Failure, Step};
use crate::guard_store_op::MAX_BUSY_TIMEOUT_MS;
use crate::hook_env_stamp::set_member;
use crate::hook_evidence_store_gate::hold_storage_gate;
use crate::hook_evidence_store_timeout::sqlite_timeout_ms;
use crate::local_store_read::STORE_FILE_NAME;
use crate::opencode_plugin_render::dumps;
use crate::pyjson::{self, PyVal};

const GUIDANCE_SCHEMA: &str = "agent-safety-guidance.v1";

/// The Guard home, private to its owner, as the Python store creates it before
/// its first write: a home no store has opened yet has no directory.
fn ensure_guard_home(guard_home: &Path) -> Step<()> {
    if guard_home.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(guard_home)
        .map_err(|error| Failure::Os(error.to_string()))
}

/// One store call under the shared storage gate, as `_native_store_call`
/// makes it.
pub(super) fn store_call(ctx: &Ctx, source: &str, method: &str, args: Value) -> Step<Value> {
    let Value::Object(args) = args else {
        return Err(Failure::Invalid);
    };
    ensure_guard_home(&ctx.guard_home)?;
    let timeout_ms = sqlite_timeout_ms();
    let _gate = hold_storage_gate(&ctx.guard_home, Duration::from_millis(timeout_ms.into()))
        .map_err(|error| Failure::Os(error.to_string()))?;
    crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: format!("managed-install-{method}"),
        store_path: ctx
            .guard_home
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: ctx.guard_home.to_string_lossy().into_owned(),
        method: method.to_owned(),
        source: crate::guard_store_approval_write::oauth_source(source),
        busy_timeout_ms: u64::from(timeout_ms).min(MAX_BUSY_TIMEOUT_MS),
        args,
    })
    .map(|(payload, _)| payload)
    .map_err(|error| Failure::Runtime(error.message()))
}

/// `assert_transition_mutation_allowed`: no install writes while a runtime
/// transition is pending.
pub(super) fn transition_pending(guard_home: &Path) -> bool {
    let home = std::fs::canonicalize(guard_home).unwrap_or_else(|_| guard_home.to_path_buf());
    let path = home.join("managed").join("runtime-transition.json");
    path.symlink_metadata().is_ok()
}

/// `install_agent_safety_guidance` / `uninstall_agent_safety_guidance`.
fn guidance(ctx: &Ctx, op: &str, action: &str) -> Step<Value> {
    let home = std::path::absolute(&ctx.home).unwrap_or_else(|_| ctx.home.clone());
    let request = json!({
        "schema": GUIDANCE_SCHEMA,
        "op": op,
        "home_dir": home.to_string_lossy(),
    });
    let bytes = crate::agent_safety_guidance::run_command(request.to_string().as_bytes())
        .map_err(Failure::Runtime)?;
    let answer: Value = serde_json::from_slice(&bytes).map_err(|_| Failure::Invalid)?;
    match answer.get("failure") {
        None | Some(Value::Null) => Ok(answer),
        Some(Value::String(message)) => Err(Failure::Runtime(message.clone())),
        Some(_) => Err(Failure::Runtime(format!(
            "Guard could not {action} agent safety guidance"
        ))),
    }
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

/// `managed_install_record`: one harness's proof, row write and read-back.
pub(crate) fn record(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let active = active(fields)?;
    let source = text(fields, "source")?;
    let harness = text(fields, "target")?;
    let workspace = match fields.get("workspace") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(path)) => Value::from(path.as_str()),
        Some(_) => return Err(Failure::Invalid),
    };
    // The manifest arrives as `json.dumps(manifest)` text so the row keeps
    // the key order Python wrote; a parsed `Map` would sort it.
    let manifest_text = text(fields, "manifest")?;
    let mut ordered = pyjson::parse(manifest_text).map_err(|_| Failure::Invalid)?;
    let PyVal::Dict(entries) = &mut ordered else {
        return Err(Failure::Invalid);
    };
    if active {
        let manifest: Map<String, Value> =
            serde_json::from_str(manifest_text).map_err(|_| Failure::Invalid)?;
        // `{**manifest, "protection_artifact_proof": json.loads(proof)}`.
        let proof =
            pyjson::parse(&render(&bind(ctx, &manifest)?)?).map_err(|_| Failure::Invalid)?;
        set_member(entries, "protection_artifact_proof", proof);
    }
    if transition_pending(&ctx.guard_home) {
        return Err(Failure::Refusal("pending_transition".to_owned()));
    }
    let manifest_json = dumps(&ordered);
    store_call(
        ctx,
        source,
        "set_managed_install",
        json!({
            "harness": harness,
            "active": active,
            "workspace": workspace,
            "manifest_json": manifest_json,
            "now": text(fields, "now")?,
        }),
    )?;
    let row = store_call(
        ctx,
        source,
        "get_managed_install",
        json!({ "harness": harness }),
    )?;
    Ok(json!({ "row": row }))
}

/// `managed_install_guidance`: after an install that recorded a harness the
/// guidance is installed; after an uninstall it is removed once no harness
/// is active. Answers `guidance` when it changed, else `null`.
pub(crate) fn guidance_after(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let source = text(fields, "source")?;
    if active(fields)? {
        return Ok(json!({ "guidance": guidance(ctx, "install", "install")? }));
    }
    let all = store_call(ctx, source, "list_managed_installs", json!({}))?;
    let any_active = all
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row["active"] == json!(true)));
    if any_active {
        return Ok(json!({ "guidance": null }));
    }
    Ok(json!({ "guidance": guidance(ctx, "uninstall", "remove")? }))
}

fn active(fields: &Map<String, Value>) -> Step<bool> {
    match text(fields, "command")? {
        "install" => Ok(true),
        "uninstall" => Ok(false),
        _ => Err(Failure::Invalid),
    }
}

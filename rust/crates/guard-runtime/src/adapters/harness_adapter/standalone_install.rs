//! The installs that stand alone, each under its own native installation
//! transaction: one harness's launcher shim, the shell profile's PATH block
//! and Cursor's native hooks.
//!
//! The request carries what `managed_install` does (`client_pid`, `thread`,
//! `transition`, `interpreter` and `shell_profile`, plus `actor`,
//! `process_identity` and `deadline_ms`, or the `owner` token of a transaction
//! the caller already holds). Each op answers `{ok: true, manifest}` after
//! journaling every write under the owner, or `{ok: false, failure}`.
//!
//! - `shim_install` takes `harness`, `launcher_name` and `display_name`.
//! - `profile_install` takes nothing more. It answers the profile's manifest
//!   without taking any lock when the profile needs no change.
//! - `cursor_hooks_install` publishes Cursor's hooks-only plan, then requires
//!   the hooks Cursor now reads to be Guard's.

use serde_json::{json, Map, Value};

use super::managed_install::{finish, within};
use super::managed_install_target::{published, stopped, Owned, INVALID};
use super::{answer, describe, route, shim_profile, shims_apply, Ctx};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SHIM_KEYS: [&str; 3] = ["harness", "launcher_name", "display_name"];

/// The fields `apply_guard_shims` takes from the caller's process.
fn process_fields(fields: &Map<String, Value>) -> Map<String, Value> {
    let mut asked = Map::new();
    for key in ["interpreter", "transition"] {
        asked.insert(key.into(), fields.get(key).cloned().unwrap_or(Value::Null));
    }
    asked
}

/// `install_guard_shim`: the launcher of one harness, published and journaled.
pub(super) fn shim(ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let target = ctx.guard_home.join("bin");
    finish(within(ctx, fields, &target, |owner| {
        let mut entry = Map::new();
        for key in SHIM_KEYS {
            entry.insert(key.into(), fields.get(key).cloned().unwrap_or(Value::Null));
        }
        let mut asked = process_fields(fields);
        asked.insert("shims".into(), json!([entry]));
        let applied = shims_apply::apply_guard_shims(ctx, &asked).map_err(stopped)?;
        published(owner, applied.get("publish"))?;
        let manifest = applied
            .get("shims")
            .and_then(Value::as_array)
            .and_then(|manifests| manifests.first())
            .and_then(Value::as_str)
            .ok_or(INVALID)?;
        Ok(json!({ "ok": true, "manifest": manifest }))
    }))
}

/// `ensure_guard_shim_path_in_shell_profile`: the PATH block of the user's
/// shell profile.
pub(super) fn profile(ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let Some(Value::Object(shell)) = fields.get("shell_profile") else {
        return Err(ERR_INVALID);
    };
    let prepared = match shim_profile::prepare(ctx, shell) {
        Ok(prepared) => prepared,
        Err(failure) => return answer(Err(failure)),
    };
    let nothing_to_write = prepared
        .get("files")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    if nothing_to_write {
        return Ok(json!({ "ok": true, "manifest": prepared.get("manifest") }));
    }
    let target = ctx.guard_home.join("bin");
    finish(within(ctx, fields, &target, |owner| {
        let mut asked = process_fields(fields);
        asked.insert("shims".into(), json!([]));
        asked.insert("profile".into(), Value::Object(shell.clone()));
        let applied = shims_apply::apply_guard_shims(ctx, &asked).map_err(stopped)?;
        published(owner, applied.get("publish"))?;
        Ok(json!({ "ok": true, "manifest": applied.get("profile") }))
    }))
}

/// `install_cursor_hooks`: Cursor's hooks and the script they run.
pub(super) fn cursor_hooks(ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let spec = describe::spec("cursor").ok_or(ERR_INVALID)?;
    let target = ctx.guard_home.join("managed");
    let done: Owned<Value> = within(ctx, fields, &target, |owner| {
        let mut plan = Map::new();
        plan.insert("plan_op".into(), json!("hooks_install"));
        plan.insert("removals".into(), json!(true));
        plan.insert(
            "transition".into(),
            fields.get("transition").cloned().unwrap_or(Value::Null),
        );
        let applied = shims_apply::apply_plan(spec, ctx, &plan).map_err(stopped)?;
        // The plan also retires the project-local hooks an older install wrote.
        published(owner, applied.get("publish"))?;
        route(spec, "verify", ctx, &Map::new()).map_err(stopped)?;
        let manifest = applied
            .get("manifest")
            .and_then(Value::as_str)
            .ok_or(INVALID)?;
        Ok(json!({ "ok": true, "manifest": manifest }))
    });
    finish(done)
}

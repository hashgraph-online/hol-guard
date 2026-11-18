//! `managed_install`, `adapter_install` and `adapter_uninstall`: harness
//! installs and uninstalls done under one native installation transaction.
//!
//! What `apply_managed_install` and `NativeHarnessAdapter.install` chained
//! from Python: take the Guard home's lifecycle and installation locks (or run
//! as the owner Python already holds, named by its `owner` token), refuse
//! while a runtime transition is pending, install or remove each target,
//! write its managed-install row, and install or remove the agent safety
//! guidance. The owner journals every mutation itself.
//!
//! Every request carries `client_pid` and `thread` (the caller's process and
//! thread), `transition` (`package_roots` and `budget`) and the facts only the
//! caller's process knows (see `managed_install_target`). A request without an
//! `owner` also carries `actor`, `process_identity` and `deadline_ms`.
//!
//! `managed_install` takes `command` (`install` or `uninstall`), `targets`
//! (each `{harness, surface?, manifest?}`; a `manifest` is one Python already
//! produced, for the adapters it still runs), `workspace`, `now` and `source`,
//! and answers `{ok: true, rows, guidance}` with every recorded row and the
//! guidance the command changed. `adapter_install` and `adapter_uninstall`
//! answer `{ok: true, manifest}` for the request's `harness`. A failure answers
//! `{ok: false, failure}` in the shape the owned ops use.

use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::describe::{self, Install};
use super::managed_install_target::{install, stopped, uninstall, Owned, INVALID};
use super::managed_record::{guidance_after, record, transition_pending};
use super::{answer, managed_update, update_bounded, Ctx, Spec};
use crate::runner_authority_op::KindResult;
use crate::transition_files::{
    with_owned, with_registered, Budget, OwnedFailure, OwnedSpec, Owner,
};

/// The longest a request may wait for the locks, as the owned ops cap it.
const MAX_WAIT: Duration = Duration::from_secs(600);

fn number(fields: &Map<String, Value>, key: &str) -> Owned<u64> {
    fields.get(key).and_then(Value::as_u64).ok_or(INVALID)
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Owned<&'a str> {
    fields.get(key).and_then(Value::as_str).ok_or(INVALID)
}

/// Run `work` as the owner of the Guard home's mutations: the one Python
/// holds when the request names it, else a new one over `target`.
pub(super) fn within<T>(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    target: &Path,
    work: impl FnOnce(&mut Owner) -> Owned<T>,
) -> Owned<T> {
    let pid = u32::try_from(number(fields, "client_pid")?).map_err(|_| INVALID)?;
    let thread = number(fields, "thread")?;
    let budget = Budget::parse(
        fields
            .get("transition")
            .and_then(|found| found.get("budget")),
    )
    .map_err(|_| INVALID)?;
    if let Some(token) = fields.get("owner").and_then(Value::as_str) {
        return with_registered(token, pid, thread, |owner| {
            if transition_pending(&ctx.guard_home) {
                return Err(OwnedFailure::Transition("pending_transition"));
            }
            work(owner)
        });
    }
    let wait = Duration::from_millis(number(fields, "deadline_ms")?).min(MAX_WAIT);
    let spec = OwnedSpec {
        guard_home: &ctx.guard_home,
        target,
        actor: text(fields, "actor")?,
        process_identity: text(fields, "process_identity")?,
        pid,
        thread,
        deadline: Instant::now() + wait,
        // The lifecycle lock of the Guard home itself, as `config_path.parent`.
        lock_dirs: vec![ctx.guard_home.clone()],
        check_pending: true,
        recover: false,
    };
    with_owned(&spec, &budget, work)
}

fn finish(done: Owned<Value>) -> KindResult {
    Ok(match done {
        Ok(answer) => answer,
        Err(failure) => failure.to_json(),
    })
}

fn surface(target: &Map<String, Value>) -> Owned<Option<&str>> {
    match target.get("surface") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(surface)) => Ok(Some(surface.as_str())),
        Some(_) => Err(INVALID),
    }
}

/// The fields `managed_install_record` takes for one target's manifest.
fn record_fields(
    fields: &Map<String, Value>,
    command: &str,
    harness: &str,
    manifest: &str,
) -> Owned<Map<String, Value>> {
    let mut record = Map::new();
    record.insert("command".into(), json!(command));
    record.insert("target".into(), json!(harness));
    record.insert("manifest".into(), json!(manifest));
    record.insert(
        "workspace".into(),
        fields.get("workspace").cloned().unwrap_or(Value::Null),
    );
    record.insert("now".into(), json!(text(fields, "now")?));
    record.insert("source".into(), json!(text(fields, "source")?));
    Ok(record)
}

/// `_apply_managed_install_owned`: each target's adapter, then its row, and
/// the guidance once any row was written. A later failure keeps the rows
/// already written.
pub(super) fn run(ctx: &Ctx, fields: &Map<String, Value>, owner: &mut Owner) -> Owned<Value> {
    let command = text(fields, "command")?;
    let active = match command {
        "install" => true,
        "uninstall" => false,
        _ => return Err(INVALID),
    };
    let targets = fields
        .get("targets")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    let mut rows: Vec<Value> = Vec::new();
    for target in targets {
        let target = target.as_object().ok_or(INVALID)?;
        let harness = text(target, "harness")?;
        let spec = describe::spec(harness).ok_or(INVALID)?;
        let surface = surface(target)?;
        let manifest = match target.get("manifest").and_then(Value::as_str) {
            Some(prepared) => prepared.to_owned(),
            None if active => install(spec, ctx, fields, owner, surface)?,
            None => uninstall(spec, ctx, fields, owner, surface)?,
        };
        let recorded =
            record(ctx, &record_fields(fields, command, harness, &manifest)?).map_err(stopped)?;
        if let Some(row) = recorded.get("row").filter(|row| row.is_object()) {
            rows.push(row.clone());
        }
    }
    let mut guidance = Value::Null;
    if !rows.is_empty() {
        let mut asked = Map::new();
        asked.insert("command".into(), json!(command));
        asked.insert("source".into(), json!(text(fields, "source")?));
        let answer = guidance_after(ctx, &asked).map_err(stopped)?;
        guidance = answer.get("guidance").cloned().unwrap_or(Value::Null);
    }
    Ok(json!({ "ok": true, "rows": rows, "guidance": guidance }))
}

/// `managed_install`: the whole install or uninstall of `targets`.
pub(super) fn managed(ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let target = ctx.guard_home.join("managed");
    finish(within(ctx, fields, &target, |owner| {
        run(ctx, fields, owner)
    }))
}

/// `adapter_install` and `adapter_uninstall`: one harness, for a caller that
/// runs its own transaction around several steps.
pub(super) fn adapter(op: &str, spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> KindResult {
    let target = ctx.guard_home.join("bin");
    let installing = op == "adapter_install";
    if installing && spec.install == Install::Delegated {
        return finish(Err(INVALID));
    }
    let done = surface(fields).and_then(|surface| {
        within(ctx, fields, &target, |owner| {
            let manifest = if installing {
                install(spec, ctx, fields, owner, surface)?
            } else {
                uninstall(spec, ctx, fields, owner, surface)?
            };
            Ok(json!({ "ok": true, "manifest": manifest }))
        })
    });
    finish(done)
}

/// The ops that install, repair or record a managed install, or `None` for
/// another op.
pub(super) fn route(op: &str, ctx: &Ctx, fields: &Map<String, Value>) -> Option<KindResult> {
    Some(match op {
        "managed_install" => managed(ctx, fields),
        "managed_update" => managed_update::dispatch(ctx, fields),
        "managed_install_record" => answer(record(ctx, fields)),
        "managed_install_guidance" => answer(guidance_after(ctx, fields)),
        "bounded_hook_scripts" => answer(update_bounded::scripts(ctx)),
        "remove_bounded_hook_script" => answer(update_bounded::remove(ctx, fields)),
        _ => return None,
    })
}

//! Recovery and commit of an authenticated Codex publication record, and the
//! `transition_files` ops that reach the record.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{decode, recovery};
use super::publication::{self, path_present, Call};
use super::publication_baseline;
use super::publication_files;
use super::publication_io::{
    encode, require_unchanged_for_rollback, restore_private, rollback_identity,
};
use super::publication_receipt;
use super::{Budget, Fault, Step};
use crate::codex_hook_key;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

fn field<'a>(payload: &'a Map<String, Value>, key: &str) -> &'a Value {
    payload.get(key).unwrap_or(&Value::Null)
}

fn bytes(payload: &Map<String, Value>, key: &str) -> Step<Option<Vec<u8>>> {
    decode(payload.get(key))
}

fn config_of(payload: &Map<String, Value>) -> Step<PathBuf> {
    field(payload, "config_path")
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| recovery("record_invalid"))
}

/// `_require_recorded_config_identity`: the config is still the recorded
/// predecessor (before commit) or the recorded published inode.
fn require_config_identity(
    call: &Call<'_>,
    payload: &Map<String, Value>,
    config: &Path,
) -> Step<()> {
    let Some(before_identity) = payload.get("before_config_identity") else {
        return Err(recovery("config_identity_missing"));
    };
    let current = rollback_identity(config)?;
    let value = call.snapshot(config)?;
    if rollback_identity(config)? != current {
        return Err(recovery("generation_changed"));
    }
    let encoded = current.unwrap_or(Value::Null);
    let uncommitted = field(payload, "phase").as_str() != Some("committed")
        || payload.contains_key("repair_plan");
    if uncommitted && &encoded == before_identity && value == bytes(payload, "before_config")? {
        return Ok(());
    }
    if payload
        .get("after_config_identity")
        .is_some_and(|after| after == &encoded)
        && value == bytes(payload, "after_config")?
    {
        return Ok(());
    }
    Err(recovery("generation_changed"))
}

type Change = (PathBuf, Option<Vec<u8>>, Option<Vec<u8>>);

fn changes(home: &Path, payload: &Map<String, Value>, config: &Path) -> Step<Vec<Change>> {
    let slot = field(payload, "config_path").as_str().unwrap_or_default();
    let (manifest, receipt) = Call::targets(home, slot);
    let mut changes = vec![
        (
            config.to_path_buf(),
            bytes(payload, "before_config")?,
            bytes(payload, "after_config")?,
        ),
        (
            manifest,
            bytes(payload, "before_manifest")?,
            bytes(payload, "after_manifest")?,
        ),
    ];
    match (payload.get("before_receipt"), payload.get("after_receipt")) {
        (None, None) => {}
        (Some(before), Some(after)) => {
            changes.push((receipt, decode(Some(before))?, decode(Some(after))?));
        }
        _ => return Err(recovery("record_invalid")),
    }
    Ok(changes)
}

/// `recover_hook_publication`: the idempotent inverse, checked across every
/// file before any is touched. Answers whether files were restored.
pub(super) fn recover(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    if !path_present(&Call::record_path(&home)) {
        return Ok(json!(false));
    }
    let payload = call.load(&home, false)?;
    if payload.contains_key("publication_inverse") {
        return Err(recovery("explicit_inverse_pending"));
    }
    let config = config_of(&payload)?;
    if field(&payload, "phase").as_str() == Some("config_conflict") {
        retire_conflict(call, &home, &payload, &config)?;
        return Ok(json!(false));
    }
    require_config_identity(call, &payload, &config)?;
    let changes = changes(&home, &payload, &config)?;
    // A foreign edit or newer generation of either file must survive, even
    // when the other file still matches this transaction.
    let committed = field(&payload, "phase").as_str() == Some("committed");
    for (target, before, after) in &changes {
        let current = call.snapshot(target)?;
        if &current != after && (committed || &current != before) {
            return Err(recovery("generation_changed"));
        }
    }
    if committed {
        remove_record(&home)?;
        return Ok(json!(false));
    }
    // Authority participants first: an interrupted recovery that already
    // replaced the config leaves an unknown inode for explicit recovery.
    for (target, before, _) in changes[1..].iter().chain(&changes[..1]) {
        if target == &config {
            require_config_identity(call, &payload, &config)?;
        }
        if &call.snapshot(target)? != before {
            restore_private(target, before.as_deref(), &mut call.events)?;
        }
    }
    for (target, before, _) in &changes {
        if &call.snapshot(target)? != before {
            return Err(recovery("readback_failed"));
        }
    }
    remove_record(&home)?;
    if payload.get("key_created").and_then(Value::as_bool) == Some(true) {
        let home_text = home.to_string_lossy();
        if let Some(reason) = codex_hook_key::answer("key_remove_if_unused", &home_text)
            .as_ref()
            .and_then(|answer| answer.get("error"))
            .and_then(Value::as_str)
        {
            return Err(Fault::Integrity(
                reason.to_owned(),
                "The private Codex hook authentication key is not usable; repair the Codex \
                 installation."
                    .to_owned(),
            ));
        }
    }
    Ok(json!(true))
}

/// A `config_conflict` record names a publication a foreign writer overtook:
/// the config is theirs, so the inverse is refused for good. Left in place it
/// refuses every later install, so recovery retires it when nothing else is
/// unresolved: no repair or explicit inverse is pending and Guard's own
/// authority files still hold this transaction's before or after bytes.
/// No file is touched; the next install republishes over the foreign config.
fn retire_conflict(
    call: &Call<'_>,
    home: &Path,
    payload: &Map<String, Value>,
    config: &Path,
) -> Step<()> {
    if payload.contains_key("repair_plan") {
        return Err(recovery("config_conflict"));
    }
    for (target, before, after) in changes(home, payload, config)?.iter().skip(1) {
        let current = call.snapshot(target)?;
        if &current != before && &current != after {
            return Err(recovery("config_conflict"));
        }
    }
    remove_record(home)
}

/// `commit_hook_publication`, after authenticated native hook readback.
fn commit(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let payload = call.load(&home, false)?;
    if payload.contains_key("publication_inverse") {
        return Err(recovery("explicit_inverse_pending"));
    }
    if payload.contains_key("repair_plan") {
        return Err(recovery("repair_requires_native_verification"));
    }
    let config = config_of(&payload)?;
    let canonical = call.canonical(&config)?;
    let (manifest, receipt) = Call::targets(&home, &canonical);
    if call.snapshot(&config)? != bytes(&payload, "after_config")?
        || call.snapshot(&manifest)? != bytes(&payload, "after_manifest")?
    {
        return Err(recovery("generation_changed"));
    }
    if payload.contains_key("after_receipt")
        && call.snapshot(&receipt)? != bytes(&payload, "after_receipt")?
    {
        return Err(recovery("generation_changed"));
    }
    commit_record(call, &home, payload)
}

/// The record half of `_commit_verified_hook_repair_publication`: the caller
/// checked the live authorization and timing; the sealed proof must match.
fn commit_repair(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let mut payload = call.load(&home, false)?;
    let observation = field(call.args, "observation").clone();
    if !observation.is_object()
        || !super::publication_proof::ordered(call, &observation)
        || !Call::proof_matches(&home, &payload, &observation)?
    {
        return Err(recovery("repair_native_verification_invalid"));
    }
    payload.insert("native_verification".to_owned(), observation);
    commit_record(call, &home, payload)
}

/// `_commit_record`: the commit is durable before the caller's cleanup
/// (`publication_remove`), so a crash between them keeps the candidate rather
/// than applying the predecessor inverse.
fn commit_record(call: &mut Call<'_>, home: &Path, mut payload: Map<String, Value>) -> Step<Value> {
    payload.insert("phase".to_owned(), json!("committed"));
    require_config_identity(call, &payload, &config_of(&payload)?)?;
    call.store(home, &payload)?;
    Ok(Value::Null)
}

/// `_remove_record`.
fn remove_record(home: &Path) -> Step<()> {
    let path = Call::record_path(home);
    if fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(recovery("record_invalid"));
    }
    fs::remove_file(&path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

fn answer(op: &str, call: &mut Call<'_>) -> Step<Value> {
    match op {
        "publication_snapshot" => encode(call.snapshot(&call.path("path")?)?.as_deref()),
        "publication_identity" => {
            Ok(rollback_identity(&call.path("path")?)?.unwrap_or(Value::Null))
        }
        "publication_pending" => Ok(json!(path_present(&Call::record_path(&call.home()?)))),
        "publication_load" => {
            let home = call.home()?;
            let conflict = call
                .args
                .get("live_config_conflict")
                .and_then(Value::as_bool);
            Ok(Value::Object(call.load(&home, conflict.unwrap_or(false))?))
        }
        "publication_rollback_check" => {
            let original = decode(call.args.get("original"))?;
            let written =
                decode(call.args.get("written"))?.ok_or(Fault::Transition("files_invalid"))?;
            require_unchanged_for_rollback(
                &call.path("path")?,
                original.as_deref(),
                &written,
                field(call.args, "original_identity"),
                field(call.args, "written_identity"),
            )
            .map(|()| Value::Null)
        }
        "publication_write" => publication_files::write(call),
        "publication_restore" => publication_files::restore(call),
        "publication_remove_manifest" => publication_files::remove_manifest(call),
        "publication_lean_sessions" => super::publication_lean::lean_sessions(call),
        "publication_short_replies" => super::publication_short_replies::short_replies(call),
        "publication_baseline" => publication_baseline::load(call),
        "publication_receipt_load" => publication_receipt::load(call),
        "publication_receipt_build" => publication_receipt::build(call),
        "publication_generation" => super::publication_generation::generation(call),
        "publication_generation_before" => super::publication_generation::snapshot(call),
        "publication_target" => super::publication_target::target(call),
        "publication_abort" => super::publication_abort::abort(call),
        "publication_repair_plan" => super::publication_repair_plan::plan(call),
        "publication_repair_prepare" => super::publication_repair_prepare::prepare(call),
        "publication_repair_request_plan" => super::publication_repair_request::plan(call),
        "publication_merge_dependency" => super::merge_dependency::merge(call),
        "publication_observe" => super::publication_observe::observe(call),
        "publication_repair_files" => super::publication_repair_files::files(call),
        "publication_inverse_dependencies" => super::publication_repair_files::inverse(call),
        "publication_inverse_prior" => super::publication_inverse_plan::prior_op(call),
        "publication_inverse_plan" => super::publication_inverse_plan::plan_op(call),
        "publication_inverse_journal" => super::publication_inverse_plan::journal_op(call),
        "publication_inverse_check" => super::publication_inverse_plan::check_op(call),
        "publication_inverse_prepare" => super::publication_inverse_prepare::prepare(call),
        "publication_inverse_verify" => super::publication_inverse_pinned::verify(call),
        "publication_inverse_pinned" => super::publication_inverse_pinned::pinned(call),
        "publication_inverse_bind" => super::publication_inverse_pinned::bind(call),
        "publication_inverse_record" => super::publication_inverse_publish::record_op(call),
        "publication_inverse_restore" => super::publication_inverse_publish::restore_op(call),
        "publication_request_create" => super::publication_request::create_op(call),
        "publication_request_read" => super::publication_request::read_op(call),
        "publication_prepare_request" => super::publication_prepare_request::prepare_op(call),
        "publication_request_policy" => super::publication_request_policy::policy_op(call),
        "publication_inspect_runtime" => super::publication_inspect_runtime::inspect_op(call),
        "publication_pin_executable" => super::publication_pin_executable::pin_op(call),
        "publication_runtime_compare" => super::publication_runtime_compare::compare_op(call),
        "publication_inverse_proof" => super::publication_proof::inverse(call),
        "publication_coordinate" => super::publication_coordinate::coordinate(call),
        "publication_deadline" => super::publication_authorize::deadline(call),
        "publication_artifact_generation" => {
            super::publication_artifact_generation::generation_op(call)
        }
        "publication_inverse_register" => super::publication_inverse_registry::register_op(call),
        "publication_authorize" => super::publication_authorize::plan(call),
        "publication_repair_claim" => super::repair_claims::claim(call),
        "publication_repair_claim_check" => super::repair_claims::check(call),
        "publication_repair_publish" => super::repair_claims::publish(call),
        "publication_remove" => remove_record(&call.home()?).map(|()| Value::Null),
        "publication_prepare" => publication::prepare(call),
        "publication_assert_repair" => publication::assert_repair(call),
        "publication_conflict" => publication::mark_conflict(call),
        "publication_config" => publication::record_config(call),
        "publication_recover" => recover(call),
        "publication_commit" => commit(call),
        "publication_commit_repair" => commit_repair(call),
        _ => Err(Fault::Transition("files_invalid")),
    }
}

/// One publication-record op: its value and the writes it journaled, or the
/// fault with the writes that already happened.
pub(super) fn dispatch(op: &str, args: &Map<String, Value>, budget: &Budget) -> KindResult {
    if !op.starts_with("publication_") {
        return Err(ERR_INVALID);
    }
    let mut call = Call {
        args,
        budget,
        events: Vec::new(),
    };
    Ok(match answer(op, &mut call) {
        Ok(value) => json!({ "ok": true, "events": call.events, "value": value }),
        Err(fault) => json!({ "error": fault.to_json(), "events": call.events }),
    })
}

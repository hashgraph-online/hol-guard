//! The Codex hook files `codex_hook_integrity` publishes: private atomic
//! writes, snapshot restores and the explicit manifest removal.

use std::fs;

use serde_json::Value;

use super::inspect::decode;
use super::output::{managed_remove, managed_write};
use super::publication::Call;
use super::publication_io::{restore_private, rollback_identity, write_private};
use super::{Fault, Step};

fn mode(call: &Call<'_>) -> Step<u32> {
    call.args
        .get("mode")
        .and_then(Value::as_u64)
        .and_then(|mode| u32::try_from(mode).ok())
        .filter(|mode| *mode <= 0o777)
        .ok_or(Fault::Transition("files_invalid"))
}

/// `atomic_write_bytes`: answers the published file's rollback identity.
pub(super) fn write(call: &mut Call<'_>) -> Step<Value> {
    let path = call.path("path")?;
    let payload = decode(call.args.get("payload"))?.ok_or(Fault::Transition("files_invalid"))?;
    if call.args.get("private").and_then(Value::as_bool) == Some(true) {
        write_private(&path, &payload, &mut call.events)?;
    } else {
        call.events
            .push(managed_write(&path, &payload, mode(call)?)?);
    }
    Ok(rollback_identity(&path)?.unwrap_or(Value::Null))
}

/// `restore_private_file`.
pub(super) fn restore(call: &mut Call<'_>) -> Step<Value> {
    let path = call.path("path")?;
    let payload = decode(call.args.get("payload"))?;
    restore_private(&path, payload.as_deref(), &mut call.events)?;
    Ok(Value::Null)
}

/// `_remove_hook_manifest_owned`: the retained authority goes before the live
/// manifest, so a crash cannot leave a receipt behind a removed manifest.
pub(super) fn remove_manifest(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.canonical(&call.path("config")?)?;
    let (manifest, receipt) = Call::targets(&home, &config);
    let symlink = |path: &std::path::Path| {
        fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
    };
    if symlink(&manifest) || symlink(&receipt) {
        return Err(Fault::Integrity(
            "codex_hook_manifest_not_regular".to_owned(),
            "Guard refused to remove a symlink in place of the Codex hook manifest.".to_owned(),
        ));
    }
    for (path, kind) in [
        (receipt, "remove_authority_receipt"),
        (manifest, "remove_manifest"),
    ] {
        if path.exists() {
            call.events.push(managed_remove(&path, kind)?);
        }
    }
    Ok(Value::Null)
}

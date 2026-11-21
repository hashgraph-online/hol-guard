//! The journal writes and restores of an explicit Codex publication inverse,
//! ported from `PendingCodexPublicationInverse._write_record` and the restore
//! loop of `publish_codex_publication_inverse`.
//!
//! The caller still checks its exact local authorization and every planned
//! generation before each op. These ops re-check the journal they replace,
//! write it or one restored target, and answer the identity they published,
//! so a later comparison can tell the file it wrote from one written after.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{decode, sha256_hex};
use super::publication::{Call, MAX_RECORD};
use super::publication_io::{read_private, rollback_identity, write_private};
use super::{compare, Ask, Fault, Step};

const JOURNAL_CHANGED: Fault = Fault::Transition("publication_inverse_journal_changed");
const GENERATION_CHANGED: Fault = Fault::Transition("publication_inverse_generation_changed");
const TOO_LARGE: Fault = Fault::Transition("publication_inverse_record_too_large");
const JOURNAL_MISSING: Fault = Fault::Transition("publication_inverse_journal_missing");

/// `_journal_bytes`: the record's raw bytes, read through a private parent.
fn journal_bytes(call: &Call<'_>, path: &Path) -> Step<Vec<u8>> {
    call.budget.hook()?;
    let raw = read_private(path, MAX_RECORD, true);
    call.budget.hook()?;
    raw.ok_or(JOURNAL_MISSING)
}

/// The journal half of `PendingCodexPublicationInverse.compare`: the same
/// file, the same bytes and the same authenticated record.
fn check_journal(
    call: &Call<'_>,
    home: &Path,
    record: &Map<String, Value>,
    sha256: &str,
    identity: &Value,
) -> Step<()> {
    let journal = Call::record_path(home);
    if rollback_identity(&journal)?.as_ref() != Some(identity)
        || sha256_hex(&journal_bytes(call, &journal)?) != sha256
        || &call.load(home, true)? != record
        || rollback_identity(&journal)?.as_ref() != Some(identity)
    {
        return Err(JOURNAL_CHANGED);
    }
    Ok(())
}

/// `before_publish=self.compare`: every file of `guard` still holds its
/// generation at the identity the caller last saw (`null` when unchecked).
fn check_guard(call: &Call<'_>) -> Step<()> {
    let Some(entries) = call.args.get("guard") else {
        return Ok(());
    };
    let entries = entries
        .as_array()
        .ok_or(Fault::Transition("files_invalid"))?;
    let roots = match call.args.get("package_roots") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(PathBuf::from))
            .collect::<Option<Vec<_>>>()
            .ok_or(Fault::Transition("files_invalid"))?,
        _ => Vec::new(),
    };
    let ask = Ask {
        budget: *call.budget,
        package_roots: roots,
    };
    for entry in entries {
        let file = entry
            .get("file")
            .ok_or(Fault::Transition("files_invalid"))?;
        let generation = match entry.get("generation").and_then(Value::as_str) {
            Some("before") => "before",
            Some("after") => "after",
            _ => return Err(Fault::Transition("files_invalid")),
        };
        let identity = entry.get("identity").filter(|value| !value.is_null());
        let path = file
            .get("path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or(Fault::Transition("files_invalid"))?;
        let same = || -> Step<bool> {
            Ok(identity.is_none_or(|expected| {
                rollback_identity(&path).ok().flatten().as_ref() == Some(expected)
            }))
        };
        if !same()? {
            return Err(GENERATION_CHANGED);
        }
        compare(std::slice::from_ref(file), generation, false, &ask)?;
        if !same()? {
            return Err(GENERATION_CHANGED);
        }
    }
    Ok(())
}

fn object<'a>(call: &'a Call<'_>, key: &str) -> Step<&'a Map<String, Value>> {
    call.args
        .get(key)
        .and_then(Value::as_object)
        .ok_or(Fault::Transition("files_invalid"))
}

fn identity_arg<'a>(call: &'a Call<'_>, key: &str) -> Step<&'a Value> {
    match call.args.get(key) {
        Some(value @ Value::Array(_)) => Ok(value),
        _ => Err(Fault::Transition("files_invalid")),
    }
}

/// `publication_inverse_record`: `_write_record(phase=..., observation=...)`
/// after the caller's `compare`. The record keeps every field it held and
/// gains `marker` as `publication_inverse`, signed at the owner operation.
/// Answers the new record, its digest and the identity it was published at.
pub(super) fn record_op(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let record = object(call, "record")?.clone();
    let marker = object(call, "marker")?.clone();
    let sha256 = call.text("journal_sha256")?.to_owned();
    let identity = identity_arg(call, "journal_identity")?.clone();
    let signed_at = call.text("signed_at")?.to_owned();
    check_journal(call, &home, &record, &sha256, &identity)?;

    let mut payload = record.clone();
    payload.insert("publication_inverse".to_owned(), Value::Object(marker));
    let mut request = Map::new();
    request.insert("op".to_owned(), json!("seal"));
    request.insert("kind".to_owned(), json!("recovery"));
    request.insert("payload".to_owned(), Value::Object(payload.clone()));
    request.insert("signed_at".to_owned(), json!(signed_at));
    let answer = Call::authority(&home, request)?;
    let encoded = answer
        .get("text")
        .and_then(Value::as_str)
        .ok_or(TOO_LARGE)?
        .as_bytes()
        .to_vec();
    if encoded.len() > MAX_RECORD {
        return Err(TOO_LARGE);
    }
    // `before_publish=self.compare`: the journal is still the one replaced.
    check_journal(call, &home, &record, &sha256, &identity)?;
    check_guard(call)?;
    let journal = Call::record_path(&home);
    // The journal write is not a Codex mutation; only restored targets are.
    write_private(&journal, &encoded, &mut Vec::new())?;
    let published = rollback_identity(&journal)?.ok_or(JOURNAL_CHANGED)?;
    if journal_bytes(call, &journal)? != encoded
        || rollback_identity(&journal)?.as_ref() != Some(&published)
    {
        return Err(JOURNAL_CHANGED);
    }
    Ok(json!({
        "record": payload,
        "sha256": sha256_hex(&encoded),
        "identity": published,
    }))
}

/// Whether `path` already holds `after` with its planned mode.
fn holds(call: &Call<'_>, path: &Path, after: &[u8], after_mode: u32) -> Step<bool> {
    if call.snapshot(path)?.as_deref() != Some(after) {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        Ok(mode == after_mode)
    }
    #[cfg(windows)]
    {
        let _ = after_mode;
        Ok(true)
    }
}

/// `publication_inverse_restore`: one target of the inverse, restored to its
/// planned `after` bytes unless it already holds them, then checked at the
/// identity it was published at (or the caller's `identity` when untouched).
pub(super) fn restore_op(call: &mut Call<'_>) -> Step<Value> {
    let path = call.path("path")?;
    let after = decode(call.args.get("after"))?.ok_or(Fault::Transition("files_invalid"))?;
    let after_mode = call
        .args
        .get("after_mode")
        .and_then(Value::as_u64)
        .and_then(|mode| u32::try_from(mode).ok())
        .ok_or(Fault::Transition("files_invalid"))?;
    let mut identity = call.args.get("identity").cloned().unwrap_or(Value::Null);
    if !holds(call, &path, &after, after_mode)? {
        check_guard(call)?;
        let mut events = Vec::new();
        write_private(&path, &after, &mut events)?;
        for mut event in events {
            if let Some(mutation) = event.get_mut("mutation").and_then(Value::as_object_mut) {
                mutation.insert(
                    "operation".to_owned(),
                    json!("explicit_inverse_provisional"),
                );
            }
            call.events.push(event);
        }
        identity = rollback_identity(&path)?.unwrap_or(Value::Null);
    }
    if identity.is_null()
        || rollback_identity(&path)?.as_ref() != Some(&identity)
        || call.snapshot(&path)?.as_deref() != Some(after.as_slice())
        || rollback_identity(&path)?.as_ref() != Some(&identity)
    {
        return Err(GENERATION_CHANGED);
    }
    Ok(json!({ "identity": identity }))
}

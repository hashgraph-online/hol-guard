//! The reviewable plan of an exact inverse for an unresolved Codex
//! publication, ported from `codex_publication_inverse_plan`.
//!
//! A plan conveys no mutation or lifecycle authority. Authentication of the
//! old journal is necessary but cannot authorize overwriting the current
//! config. These ops check the plan's shape against the journal, answer its
//! approval subject, and check that nothing the plan captured has changed.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{decode, sha256_hex};
use super::publication::{Call, MAX_RECORD};
use super::publication_io::{read_private, rollback_identity};
use super::publication_repair_plan::canonical_uuid;
use super::python_equal::python_equal;
use super::{Fault, Step};
use crate::codex_hook_authority_record::python_json::python_canonical_json;
use crate::runtime_transition_record::check_change;

const ACTION: &str = "apps.repair.codex-publication-inverse";
const PLAN_SCHEMA: &str = "hol-guard.codex-publication-inverse-plan.v1";
const MARKER_SCHEMA: &str = "hol-guard.codex-explicit-publication-inverse.v1";
const PRIOR_INVALID: Fault = Fault::Transition("publication_inverse_prior_record_invalid");
const PLAN_INVALID: Fault = Fault::Transition("publication_inverse_plan_invalid");
const KEYS: [&str; 3] = ["before_config", "before_manifest", "before_receipt"];

/// `publication_inverse_prior`: the operation of a prior inverse the record
/// names, validated as review data and never as replay authority.
pub(super) fn prior_op(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let record = call
        .args
        .get("record")
        .and_then(Value::as_object)
        .ok_or(PRIOR_INVALID)?;
    Ok(prior(&home, record)?.map_or(Value::Null, Value::String))
}

fn is_int(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_i64() || value.is_u64())
}

fn targets(home: &Path, record: &Map<String, Value>) -> Step<[String; 3]> {
    let config = record
        .get("config_path")
        .and_then(Value::as_str)
        .ok_or(PRIOR_INVALID)?;
    let (manifest, receipt) = Call::targets(home, config);
    let spelled = |path: PathBuf| path.to_string_lossy().into_owned();
    Ok([config.to_owned(), spelled(manifest), spelled(receipt)])
}

pub(super) fn prior(home: &Path, record: &Map<String, Value>) -> Step<Option<String>> {
    let Some(marker) = record.get("publication_inverse") else {
        return Ok(None);
    };
    let marker = marker.as_object().ok_or(PRIOR_INVALID)?;
    let plan = marker
        .get("plan")
        .and_then(Value::as_object)
        .ok_or(PRIOR_INVALID)?;
    let operation = plan
        .get("operation_id")
        .and_then(Value::as_str)
        .filter(|value| canonical_uuid(value))
        .ok_or(PRIOR_INVALID)?;
    let canonical = python_canonical_json(&Value::Object(plan.clone())).ok_or(PRIOR_INVALID)?;
    let subject = format!(
        "codex-publication-inverse:{operation}:{}",
        sha256_hex(canonical.as_bytes())
    );
    let targets = targets(home, record)?;
    fn text<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
        item.get(key).and_then(Value::as_str)
    }
    let phase = text(marker, "phase").unwrap_or_default();
    let published = marker
        .get("publication_monotonic")
        .filter(|value| value.is_number())
        .and_then(Value::as_f64);
    let pid = marker.get("owner_pid");
    let files = plan
        .get("files")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 3);
    let identities = marker
        .get("file_identities")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 3);
    let restored = marker.get("restored").and_then(Value::as_array);
    let restored: Option<Vec<i64>> =
        restored.and_then(|items| items.iter().map(Value::as_i64).collect());
    let allowed = |values: &[i64]| [&[][..], &[1], &[1, 2], &[1, 2, 0]].contains(&values);
    let valid = text(marker, "schema") == Some(MARKER_SCHEMA)
        && ["restoring", "restored", "verified"].contains(&phase)
        && text(plan, "schema") == Some(PLAN_SCHEMA)
        && text(plan, "action") == Some(ACTION)
        && text(plan, "guard_home") == Some(home.to_string_lossy().as_ref())
        && plan.get("config_path") == record.get("config_path")
        && plan.get("interrupted_operation_id") == record.get("operation_id")
        && text(marker, "subject") == Some(subject.as_str())
        && is_int(pid)
        && pid.and_then(Value::as_i64).is_some_and(|pid| pid > 0)
        && text(marker, "owner_operation_id").is_some_and(|owner| !owner.is_empty())
        && published.is_some_and(|value| value.is_finite() && value > 0.0)
        && files.is_some()
        && identities.is_some()
        && restored.as_deref().is_some_and(allowed)
        && (phase == "restoring" || restored.as_deref() == Some(&[1, 2, 0][..]))
        && (phase != "verified"
            || marker
                .get("native_verification")
                .is_some_and(Value::is_object));
    let (Some(files), Some(identities), true) = (files, identities, valid) else {
        return Err(PRIOR_INVALID);
    };
    for ((change, identity), (target, key)) in
        files.iter().zip(identities).zip(targets.iter().zip(KEYS))
    {
        let change = change.as_object().ok_or(PRIOR_INVALID)?;
        let identity_valid = match identity {
            Value::Null => true,
            Value::Array(values) => values.len() == 5 && values.iter().all(|v| is_int(Some(v))),
            _ => false,
        };
        if text(change, "path") != Some(target.as_str())
            || text(change, "kind") != Some("binding")
            || change.get("no_follow") != Some(&Value::Bool(true))
            || !is_int(change.get("after_mode"))
            || change.get("after_mode").and_then(Value::as_u64) != Some(0o600)
            || change.contains_key("expected_digest")
            || decode(change.get("after"))? != decode(record.get(key))?
            || !identity_valid
        {
            return Err(PRIOR_INVALID);
        }
    }
    Ok(Some(operation.to_owned()))
}

/// `publication_inverse_plan`: the checked approval payload and its subject.
pub(super) fn plan_op(call: &mut Call<'_>) -> Step<Value> {
    let args = call.args;
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(PLAN_INVALID);
    let operation = text("operation_id")?;
    let checked = |key: &str| -> Step<Value> {
        let items = args
            .get(key)
            .and_then(Value::as_array)
            .ok_or(PLAN_INVALID)?;
        for item in items {
            check_change(item.as_object().ok_or(PLAN_INVALID)?)
                .map_err(|(reason, detail)| Fault::Refused(reason, detail))?;
        }
        Ok(Value::Array(items.clone()))
    };
    let field = |key: &str| args.get(key).cloned().unwrap_or(Value::Null);
    let payload = json!({
        "schema": PLAN_SCHEMA,
        "action": ACTION,
        "guard_home": text("home")?,
        "config_path": text("config")?,
        "operation_id": operation,
        "interrupted_operation_id": text("interrupted_operation_id")?,
        "resumed_inverse_operation_id": field("resumed_inverse_operation_id"),
        "journal_sha256": text("journal_sha256")?,
        "journal_identity": field("journal_identity"),
        "files": checked("files")?,
        "file_identities": field("file_identities"),
        "dependencies": checked("dependencies")?,
        "native_runtime": field("native_runtime"),
        "verification_workspace": field("verification_workspace"),
    });
    let canonical = python_canonical_json(&payload).ok_or(PLAN_INVALID)?;
    let subject = format!(
        "codex-publication-inverse:{operation}:{}",
        sha256_hex(canonical.as_bytes())
    );
    Ok(json!({ "payload": payload, "subject": subject }))
}

/// `publication_inverse_check`: the journal, the record and every target
/// still hold exactly what the plan captured; answers the record's
/// predecessor manifest snapshot.
pub(super) fn check_op(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let args = call.args;
    let journal = Call::record_path(&home);
    let captured = args.get("journal_identity").ok_or(PLAN_INVALID)?;
    let changed = Fault::Transition("publication_inverse_journal_changed");
    call.budget.hook()?;
    if rollback_identity(&journal)?.as_ref() != Some(captured) {
        return Err(changed);
    }
    let raw = read_private(&journal, MAX_RECORD, true)
        .ok_or(Fault::Transition("publication_inverse_journal_missing"))?;
    call.budget.hook()?;
    if Some(sha256_hex(&raw).as_str()) != args.get("journal_sha256").and_then(Value::as_str)
        || rollback_identity(&journal)?.as_ref() != Some(captured)
    {
        return Err(changed);
    }
    let record = call.load(&home, true)?;
    check_record(&home, &record, call.args)?;
    let changes = call.args.get("files").and_then(Value::as_array);
    let identities = call.args.get("file_identities").and_then(Value::as_array);
    for (change, identity) in changes
        .into_iter()
        .flatten()
        .zip(identities.into_iter().flatten())
    {
        call.budget.hook()?;
        let path = PathBuf::from(
            change
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        let before = decode(change.get("before"))?;
        let same = |found: Option<Value>| found.as_ref().unwrap_or(&Value::Null) == identity;
        if !same(rollback_identity(&path)?)
            || call.snapshot(&path)? != before
            || !same(rollback_identity(&path)?)
        {
            return Err(Fault::Transition("publication_inverse_generation_changed"));
        }
    }
    // The authenticated predecessor manifest the dependencies are checked against.
    Ok(record
        .get("before_manifest")
        .cloned()
        .unwrap_or(Value::Null))
}

/// `PendingCodexPublicationInverse.compare`'s journal check: the journal still
/// has the identity and SHA-256 the pending inverse captured, and the record
/// it loads is the one the inverse holds. Answers `null`.
pub(super) fn journal_op(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let args = call.args;
    let journal = Call::record_path(&home);
    let captured = args.get("journal_identity").ok_or(PLAN_INVALID)?;
    let changed = Fault::Transition("publication_inverse_journal_changed");
    call.budget.hook()?;
    if rollback_identity(&journal)?.as_ref() != Some(captured) {
        return Err(changed);
    }
    let raw = read_private(&journal, MAX_RECORD, true)
        .ok_or(Fault::Transition("publication_inverse_journal_missing"))?;
    call.budget.hook()?;
    if Some(sha256_hex(&raw).as_str()) != args.get("journal_sha256").and_then(Value::as_str) {
        return Err(changed);
    }
    let held = args.get("record").ok_or(PLAN_INVALID)?;
    let record = Value::Object(call.load(&home, true)?);
    if !python_equal(&record, held) || rollback_identity(&journal)?.as_ref() != Some(captured) {
        return Err(changed);
    }
    Ok(Value::Null)
}

fn check_record(home: &Path, record: &Map<String, Value>, args: &Map<String, Value>) -> Step<()> {
    fn text<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
        item.get(key).and_then(Value::as_str)
    }
    let resumed = text(args, "resumed_inverse_operation_id").map(str::to_owned);
    let config = text(args, "config").ok_or(PLAN_INVALID)?;
    let (manifest, receipt) = Call::targets(home, text(record, "config_path").ok_or(PLAN_INVALID)?);
    let targets = [
        config.to_owned(),
        manifest.to_string_lossy().into_owned(),
        receipt.to_string_lossy().into_owned(),
    ];
    let changes = args.get("files").and_then(Value::as_array);
    let identities = args.get("file_identities").and_then(Value::as_array);
    let shaped = match (changes, identities) {
        (Some(changes), Some(identities)) if changes.len() == 3 && identities.len() == 3 => changes,
        _ => return Err(PLAN_INVALID),
    };
    let phase = text(record, "phase").unwrap_or_default();
    if !["prepared", "config_conflict"].contains(&phase)
        || record.contains_key("repair_plan")
        || prior(home, record)? != resumed
        || text(record, "config_path") != Some(config)
        || record.get("operation_id") != args.get("interrupted_operation_id")
    {
        return Err(PLAN_INVALID);
    }
    for ((change, target), key) in shaped.iter().zip(&targets).zip(KEYS) {
        let change = change.as_object().ok_or(PLAN_INVALID)?;
        let after = decode(change.get("after"))?;
        if text(change, "path") != Some(target.as_str())
            || after.is_none()
            || after != decode(record.get(key))?
            || change.get("no_follow") != Some(&Value::Bool(true))
            || change.get("after_mode").and_then(Value::as_u64) != Some(0o600)
            || text(change, "kind") != Some("binding")
            || change
                .get("expected_digest")
                .is_some_and(|value| !value.is_null())
        {
            return Err(PLAN_INVALID);
        }
    }
    Ok(())
}

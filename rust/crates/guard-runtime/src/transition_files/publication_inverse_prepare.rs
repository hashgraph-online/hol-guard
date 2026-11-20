//! `publication_inverse_prepare`: the whole preparation of a reviewable
//! inverse for an unresolved Codex publication, ported from
//! `prepare_authenticated_hook_publication_inverse`.
//!
//! The journal is authenticated under the runtime's own key and never
//! retired. A foreign config can be reviewed, but a competing authority
//! generation is never adopted into the inverse. A completed publication
//! needs its own reviewed recovery policy, not this protected inverse. The
//! caller sends the installation (`spec`), the harness `context`, the
//! `config` it names and a fresh `operation_id`; it settles the answer.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::inspect::{decode, mode_of, resolve_lenient, sha256_hex};
use super::publication::{Call, MAX_RECORD};
use super::publication_inverse_pinned::{predecessor_files, verify};
use super::publication_inverse_plan::prior;
use super::publication_io::{encode, read_private, rollback_identity};
use super::publication_repair_prepare::{fault, settled};
use super::{Fault, Step};
use crate::harness_adapter::{verify_captured, Verdict};

const INVALID: Fault = Fault::Transition("native_transition_invalid");
const MISSING: Fault = Fault::Transition("publication_inverse_predecessor_authority_missing");
const CHANGED: Fault = Fault::Transition("publication_inverse_generation_changed");

/// `_journal_bytes`: the journal, bounded and private, between two deadline
/// checks.
fn journal_bytes(call: &Call<'_>, journal: &Path) -> Step<Vec<u8>> {
    call.budget.hook()?;
    let raw = read_private(journal, MAX_RECORD, true);
    call.budget.hook()?;
    raw.ok_or(Fault::Transition("publication_inverse_journal_missing"))
}

fn bytes(record: &Map<String, Value>, key: &str) -> Step<Option<Vec<u8>>> {
    decode(record.get(key))
}

/// Request: `home`, `config`, `operation_id`, `spec`, `context` and
/// `package_roots`. Answer: the plan's facts, `{"guard_home", "config",
/// "operation_id", "interrupted_operation_id", "journal_sha256",
/// "journal_identity", "resumed_inverse_operation_id", "changes",
/// "change_identities", "dependencies"}`. `changes` and `change_identities`
/// run config, manifest, receipt.
pub(super) fn prepare(call: &mut Call<'_>) -> Step<Value> {
    call.budget.hook()?;
    let home = call.home()?;
    let journal = Call::record_path(&home);
    let journal_identity = rollback_identity(&journal)?
        .ok_or(Fault::Transition("publication_inverse_journal_missing"))?;
    let raw = journal_bytes(call, &journal)?;
    let record = call.load(&home, true)?;
    let text = |key: &str| record.get(key).and_then(Value::as_str);
    if !matches!(text("phase"), Some("prepared" | "config_conflict"))
        || record.contains_key("repair_plan")
    {
        return Err(Fault::Transition("publication_inverse_phase_invalid"));
    }
    let resumed = prior(&home, &record)?;
    let given = call.path("config")?;
    let config = match (given.parent(), given.file_name()) {
        (Some(parent), Some(name)) => resolve_lenient(parent).join(name),
        _ => given,
    };
    let config_text = config.to_string_lossy().into_owned();
    if text("config_path") != Some(config_text.as_str()) {
        return Err(Fault::Transition("publication_inverse_target_mismatch"));
    }
    let (manifest, receipt) = Call::targets(&home, &config_text);
    let (before_config, before_manifest, before_receipt) = (
        bytes(&record, "before_config")?,
        bytes(&record, "before_manifest")?,
        bytes(&record, "before_receipt")?,
    );
    let (Some(before_config), Some(before_manifest), Some(before_receipt)) =
        (before_config, before_manifest, before_receipt)
    else {
        return Err(MISSING);
    };
    let mut changes = Vec::new();
    let mut identities = Vec::new();
    let targets = [
        (&config, &before_config, "before_config", "after_config"),
        (
            &manifest,
            &before_manifest,
            "before_manifest",
            "after_manifest",
        ),
        (&receipt, &before_receipt, "before_receipt", "after_receipt"),
    ];
    for (target, previous, before_key, after_key) in targets {
        let identity = rollback_identity(target)?;
        let current = call.snapshot(target)?;
        if rollback_identity(target)? != identity {
            return Err(CHANGED);
        }
        let known = [bytes(&record, before_key)?, bytes(&record, after_key)?];
        if target != &config && !known.contains(&current) {
            return Err(Fault::Transition(
                "publication_inverse_authority_generation_changed",
            ));
        }
        let mode = if identity.is_none() {
            0o600
        } else {
            mode_of(target)?
        };
        changes.push(json!({
            "path": target.to_string_lossy(),
            "before": encode(current.as_deref())?,
            "after": encode(Some(previous))?,
            "before_mode": mode,
            "after_mode": 0o600,
            "kind": "binding",
            "no_follow": true,
        }));
        identities.push(identity.unwrap_or(Value::Null));
    }
    let manifest_text = std::str::from_utf8(&before_manifest).map_err(|_| INVALID)?;
    call.budget.hook()?;
    let mut request = call.args.clone();
    request.insert("config".to_owned(), json!(config_text));
    match verify_captured(&request, &before_config, manifest_text).map_err(fault)? {
        Verdict::HooksDisabled => {
            return Err(Fault::Transition(
                "publication_inverse_predecessor_hooks_disabled",
            ))
        }
        Verdict::State(state) => settled(&state)?,
    }
    call.budget.hook()?;
    let dependencies = predecessor_files(call, &home, manifest_text)?;
    if journal_bytes(call, &journal)? != raw
        || rollback_identity(&journal)? != Some(journal_identity.clone())
    {
        return Err(Fault::Transition("publication_inverse_journal_changed"));
    }
    let interrupted = text("operation_id").ok_or(INVALID)?.to_owned();
    let journal_sha256 = sha256_hex(&raw);
    let dependencies: Vec<Value> = dependencies.into_iter().map(Value::Object).collect();
    let mut args = call.args.clone();
    args.insert("config".to_owned(), json!(config_text));
    args.insert("interrupted_operation_id".to_owned(), json!(interrupted));
    args.insert("journal_sha256".to_owned(), json!(journal_sha256));
    args.insert("journal_identity".to_owned(), journal_identity.clone());
    args.insert("resumed_inverse_operation_id".to_owned(), json!(resumed));
    args.insert("files".to_owned(), Value::Array(changes.clone()));
    args.insert(
        "file_identities".to_owned(),
        Value::Array(identities.clone()),
    );
    args.insert(
        "dependencies".to_owned(),
        Value::Array(dependencies.clone()),
    );
    verify(&mut Call {
        args: &args,
        budget: call.budget,
        events: Vec::new(),
    })?;
    Ok(json!({
        "guard_home": home.to_string_lossy(),
        "config": config_text,
        "operation_id": call.text("operation_id")?,
        "interrupted_operation_id": interrupted,
        "journal_sha256": journal_sha256,
        "journal_identity": journal_identity,
        "resumed_inverse_operation_id": resumed,
        "changes": changes,
        "change_identities": identities,
        "dependencies": dependencies,
    }))
}

#[cfg(test)]
#[path = "tests_publication_inverse_prepare.rs"]
mod tests;

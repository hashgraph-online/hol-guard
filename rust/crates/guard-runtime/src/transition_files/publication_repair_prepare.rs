//! `publication_repair_prepare`: the whole preparation of a Codex authority
//! repair, ported from `prepare_authenticated_hook_manifest_repair`.
//!
//! A repair restores only the manifest its sealed receipt retained. This
//! refuses a manifest that is present, loads the receipt under the runtime's
//! own key, parses the retained config and verifies the retained manifest
//! against the installation the caller expects, pins every dependency, checks
//! that nothing changed since, and checks the plan. The caller sends the
//! installation (`spec`), the harness `context`, the `config` it names and a
//! fresh `operation_id`; it settles the answer and holds nothing else.

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::inspect::{decode, resolve_lenient, sha256_hex};
use super::publication::Call;
use super::publication_generation::package_roots;
use super::publication_io::encode;
use super::{checked, compare, publication_receipt, publication_repair_files};
use super::{publication_repair_plan, Ask, Fault, Step};
use crate::harness_adapter::{verify_captured, Failure, Verdict};

const INVALID: Fault = Fault::Transition("native_transition_invalid");

/// The fault the Python caller raises for a verification that failed.
pub(super) fn fault(failure: Failure) -> Fault {
    match failure {
        Failure::Runtime(message) | Failure::Refusal(message) | Failure::NotFound(message) => {
            Fault::Runtime(message)
        }
        Failure::Os(message) => Fault::Os(std::io::Error::other(message)),
        Failure::Integrity(reason) => Fault::Integrity(reason.to_owned(), reason.to_owned()),
        Failure::Reply(_) | Failure::Invalid => INVALID,
    }
}

fn bytes(loaded: &Value, key: &str) -> Step<Vec<u8>> {
    decode(loaded.get(key))?.ok_or(INVALID)
}

/// Request: `home`, `config`, `operation_id`, `spec`, `context` and
/// `package_roots`. Answer: `{"change", "files", "payload", "subject",
/// "guard_home", "config"}`, the files in the order the plan pins them.
pub(super) fn prepare(call: &mut Call<'_>) -> Step<Value> {
    call.budget.hook()?;
    let home = call.home()?;
    let given = call.path("config")?;
    let config = match (given.parent(), given.file_name()) {
        (Some(parent), Some(name)) => resolve_lenient(parent).join(name),
        _ => given.clone(),
    };
    let config_text = config.to_string_lossy().into_owned();
    let operation = call.text("operation_id")?.to_owned();
    let (manifest_path, _) = Call::targets(&home, &call.canonical(&config)?);
    if call.snapshot(&manifest_path)?.is_some() {
        return Err(Fault::Transition("authority_repair_manifest_present"));
    }
    let loaded = publication_receipt::load(call)?;
    let (manifest, receipt, retained) = (
        bytes(&loaded, "manifest")?,
        bytes(&loaded, "receipt")?,
        bytes(&loaded, "config")?,
    );
    let manifest_text = std::str::from_utf8(&manifest).map_err(|_| INVALID)?;
    let mut request = call.args.clone();
    request.insert("config".to_owned(), json!(config_text));
    let verdict = verify_captured(&request, &retained, manifest_text).map_err(fault)?;
    call.budget.hook()?;
    match verdict {
        Verdict::HooksDisabled => {
            return Err(Fault::Transition("authority_repair_hooks_disabled"));
        }
        Verdict::State(state) => settled(&state)?,
    }
    call.budget.hook()?;
    let mut pins = request;
    pins.insert("manifest_text".to_owned(), json!(manifest_text));
    pins.insert("receipt_sha256".to_owned(), json!(sha256_hex(&receipt)));
    pins.insert("config_sha256".to_owned(), json!(sha256_hex(&retained)));
    let pinned = publication_repair_files::files(&mut Call {
        args: &pins,
        budget: call.budget,
        events: Vec::new(),
    })?;
    let slot = resolve_lenient(&manifest_path);
    let change = json!({
        "path": slot.to_string_lossy(),
        "before": null,
        "after": encode(Some(&manifest))?,
        "before_mode": 0o600,
        "after_mode": 0o600,
        "kind": "binding",
        "no_follow": true,
    });
    let mut files = vec![change.clone()];
    files.extend(
        pinned
            .get("files")
            .and_then(Value::as_array)
            .ok_or(INVALID)?
            .clone(),
    );
    if manifest_path.is_symlink() {
        return Err(Fault::Transition("file_target_invalid"));
    }
    checked(&files)?;
    let ask = Ask {
        budget: *call.budget,
        package_roots: package_roots(call.args)?
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    };
    compare(&files, "before", false, &ask)?;
    call.budget.hook()?;
    plan(call, &home, &operation, &config_text, change, files)
}

/// `integrity_status` must be `valid`; anything else names its own refusal.
pub(super) fn settled(state: &Map<String, Value>) -> Step<()> {
    if state.get("integrity_status").and_then(Value::as_str) == Some("valid") {
        return Ok(());
    }
    let text = |key: &str| {
        state
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Err(Fault::Integrity(
        text("integrity_reason"),
        text("integrity_message"),
    ))
}

fn plan(
    call: &Call<'_>,
    home: &std::path::Path,
    operation: &str,
    config: &str,
    change: Value,
    files: Vec<Value>,
) -> Step<Value> {
    let mut args = Map::new();
    args.insert("operation_id".to_owned(), json!(operation));
    args.insert("home".to_owned(), json!(home.to_string_lossy()));
    args.insert("config".to_owned(), json!(config));
    args.insert("change".to_owned(), change.clone());
    args.insert("files".to_owned(), Value::Array(files.clone()));
    let planned = publication_repair_plan::plan(&mut Call {
        args: &args,
        budget: call.budget,
        events: Vec::new(),
    })?;
    let payload = planned.get("payload").cloned().ok_or(INVALID)?;
    Ok(json!({
        "change": change,
        "files": files,
        "guard_home": payload.get("guard_home"),
        "config": payload.get("config_path"),
        "payload": payload,
        "subject": planned.get("subject"),
    }))
}

#[cfg(test)]
#[path = "tests_publication_repair_prepare.rs"]
mod tests;

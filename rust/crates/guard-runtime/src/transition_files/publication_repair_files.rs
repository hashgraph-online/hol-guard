//! What a Codex hook repair or publication inverse pins, ported from
//! `prepare_authenticated_hook_manifest_repair` and
//! `_capture_predecessor_dependencies`.
//!
//! A repair restores the manifest its sealed receipt captured, and an inverse
//! restores the manifest a publication replaced. Each pins the key by digest
//! and every artifact each authenticated launch generation runs, so neither
//! can restore authority over bytes that changed after they were captured. A
//! repair also pins the receipt and the config. The manifest change stays
//! with the caller, which already holds its bytes.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::resolve_lenient;
use super::merge_dependency::merged;
use super::publication::Call;
use super::publication_generation::{identity_dependency, package_roots};
use super::{Fault, Step};
use crate::codex_hook_key;
use crate::codex_hook_launch_trust::{self, Refusal, LAUNCH_INVALID};
use crate::codex_hook_manifest_auth::authenticate_text;
use crate::codex_hook_manifest_build::bridge_argv_sha256;
use crate::codex_hook_manifest_refusal::refusal as manifest_refusal;

type Object = Map<String, Value>;

const MAX_GENERATIONS: usize = 8;
const SHARED: [&str; 5] = [
    "schema_version",
    "harness",
    "installation_id",
    "config",
    "context",
];

/// The refusals one caller names: a retained generation that does not
/// verify, and a generation whose interpreter names no target.
#[derive(Clone, Copy)]
pub(super) struct Purpose {
    retained: &'static str,
    target: &'static str,
}

pub(super) const REPAIR: Purpose = Purpose {
    retained: "codex_hook_repair_retained_identity_invalid",
    target: "authority_repair_identity_invalid",
};
const INVERSE: Purpose = Purpose {
    retained: "codex_publication_inverse_retained_identity_invalid",
    target: "publication_inverse_predecessor_identity_invalid",
};

impl Purpose {
    fn retained_invalid(self) -> Fault {
        Fault::Integrity(
            self.retained.to_owned(),
            "Guard could not verify a retained Codex launch generation.".to_owned(),
        )
    }
}

/// The authenticated manifest a request names: `manifest_text`, captured
/// bytes this runtime authenticates under its own key, or `manifest`, one a
/// caller already authenticated.
fn manifest_arg(call: &Call<'_>) -> Step<Object> {
    if let Some(text) = call.args.get("manifest_text") {
        let text = text.as_str().ok_or(Fault::Transition("files_invalid"))?;
        let home = call.home()?;
        let home = home.to_str().ok_or(Fault::Transition("files_invalid"))?;
        return authenticate_text(home, text, None, None).map_err(|reason| {
            let (code, message) = manifest_refusal(reason);
            Fault::Integrity(code, message)
        });
    }
    call.args
        .get("manifest")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(Fault::Transition("files_invalid"))
}

fn roots(call: &Call<'_>) -> Step<Vec<PathBuf>> {
    Ok(package_roots(call.args)?
        .into_iter()
        .map(PathBuf::from)
        .collect())
}

/// `publication_inverse_dependencies`: the key and every artifact the
/// authenticated predecessor `manifest` runs. Answer: `{"files": [...]}`.
pub(super) fn inverse(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let manifest = manifest_arg(call)?;
    let roots = roots(call)?;
    let key = identity_dependency(call, &codex_hook_key::key_path(&home))?;
    let mut files = vec![as_object(key)?];
    pin_generations(call, &mut files, &manifest, &roots, None, INVERSE)?;
    Ok(json!({ "files": files }))
}

fn pin_generations(
    call: &Call<'_>,
    files: &mut Vec<Object>,
    manifest: &Object,
    roots: &[PathBuf],
    written: Option<&Path>,
    purpose: Purpose,
) -> Step<()> {
    for generation in generations(manifest, purpose)? {
        call.budget.hook()?;
        for dependency in artifacts(generation, roots, purpose)? {
            add(files, dependency, written)?;
        }
    }
    Ok(())
}

/// Request: `home`, `config` (the publication slot), the authenticated
/// `manifest` the receipt sealed, the `receipt_sha256` and `config_sha256`
/// the caller verified, and `package_roots`. Answer:
/// `{"files": [...]}`, every dependency once, in the order first pinned.
pub(super) fn files(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let given = call.path("config")?;
    let config = match (given.parent(), given.file_name()) {
        (Some(parent), Some(name)) => resolve_lenient(parent).join(name),
        _ => given.clone(),
    };
    let (manifest_path, receipt_path) = Call::targets(&home, &call.canonical(&given)?);
    if call.snapshot(&manifest_path)?.is_some() {
        return Err(Fault::Transition("authority_repair_manifest_present"));
    }
    let manifest = manifest_arg(call)?;
    let roots = roots(call)?;
    let mut files: Vec<Object> = Vec::new();
    let manifest_slot = resolve_lenient(&manifest_path);
    let pinned = [
        (codex_hook_key::key_path(&home), None),
        (receipt_path, Some("receipt_sha256")),
        (config, Some("config_sha256")),
    ];
    for (path, captured) in pinned {
        let dependency = as_object(identity_dependency(call, &path)?)?;
        // The receipt and config must still be the bytes the caller verified.
        if let Some(key) = captured {
            let expected = call.args.get(key).and_then(Value::as_str);
            if expected.is_none()
                || dependency.get("expected_digest").and_then(Value::as_str) != expected
            {
                return Err(Fault::Transition("authority_repair_dependency_changed"));
            }
        }
        add(&mut files, dependency, Some(&manifest_slot))?;
    }
    pin_generations(
        call,
        &mut files,
        &manifest,
        &roots,
        Some(&manifest_slot),
        REPAIR,
    )?;
    Ok(json!({ "files": files }))
}

fn as_object(value: Value) -> Step<Object> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(Fault::Transition("files_invalid")),
    }
}

/// One dependency per path; a second pin of one artifact merges, and a pin
/// of the manifest the caller writes is a conflict.
pub(super) fn add(files: &mut Vec<Object>, dependency: Object, written: Option<&Path>) -> Step<()> {
    let path = dependency.get("path").cloned();
    let slot = written.map(|written| written.to_string_lossy().into_owned());
    if slot.is_some() && path.as_ref().and_then(Value::as_str) == slot.as_deref() {
        return Err(Fault::Transition("adapter_preparation_generation_conflict"));
    }
    match files
        .iter_mut()
        .find(|item| item.get("path") == path.as_ref())
    {
        Some(previous) => *previous = merged(previous, &dependency)?,
        None => files.push(dependency),
    }
    Ok(())
}

/// The manifest and every retained generation it authenticates, as
/// `retained_launch_generations` selects them.
fn generations(manifest: &Object, purpose: Purpose) -> Step<Vec<&Object>> {
    let list = |name: &str| match manifest.get(name) {
        None => Ok(&[][..]),
        Some(Value::Array(items)) if items.len() <= MAX_GENERATIONS => Ok(items.as_slice()),
        Some(_) => Err(purpose.retained_invalid()),
    };
    let retained = list("retained_bridge_generations")?;
    let allowed = list("compatible_bridge_argv_sha256")?;
    let well_formed = |value: &Value| {
        value.as_str().is_some_and(|text| {
            text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    };
    if !allowed.iter().all(well_formed) {
        return Err(purpose.retained_invalid());
    }
    let mut result = vec![manifest];
    for candidate in retained {
        let candidate = candidate
            .as_object()
            .filter(|candidate| {
                SHARED
                    .iter()
                    .all(|field| candidate.get(*field) == manifest.get(*field))
            })
            .ok_or_else(|| purpose.retained_invalid())?;
        let events = candidate
            .get("events")
            .and_then(Value::as_array)
            .filter(|events| !events.is_empty())
            .ok_or_else(|| purpose.retained_invalid())?;
        for event in events {
            let registered = event
                .get("argv")
                .and_then(Value::as_array)
                .filter(|argv| !argv.is_empty() && argv.iter().all(Value::is_string))
                .and_then(|argv| bridge_argv_sha256(argv))
                .is_some_and(|hash| allowed.iter().any(|item| item == &json!(hash)));
            if !registered {
                return Err(purpose.retained_invalid());
            }
        }
        result.push(candidate);
    }
    Ok(result)
}

fn refusal((reason, message): Refusal, purpose: Purpose) -> Fault {
    if reason == LAUNCH_INVALID {
        purpose.retained_invalid()
    } else {
        Fault::Integrity(reason, message)
    }
}

/// `verify_captured_launch_generation`, then each artifact it runs.
fn artifacts(generation: &Object, roots: &[PathBuf], purpose: Purpose) -> Step<Vec<Object>> {
    let mut args = Object::new();
    args.insert("manifest".to_owned(), Value::Object(generation.clone()));
    codex_hook_launch_trust::captured(&args, roots).map_err(|refused| refusal(refused, purpose))?;
    let interpreter = generation.get("interpreter").and_then(Value::as_object);
    let packaged = generation.get("packaged_files").and_then(Value::as_array);
    let (Some(interpreter), Some(packaged)) = (interpreter, packaged) else {
        return Err(purpose.retained_invalid());
    };
    let mut roles: Vec<(&str, &Object)> = Vec::new();
    for identity in packaged.iter().filter_map(Value::as_object) {
        let Some(role) = identity.get("role").and_then(Value::as_str) else {
            continue;
        };
        match roles.iter_mut().find(|(name, _)| *name == role) {
            Some(entry) => entry.1 = identity,
            None => roles.push((role, identity)),
        }
    }
    let mut dependencies = roles
        .into_iter()
        .map(|(_, identity)| artifact(identity, None))
        .collect::<Step<Vec<_>>>()?;
    let target = interpreter
        .get("target")
        .and_then(Value::as_object)
        .ok_or(Fault::Transition(purpose.target))?;
    dependencies.push(artifact(target, Some(interpreter))?);
    Ok(dependencies)
}

/// `TransitionFile.artifact_dependency`: the exact artifact pinned by its
/// digest, without journaling its bytes.
pub(super) fn artifact(identity: &Object, invocation: Option<&Object>) -> Step<Object> {
    let invalid = Fault::Transition("artifact_dependency_invalid");
    let path = identity.get("path").and_then(Value::as_str);
    let mode = identity
        .get("mode")
        .filter(|mode| mode.is_i64() || mode.is_u64());
    let digest = identity.get("sha256").filter(|digest| digest.is_string());
    let (Some(path), Some(mode), Some(digest)) = (path, mode, digest) else {
        return Err(invalid);
    };
    let path = Path::new(path);
    if !path.is_absolute() || path.is_symlink() {
        return Err(Fault::Transition("file_target_invalid"));
    }
    let field = |key: &str| identity.get(key).cloned().unwrap_or(Value::Null);
    let mut payload = as_object(json!({
        "path": resolve_lenient(path).to_string_lossy(),
        "before": null,
        "after": null,
        "before_mode": mode,
        "after_mode": mode,
        "kind": "binding",
        "no_follow": true,
        "expected_digest": digest,
        "artifact_identity": {
            "size": field("size"),
            "owner_uid": field("owner_uid"),
            "role": field("role"),
        },
    }))?;
    if let Some(invocation) = invocation {
        let field = |key: &str| invocation.get(key).cloned().unwrap_or(Value::Null);
        payload.insert(
            "invocation_identity".to_owned(),
            json!({
                "path": field("invocation_path"),
                "mode": field("invocation_mode"),
                "owner_uid": field("invocation_owner_uid"),
                "link_target": field("link_target"),
            }),
        );
    }
    Ok(payload)
}

#[cfg(test)]
#[path = "tests_publication_repair_files.rs"]
mod tests;

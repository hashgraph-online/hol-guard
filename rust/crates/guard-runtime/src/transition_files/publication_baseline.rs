//! The prior authenticated Codex hook baseline, ported from
//! `codex_hook_manifest.load_hook_manifest_baseline`.
//!
//! No manifest and no key is the only unauthenticated state that may create a
//! baseline: a first install, or the explicit migration of an exact legacy
//! hook. If either modern artifact exists, every authenticity and ownership
//! check must pass before current package bytes can be signed again.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::publication::{path_present, Call};
use super::{Fault, Step};
use crate::codex_hook_key::key_path;
use crate::codex_hook_manifest_auth;

/// One field of the installation the caller expects: named on the request,
/// or else by its `spec` (`CodexHookManifestSpec.payload`).
fn installation<'a>(call: &Call<'a>, key: &str) -> Option<&'a Value> {
    call.args.get(key).or_else(|| {
        call.args
            .get("spec")
            .and_then(Value::as_object)
            .and_then(|spec| spec.get(key))
    })
}

fn installation_path(call: &Call<'_>, keys: &[&str]) -> Step<PathBuf> {
    let path = keys
        .iter()
        .find_map(|key| installation(call, key))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(Fault::Transition("files_invalid"))?;
    if !path.is_absolute() {
        return Err(Fault::Transition("files_invalid"));
    }
    Ok(path)
}

/// `_expected_context`: the canonical spelling of each installation path.
fn expected_context(call: &Call<'_>) -> Step<Map<String, Value>> {
    let mut context = Map::new();
    for key in ["guard_home", "home_dir", "runtime_guard_home"] {
        let path = installation_path(call, &[key])?;
        context.insert(key.to_owned(), json!(call.canonical(&path)?));
    }
    let workspace = match installation(call, "workspace_dir") {
        None | Some(Value::Null) => Value::Null,
        Some(_) => json!(call.canonical(&installation_path(call, &["workspace_dir"])?)?),
    };
    context.insert("workspace_dir".to_owned(), workspace);
    Ok(context)
}

/// `_manifest_has_owned_installation_context`.
fn owned(
    manifest: &Map<String, Value>,
    config_target: &str,
    expected: &Map<String, Value>,
    rebinding: bool,
) -> bool {
    let config = manifest.get("config").and_then(Value::as_object);
    let context = manifest.get("context").and_then(Value::as_object);
    let config_owned = config.is_some_and(|config| {
        config.get("scope").and_then(Value::as_str) == Some("global")
            && config.get("target").and_then(Value::as_str) == Some(config_target)
    });
    let context_owned = context.is_some_and(|context| {
        context == expected
            || (rebinding
                && context.keys().eq(expected.keys())
                && ["guard_home", "home_dir", "runtime_guard_home"]
                    .iter()
                    .all(|key| context.get(*key) == expected.get(*key)))
    });
    manifest.get("harness").and_then(Value::as_str) == Some("codex")
        && config_owned
        && context_owned
}

const UNTRUSTED_REASON: &str = "codex_hook_manifest_baseline_untrusted";
const UNTRUSTED_MESSAGE: &str = "Guard refused to authenticate hook package bytes because the existing managed-hook baseline is missing, invalid, or belongs to another installation. Reinstall hol-guard from a trusted package, then run `hol-guard install codex` again.";

/// The refusal that ends a baseline nobody can trust: `cause` is the
/// authentication reason behind it, `null` for one owned by another installation.
fn untrusted(cause: Option<&str>) -> Value {
    json!({
        "untrusted": {
            "reason": UNTRUSTED_REASON,
            "message": UNTRUSTED_MESSAGE,
            "cause": cause,
        }
    })
}

/// `load_hook_manifest_baseline`: `{"manifest"}`, `null` for a clean install,
/// or `{"untrusted"}` with the integrity refusal Python raises for a baseline
/// that is missing, invalid or owned by another installation. Request: `spec`.
pub(super) fn load(call: &mut Call<'_>) -> Step<Value> {
    call.budget.hook()?;
    let answer = settled(call)?;
    call.budget.hook()?;
    Ok(answer)
}

fn settled(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = installation_path(call, &["config", "config_path"])?;
    let config_target = call.canonical(&config)?;
    let (manifest_path, _) = Call::targets(&home, &config_target);
    if !path_present(&manifest_path) && !path_present(&key_path(&home)) {
        return Ok(json!({ "manifest": null }));
    }
    call.budget.hook()?;
    let loaded =
        codex_hook_manifest_auth::load_path(&home.to_string_lossy(), Path::new(&manifest_path));
    call.budget.hook()?;
    let manifest = match loaded {
        Ok(manifest) => manifest,
        Err(reason) => return Ok(untrusted(Some(reason))),
    };
    let expected = expected_context(call)?;
    let rebinding =
        installation(call, "workspace_rebinding_allowed").and_then(Value::as_bool) == Some(true);
    if !owned(&manifest, &config_target, &expected, rebinding) {
        return Ok(untrusted(None));
    }
    Ok(json!({ "manifest": manifest }))
}

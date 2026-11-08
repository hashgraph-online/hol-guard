//! Authenticate the installation before touching the daemon or launching a child.
//! This is registration trust, never a hook policy decision. A cached Codex
//! command loses its authority when uninstall removes the signed manifest.
use std::path::Path;
use std::time::Instant;

use guard_policy_snapshot::local_authority_integrity::verify_local_authority_payload;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{base64url_decode_unpadded, decode_config_argument, BridgeConfig};
use crate::claude_hook_bridge_auth::private_file_raw;

const PURPOSE: &str = "codex-managed-hook-manifest";

pub(super) fn authenticate(
    config: &BridgeConfig,
    argv: &[String],
    deadline: Instant,
    event_name: &str,
) -> Option<()> {
    let encoded = argv.last()?;
    let payload: Value = serde_json::from_str(&decode_config_argument(encoded)?).ok()?;
    let manifest_path = Path::new(payload.get("manifest_path")?.as_str()?);
    let state = Path::new(&config.state_path);
    if !state.is_absolute()
        || state.file_name()? != "daemon-state.json"
        || !manifest_path.is_absolute()
    {
        return None;
    }
    let home = state.parent()?;
    if canonical(manifest_path.parent()?)? != canonical(&home.join("managed/codex"))? {
        return None;
    }
    let raw = private_file_raw(manifest_path, "Codex hook manifest").ok()?;
    if raw.len() > 1024 * 1024 || Instant::now() >= deadline {
        return None;
    }
    let mut manifest: Value = serde_json::from_str(&raw).ok()?;
    let auth = manifest.as_object_mut()?.remove("authentication")?;
    if auth.get("algorithm")?.as_str()? != "hmac-sha256" {
        return None;
    }
    let raw_key = private_file_raw(
        &home.join("managed/codex/hook-manifest.key"),
        "Codex hook key",
    )
    .ok()?;
    let secret: Value = serde_json::from_str(&raw_key).ok()?;
    let key_id = secret.get("key_id")?.as_str()?;
    let installation = secret.get("installation_id")?.as_str()?;
    let key = base64url_decode_unpadded(secret.get("key")?.as_str()?.trim_end_matches('='))?;
    if secret.get("schema_version")? != 1
        || key.len() != 32
        || key_id.len() < 24
        || installation.len() < 32
    {
        return None;
    }
    if verify_local_authority_payload(&manifest, &auth, Some(&key), Some(key_id), PURPOSE).status
        != "valid"
        || manifest.get("installation_id")?.as_str()? != installation
        || auth.get("signed_at")? != manifest.get("generated_at")?
    {
        return None;
    }
    context(&manifest, home, manifest_path)?;
    let selected = generation(&manifest, argv, event_name)?;
    context(selected, home, manifest_path)?;
    if selected.get("installation_id")? != manifest.get("installation_id")?
        || selected.get("context")? != manifest.get("context")?
        || selected.pointer("/fallback/argv")? != &json!(config.fallback_command)
        || selected.pointer("/daemon_start/argv")? != &json!(config.start_command)
    {
        return None;
    }
    let interpreter = selected.get("interpreter")?;
    if argv.len() != 1 && interpreter.get("invocation_path")?.as_str()? != argv.first()? {
        return None;
    }
    contract::validate(selected, argv, config)?;
    let files = selected.get("packaged_files")?.as_array()?;
    if !crate::codex_hook_manifest_verify_op::authenticated_launch_files(
        interpreter,
        files,
        deadline,
    ) {
        return None;
    }
    // File hashing can span an uninstall or reinstall. Do not carry the old
    // registration across that change into daemon IPC or child execution.
    if private_file_raw(manifest_path, "Codex hook manifest").ok()? != raw
        || private_file_raw(
            &home.join("managed/codex/hook-manifest.key"),
            "Codex hook key",
        )
        .ok()?
            != raw_key
    {
        return None;
    }
    (Instant::now() < deadline).then_some(())
}

fn context(manifest: &Value, home: &Path, path: &Path) -> Option<()> {
    if manifest.get("schema_version")? != 2
        || manifest.get("harness")?.as_str()? != "codex"
        || manifest.pointer("/context/runtime_guard_home")?.as_str()? != canonical(home)?
    {
        return None;
    }
    let target = manifest.pointer("/config/target")?.as_str()?;
    if !Path::new(target).is_absolute() {
        return None;
    }
    let digest = hex::encode(Sha256::digest(canonical(Path::new(target))?.as_bytes()));
    let expected = home
        .join("managed/codex")
        .join(format!("hooks-{}.manifest.json", &digest[..24]));
    (canonical(&expected)? == canonical(path)?).then_some(())
}

fn generation<'a>(manifest: &'a Value, argv: &[String], event_name: &str) -> Option<&'a Value> {
    let retained: &'a [Value] = match manifest.get("retained_bridge_generations") {
        None => &[],
        Some(value) => value.as_array()?.as_slice(),
    };
    let allowed = match manifest.get("compatible_bridge_argv_sha256") {
        None => &[][..],
        Some(value) => value.as_array()?.as_slice(),
    };
    if retained.len() > 8
        || allowed.len() > 8
        || allowed.iter().any(|item| {
            item.as_str().is_none_or(|text| {
                text.len() != 64
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
    {
        return None;
    }
    for candidate in std::iter::once(manifest).chain(retained.iter().rev()) {
        let events = candidate.get("events")?.as_array()?;
        let mut registered: Option<Vec<String>> = None;
        for event in events {
            let mut values: Vec<String> = event
                .get("argv")?
                .as_array()?
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<_>>()?;
            if values.get(1).map(String::as_str) == Some("codex-hook-bridge") {
                values.drain(..2);
            }
            if registered.as_ref().is_some_and(|known| known != &values) {
                return None;
            }
            registered = Some(values);
        }
        let registered = registered?;
        if (std::ptr::eq(candidate, manifest)
            || allowed
                .iter()
                .any(|hash| hash.as_str() == Some(&argv_hash(&registered))))
            && registered_argv_matches(argv, &registered, event_name)
        {
            return Some(candidate);
        }
    }
    // Legacy signed manifests can retain an exact argv hash without an old
    // layout. Never infer child paths: verify the current signed layout.
    let expected = comparison_argv(manifest, argv)?;
    allowed
        .iter()
        .any(|hash| hash.as_str() == Some(&argv_hash(&expected)))
        .then_some(manifest)
}

fn registered_argv_matches(incoming: &[String], registered: &[String], event_name: &str) -> bool {
    if incoming.is_empty() || registered.is_empty() {
        return false;
    }
    if incoming.len() != 1
        && (incoming.len() != registered.len()
            || incoming.get(..incoming.len() - 1)
                != registered.get(..registered.len().saturating_sub(1)))
    {
        return false;
    }
    let (Some(incoming), Some(registered)) = (incoming.last(), registered.last()) else {
        return false;
    };
    if incoming == registered {
        return true;
    }
    // Desktop has already spent part of the deadline when it delegates.
    // Permit only that event's smaller budget; all other fields stay signed.
    let parse =
        |raw: &str| -> Option<Value> { serde_json::from_str(&decode_config_argument(raw)?).ok() };
    let (Some(mut incoming), Some(mut registered)) = (parse(incoming), parse(registered)) else {
        return false;
    };
    let (Some(incoming), Some(registered)) = (incoming.as_object_mut(), registered.as_object_mut())
    else {
        return false;
    };
    let (Some(new), Some(old)) = (
        incoming.remove("hook_timeouts"),
        registered.remove("hook_timeouts"),
    ) else {
        return false;
    };
    if incoming != registered {
        return false;
    }
    let (Some(mut new), Some(mut old)) = (new.as_object().cloned(), old.as_object().cloned())
    else {
        return false;
    };
    let ceiling = old
        .get(event_name)
        .and_then(Value::as_i64)
        .or_else(|| old.values().filter_map(Value::as_i64).min());
    let lowered = new.remove(event_name).and_then(|value| value.as_i64());
    old.remove(event_name);
    new == old && matches!((lowered,ceiling),(Some(new),Some(old)) if new>2 && new<=old)
}

fn argv_hash(argv: &[String]) -> String {
    let value = crate::pyjson::PyVal::List(
        argv.iter()
            .cloned()
            .map(crate::pyjson::PyVal::Str)
            .collect(),
    );
    let mut text = String::new();
    crate::hook_env_stamp::dumps(&value, true, false, &mut text);
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub(crate) fn canonical(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    Some(crate::claude_hook_bridge_url::resolve_absolute(
        path.to_str()?,
    ))
}

fn comparison_argv(manifest: &Value, argv: &[String]) -> Option<Vec<String>> {
    if argv.len() == 4 {
        return Some(argv.to_vec());
    }
    if argv.len() != 1 {
        return None;
    }
    let bridge = manifest
        .get("packaged_files")?
        .as_array()?
        .iter()
        .find(|file| file.get("role").and_then(Value::as_str) == Some("bridge"))?;
    Some(vec![
        manifest
            .pointer("/interpreter/invocation_path")?
            .as_str()?
            .to_owned(),
        "-I".to_owned(),
        bridge.get("path")?.as_str()?.to_owned(),
        argv[0].clone(),
    ])
}

#[path = "codex_hook_bridge_registration_contract.rs"]
mod contract;

#[cfg(test)]
#[path = "codex_hook_bridge_registration_tests.rs"]
mod tests;

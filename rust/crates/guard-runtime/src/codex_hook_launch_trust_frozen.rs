//! The frozen Codex hook launch, ported from `frozen_codex_runtime`.
//!
//! A frozen Guard runs every packaged role from one executable. Its launch is
//! trusted only while the authenticated manifest binds every role to that
//! executable, the fallback and daemon-start commands are the frozen
//! subcommands of it, and every event registers exactly this bridge config.

use std::path::Path;

use serde_json::{json, Value};

use super::{
    file, mapping, packaged_files, strings, verify_context, Checked, Object, Packaged, Refusal,
    Request, LAUNCH_INVALID,
};
use crate::codex_hook_bridge::{decode_config_argument, BRIDGE_COMMAND};
use crate::codex_hook_bridge_trust_files::{canonical, verify_executable_in};

const RECOVER_ARG: &str = "--_hol-guard-codex-daemon-recover";
const TRANSPORT_ROLES: [&str; 4] = ["bridge", "launch_runtime", "runtime_trust", "windows_job"];

fn refused(message: &str) -> Refusal {
    (
        LAUNCH_INVALID.to_owned(),
        format!("managed frozen Codex {message}"),
    )
}

/// What a frozen launch must agree with besides the manifest.
pub(super) struct Launch<'a> {
    pub(super) guard_home: &'a Path,
    pub(super) state: String,
    pub(super) configured_manifest: String,
    pub(super) fallback: &'a [String],
    pub(super) start: &'a [String],
    pub(super) config_json: &'a str,
}

/// `_validate_frozen_codex_hook_launch`: `frozen` names the executable this
/// process runs, and the transition artifact it must be when one is named.
pub(super) fn launch(
    request: &Request<'_>,
    frozen: &Object,
    roots: &[std::path::PathBuf],
) -> Checked<Value> {
    let manifest = &request.manifest;
    verify_context(manifest, &request.home, &request.manifest_path)?;
    let interpreter = mapping(manifest.get("interpreter"), "interpreter")?;
    verify_executable_in(&Value::Object(interpreter.clone()), Some(roots)).map_err(file)?;
    let packaged = packaged_files(manifest, roots)?;
    let target = mapping(interpreter.get("target"), "interpreter target")?;
    let target_path = target.get("path").and_then(Value::as_str);
    let current = frozen
        .get("executable")
        .and_then(Value::as_str)
        .ok_or_else(|| refused("hook executable identity is invalid"))?;
    if let Some(artifact) = frozen
        .get("artifact")
        .filter(|artifact| !artifact.is_null())
    {
        let sha256 = artifact.get("sha256").filter(|value| value.is_string());
        if target_path != Some(current)
            || sha256.is_none()
            || target.get("sha256") != sha256
            || manifest.get("package_version") != artifact.get("package_version")
        {
            return Err(refused("transition artifact identity is invalid"));
        }
    }
    let invocation = interpreter.get("invocation_path").and_then(Value::as_str);
    let Some(target_path) = target_path.filter(|_| invocation == Some(current)) else {
        return Err(refused("hook executable identity is invalid"));
    };
    if packaged
        .iter()
        .any(|(_, identity)| identity.get("path").and_then(Value::as_str) != Some(target_path))
    {
        return Err(refused("hook package identity is incomplete"));
    }
    let launch = Launch {
        guard_home: &request.home,
        state: request.state.to_string_lossy().into_owned(),
        configured_manifest: request.manifest_path.to_string_lossy().into_owned(),
        fallback: &request.fallback,
        start: &request.start,
        config_json: request.config_json,
    };
    contracts(manifest, interpreter, &packaged, &launch)?;
    Ok(Value::Null)
}

/// The frozen transport, launch and bridge contracts of one generation.
pub(super) fn contracts(
    manifest: &Object,
    interpreter: &Object,
    packaged: &Packaged<'_>,
    launch: &Launch<'_>,
) -> Checked<()> {
    transport(manifest, packaged)?;
    launch_contracts(manifest, interpreter, launch)?;
    bridge_contract(manifest, launch)
}

/// `_verify_frozen_transport`.
fn transport(manifest: &Object, packaged: &Packaged<'_>) -> Checked<()> {
    let invalid = || refused("hook transport identity is invalid");
    let transport = manifest
        .get("transport")
        .and_then(Value::as_object)
        .filter(|transport| transport.get("wrapper").is_none_or(Value::is_null))
        .ok_or_else(invalid)?;
    for role in TRANSPORT_ROLES {
        let recorded = packaged
            .iter()
            .find(|(name, _)| *name == role)
            .map(|(_, identity)| *identity);
        let same = match (transport.get(role), recorded) {
            (None, None) => true,
            (Some(Value::Object(found)), Some(recorded)) => found == recorded,
            _ => false,
        };
        if !same {
            return Err(invalid());
        }
    }
    Ok(())
}

/// `_decode_private_payload`: a JSON object, or why not.
fn payload(raw: Option<&str>, label: &str) -> Checked<Object> {
    let value: Value = raw
        .and_then(|raw| serde_json::from_str(raw).ok())
        .ok_or_else(|| {
            (
                LAUNCH_INVALID.to_owned(),
                format!("{label} payload must be valid JSON"),
            )
        })?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err((
            LAUNCH_INVALID.to_owned(),
            format!("{label} payload must be a JSON object"),
        )),
    }
}

/// `_verify_frozen_launch_contracts`.
fn launch_contracts(manifest: &Object, interpreter: &Object, launch: &Launch<'_>) -> Checked<()> {
    let invocation = interpreter
        .get("invocation_path")
        .and_then(Value::as_str)
        .ok_or_else(|| refused("hook interpreter path is invalid"))?;
    let interpreter = Value::Object(interpreter.clone());
    let fallback = mapping(manifest.get("fallback"), "fallback")?;
    let argv = strings(fallback.get("argv"), "fallback argv")?;
    if argv != launch.fallback
        || fallback.get("interpreter") != Some(&interpreter)
        || fallback.get("package_roles") != Some(&json!(["fallback_entrypoint"]))
        || argv
            .get(..4)
            .is_none_or(|head| head != [invocation, "hook", "--harness", "codex"])
    {
        return Err(refused("hook fallback contract is invalid"));
    }
    let daemon = mapping(manifest.get("daemon_start"), "daemon start")?;
    let argv = strings(daemon.get("argv"), "daemon start argv")?;
    let context = mapping(manifest.get("context"), "context")?;
    let home = context.get("runtime_guard_home").and_then(Value::as_str);
    let home_dir = context.get("home_dir").and_then(Value::as_str);
    let guard_home = canonical(launch.guard_home).to_string_lossy().into_owned();
    let (Some(home), Some(home_dir)) = (home, home_dir) else {
        return Err(refused("hook daemon-start contract is invalid"));
    };
    if argv != launch.start
        || daemon.get("interpreter") != Some(&interpreter)
        || daemon.get("package_roles") != Some(&json!(["daemon_entrypoint", "daemon_manager"]))
        || argv.len() != 3
        || argv[0] != invocation
        || argv[1] != RECOVER_ARG
        || guard_home != home
    {
        return Err(refused("hook daemon-start contract is invalid"));
    }
    let recovery = payload(Some(&argv[2]), "Codex daemon recovery")?;
    if Value::Object(recovery) != json!({"guard_home": home, "home_dir": home_dir}) {
        return Err(refused("hook daemon-start context is invalid"));
    }
    Ok(())
}

/// `_verify_frozen_bridge_contract`: the bridge config names exactly this
/// launch, and every event registers exactly that config.
fn bridge_contract(manifest: &Object, launch: &Launch<'_>) -> Checked<()> {
    let decoded = decode_config_argument(launch.config_json);
    let config = payload(decoded.as_deref(), "Codex bridge")?;
    if config.get("state_path") != Some(&json!(launch.state))
        || config.get("manifest_path") != Some(&json!(launch.configured_manifest))
        || config.get("fallback_command") != Some(&json!(launch.fallback))
        || config.get("start_command") != Some(&json!(launch.start))
    {
        return Err(refused("hook bridge config is invalid"));
    }
    let events = manifest
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .ok_or_else(|| refused("hook event identity is invalid"))?;
    for event in events {
        let argv = event.get("argv").and_then(Value::as_array);
        // The native runtime is a verified copy of the bundled one, so only
        // its command and the config it reads identify the bridge.
        let registered = argv.is_some_and(|argv| {
            argv.len() == 3
                && argv[0].is_string()
                && argv[1] == BRIDGE_COMMAND
                && argv[2] == launch.config_json
        });
        if !registered {
            return Err(refused("hook bridge config changed after authentication"));
        }
    }
    Ok(())
}

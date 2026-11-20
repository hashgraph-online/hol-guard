//! `codex_hook_file_integrity` ops `launch` and `captured`: authenticate a
//! managed Codex hook launch before its fallback or daemon start runs, ported
//! from `codex_hook_runtime_trust`.
//!
//! The authenticated manifest names every file the launch may run. A launch
//! is trusted only while:
//!
//! - the manifest is this Guard home's private, MAC-verified file;
//! - one authenticated generation registers exactly this bridge argv;
//! - the interpreter and every packaged file, one per role, are the files
//!   install recorded, beside the asking trust module;
//! - the fallback and daemon-start commands are the exact isolated commands
//!   that interpreter and package root produce.
//!
//! The asker supplies two facts only it knows: the path of its own trust
//! module (`runtime_path`) and its package roots. A frozen layout, where every
//! packaged file is the one frozen executable, is checked against that
//! executable instead.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::codex_hook_bridge::{decode_config_argument, BRIDGE_COMMAND};
use crate::codex_hook_bridge_trust_files::{canonical, verify_executable_in, verify_regular_in};
use crate::codex_hook_manifest_auth as manifest_auth;
use crate::hook_process_spawn::{isolated_daemon_start_command, isolated_guard_cli_command};

/// The reason every launch refusal carries; the message says which check.
pub(crate) const LAUNCH_INVALID: &str = "codex_hook_launch_invalid";
const SCHEMA_VERSION: i64 = 2;
const STATE_FILE: &str = "daemon-state.json";
const REQUIRED_ROLES: [&str; 7] = [
    "bridge",
    "daemon_entrypoint",
    "daemon_manager",
    "fallback_entrypoint",
    "launch_runtime",
    "runtime_trust",
    "windows_job",
];
const OBSERVATION_ROLES: [&str; 2] = ["hook_probe", "native_receipt"];

/// A refusal: `(reason, message)`. Launch refusals carry [`LAUNCH_INVALID`];
/// file refusals carry their file reason, manifest refusals their manifest
/// reason, each with the wording the asker reports.
pub(crate) type Refusal = (String, String);
type Checked<T> = Result<T, Refusal>;
type Object = Map<String, Value>;

fn invalid(message: &str) -> Refusal {
    (
        LAUNCH_INVALID.to_owned(),
        format!("managed Codex hook {message}"),
    )
}

fn file(reason: String) -> Refusal {
    let message = crate::codex_hook_file_integrity_op::message(&reason);
    (reason, message)
}

fn mapping<'a>(value: Option<&'a Value>, label: &str) -> Checked<&'a Object> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{label} identity is invalid")))
}

fn strings(value: Option<&Value>, label: &str) -> Checked<Vec<String>> {
    let items = value
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| invalid(&format!("{label} is invalid")))?;
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invalid(&format!("{label} is invalid")))
}

fn text<'a>(args: &'a Object, key: &str) -> Checked<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("launch request is invalid"))
}

fn spelled(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `hook_manifest_path`: the manifest a config target owns in a Guard home.
fn manifest_for(home: &Path, target: &Path) -> PathBuf {
    crate::codex_hook_paths_op::manifest_path(home, target)
}

/// One launch request: its managed paths, this home's authenticated
/// manifest, and the commands and config the bridge was registered with.
struct Request<'a> {
    home: PathBuf,
    state: PathBuf,
    manifest_path: PathBuf,
    manifest: Object,
    config_json: &'a str,
    fallback: Vec<String>,
    start: Vec<String>,
}

fn request(args: &Object) -> Checked<Request<'_>> {
    let state = PathBuf::from(text(args, "state_path")?);
    let (home, manifest_path) = managed_paths(&state, Path::new(text(args, "manifest_path")?))?;
    let home_text = home.to_str().ok_or_else(|| invalid("paths are invalid"))?;
    // The asker words a manifest refusal from its reason. The manifest is
    // read before any command is judged, so a missing one is named first.
    let manifest = manifest_auth::load_path(home_text, &manifest_path)
        .map(manifest_auth::unsigned)
        .map_err(|reason| (reason.to_owned(), reason.to_owned()))?;
    let config_json = text(args, "config_json")?;
    let fallback = strings(args.get("fallback_command"), "fallback command")?;
    let start = strings(args.get("start_command"), "start command")?;
    Ok(Request {
        home,
        state,
        manifest_path,
        manifest,
        config_json,
        fallback,
        start,
    })
}

/// `validate_codex_hook_launch`, or the frozen launch when `frozen` names
/// the executable this process runs.
pub(crate) fn launch(args: &Object, roots: &[PathBuf]) -> Checked<Value> {
    let request = request(args)?;
    if let Some(frozen) = args.get("frozen").filter(|frozen| !frozen.is_null()) {
        return frozen::launch(&request, mapping(Some(frozen), "frozen launch")?, roots);
    }
    let runtime_path = PathBuf::from(text(args, "runtime_path")?);
    let (home, manifest_path) = (&request.home, &request.manifest_path);
    verify_context(&request.manifest, home, manifest_path)?;
    let manifest = selected_generation(&request.manifest, request.config_json)?;
    verify_context(manifest, home, manifest_path)?;
    let interpreter = mapping(manifest.get("interpreter"), "interpreter")?;
    verify_executable_in(&Value::Object(interpreter.clone()), Some(roots)).map_err(file)?;
    let packaged = packaged_files(manifest, roots)?;
    verify_transport(&packaged, manifest, &runtime_path)?;
    let (fallback, start) = (&request.fallback, &request.start);
    launch_contracts(manifest, interpreter, &packaged, home, fallback, start)?;
    let bridge = packaged_role(&packaged, "bridge")?;
    registered_bridge_argv(manifest, bridge, request.config_json)?;
    Ok(Value::Null)
}

/// `verify_captured_launch_generation` for an authenticated `manifest`,
/// packaged or frozen, without selecting or spawning it.
pub(crate) fn captured(args: &Object, roots: &[PathBuf]) -> Checked<Value> {
    let manifest = mapping(args.get("manifest"), "manifest")?;
    let interpreter = mapping(manifest.get("interpreter"), "interpreter")?;
    verify_executable_in(&Value::Object(interpreter.clone()), Some(roots)).map_err(file)?;
    let packaged = packaged_files(manifest, roots)?;
    let events = manifest
        .get("events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .ok_or_else(|| invalid("captured events are invalid"))?;
    let argv = strings(
        event_argv(&events[0])?.map(Value::from).as_ref(),
        "bridge argv",
    )?;
    if argv.len() != 3 || argv[1] != BRIDGE_COMMAND {
        return Err(invalid("captured argv is invalid"));
    }
    let config_json = &argv[2];
    let config: Value = decode_config_argument(config_json)
        .and_then(|text| serde_json::from_str(&text).ok())
        .ok_or_else(|| invalid("captured config is invalid"))?;
    let config = mapping(Some(&config), "bridge config")?;
    let context = mapping(manifest.get("context"), "context")?;
    let registration = mapping(manifest.get("config"), "config target")?;
    let field =
        |object: &'_ Object, key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
    let (Some(home), Some(runtime_home), Some(target)) = (
        field(context, "guard_home"),
        field(context, "runtime_guard_home"),
        field(registration, "target"),
    ) else {
        return Err(invalid("captured context is invalid"));
    };
    let state = spelled(&Path::new(&runtime_home).join(STATE_FILE));
    let configured = spelled(&manifest_for(Path::new(&home), Path::new(&target)));
    if field(config, "state_path").as_deref() != Some(state.as_str())
        || field(config, "manifest_path").as_deref() != Some(configured.as_str())
    {
        return Err(invalid("captured context changed"));
    }
    let fallback = strings(config.get("fallback_command"), "fallback command")?;
    let start = strings(config.get("start_command"), "start command")?;
    let target_path = mapping(interpreter.get("target"), "interpreter target")?.get("path");
    if packaged
        .iter()
        .all(|(_, identity)| identity.get("path") == target_path)
    {
        let launch = frozen::Launch {
            guard_home: Path::new(&runtime_home),
            state,
            configured_manifest: configured,
            fallback: &fallback,
            start: &start,
            config_json,
        };
        frozen::contracts(manifest, interpreter, &packaged, &launch)?;
        return Ok(Value::Null);
    }
    let trust_path = packaged_role(&packaged, "runtime_trust")?
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("captured trust path is invalid"))?;
    verify_transport(&packaged, manifest, Path::new(trust_path))?;
    let home = Path::new(&runtime_home);
    launch_contracts(manifest, interpreter, &packaged, home, &fallback, &start)?;
    registered_bridge_argv(manifest, packaged_role(&packaged, "bridge")?, config_json)?;
    Ok(Value::Null)
}

/// `_resolve_managed_hook_paths`: this Guard home and the manifest it owns.
fn managed_paths(state: &Path, manifest: &Path) -> Checked<(PathBuf, PathBuf)> {
    if !state.is_absolute() || !manifest.is_absolute() {
        return Err(invalid("paths must be absolute"));
    }
    let home = canonical(state.parent().unwrap_or(state));
    let directory = canonical(manifest.parent().unwrap_or(manifest));
    if state.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE)
        || directory != canonical(&home.join("managed").join("codex"))
    {
        return Err(invalid("paths do not belong to this Guard home"));
    }
    let name = manifest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if !name.starts_with("hooks-") || !name.ends_with(".manifest.json") {
        return Err(invalid("manifest path is invalid"));
    }
    Ok((home, manifest.to_path_buf()))
}

/// `_verify_manifest_context`: this home's Codex manifest, at the path its
/// config target names.
fn verify_context(manifest: &Object, home: &Path, path: &Path) -> Checked<()> {
    if manifest.get("schema_version").and_then(Value::as_i64) != Some(SCHEMA_VERSION)
        || manifest.get("harness").and_then(Value::as_str) != Some("codex")
    {
        return Err(invalid("manifest schema is unsupported"));
    }
    let context = mapping(manifest.get("context"), "context")?;
    if context.get("runtime_guard_home").and_then(Value::as_str) != Some(&spelled(&canonical(home)))
    {
        return Err(invalid("manifest belongs to another Guard home"));
    }
    let config = mapping(manifest.get("config"), "config")?;
    let target = config
        .get("target")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|target| target.is_absolute())
        .ok_or_else(|| invalid("config target is invalid"))?;
    if canonical(&manifest_for(home, target)) != canonical(path) {
        return Err(invalid("manifest target binding is invalid"));
    }
    Ok(())
}

type Packaged<'a> = Vec<(&'a str, &'a Object)>;

fn packaged_role<'a>(packaged: &Packaged<'a>, role: &str) -> Checked<&'a Object> {
    packaged
        .iter()
        .find(|(name, _)| *name == role)
        .map(|(_, identity)| *identity)
        .ok_or_else(|| invalid("package identity is incomplete"))
}

/// `_verified_packaged_files`: every recorded file, one per role, still the
/// file install recorded, and exactly the launch or observation role set.
fn packaged_files<'a>(manifest: &'a Object, roots: &[PathBuf]) -> Checked<Packaged<'a>> {
    let files = manifest
        .get("packaged_files")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("packaged-file identity is invalid"))?;
    let mut packaged: Packaged<'a> = Vec::new();
    for value in files {
        let identity = mapping(Some(value), "packaged file")?;
        let role = identity
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| packaged.iter().all(|(name, _)| name != role))
            .ok_or_else(|| invalid("packaged-file roles are invalid"))?;
        verify_regular_in(value, Some(roots)).map_err(file)?;
        packaged.push((role, identity));
    }
    complete(&packaged)?;
    Ok(packaged)
}

/// Every launch role, plus either all observation roles or none of them.
fn complete(packaged: &Packaged<'_>) -> Checked<()> {
    let has = |role: &&str| packaged.iter().any(|(name, _)| name == role);
    let required = REQUIRED_ROLES.iter().all(has);
    let observed = OBSERVATION_ROLES.iter().filter(|role| has(role)).count();
    let complete = packaged.len() == REQUIRED_ROLES.len() + observed
        && (observed == 0 || observed == OBSERVATION_ROLES.len());
    if !required || !complete {
        return Err(invalid("package identity is incomplete"));
    }
    Ok(())
}

/// The observation modules, when recorded, sit beside `runtime_path`.
fn verify_observation_paths(packaged: &Packaged<'_>, runtime_path: &Path) -> Checked<()> {
    let beside = |name: &str| Value::from(spelled(&canonical(&runtime_path.with_file_name(name))));
    let path_of = |role: &str| packaged_role(packaged, role).map(|identity| identity.get("path"));
    for (role, name) in [
        ("hook_probe", "runtime_transition_hook_probe.py"),
        ("native_receipt", "native_decision_receipt.py"),
    ] {
        if packaged.iter().any(|(found, _)| *found == role) && path_of(role)? != Some(&beside(name))
        {
            return Err((
                LAUNCH_INVALID.to_owned(),
                "managed Codex observation package path is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

/// `_verify_transport`: the packaged modules sit beside `runtime_path`, and
/// the recorded transport is exactly those files with no wrapper.
fn verify_transport(
    packaged: &Packaged<'_>,
    manifest: &Object,
    runtime_path: &Path,
) -> Checked<()> {
    verify_observation_paths(packaged, runtime_path)?;
    let beside = |name: &str| Value::from(spelled(&canonical(&runtime_path.with_file_name(name))));
    let path_of = |role: &str| packaged_role(packaged, role).map(|identity| identity.get("path"));
    let trust = Value::from(spelled(&canonical(runtime_path)));
    for (role, expected, what) in [
        (
            "launch_runtime",
            beside("codex_hook_launch_runtime.py"),
            "launch runtime",
        ),
        ("runtime_trust", trust, "runtime trust"),
        (
            "windows_job",
            beside("codex_hook_windows_job.py"),
            "Windows job",
        ),
    ] {
        if path_of(role)? != Some(&expected) {
            return Err(invalid(&format!("{what} path is invalid")));
        }
    }
    let transport = mapping(manifest.get("transport"), "transport")?;
    for role in ["bridge", "launch_runtime", "runtime_trust", "windows_job"] {
        if transport.get(role).and_then(Value::as_object) != Some(packaged_role(packaged, role)?) {
            return Err(invalid("transport identity is invalid"));
        }
    }
    if transport
        .get("wrapper")
        .is_some_and(|wrapper| !wrapper.is_null())
    {
        return Err(invalid("transport identity is invalid"));
    }
    Ok(())
}

/// `_verify_launch_contracts`: the fallback and daemon-start commands are
/// the exact isolated commands of the authenticated interpreter and package.
fn launch_contracts(
    manifest: &Object,
    interpreter: &Object,
    packaged: &Packaged<'_>,
    guard_home: &Path,
    fallback_command: &[String],
    start_command: &[String],
) -> Checked<()> {
    let entrypoint = packaged_role(packaged, "fallback_entrypoint")?
        .get("path")
        .and_then(Value::as_str);
    let (Some(python), Some(entrypoint)) = (
        interpreter.get("invocation_path").and_then(Value::as_str),
        entrypoint,
    ) else {
        return Err(invalid("launch identity is invalid"));
    };
    let entrypoint = Path::new(entrypoint);
    let package = entrypoint
        .parent()
        .filter(|_| entrypoint.file_name().is_some_and(|n| n == "cli.py"));
    let Some(package_root) = package
        .filter(|parent| {
            parent
                .file_name()
                .is_some_and(|n| n == "codex_plugin_scanner")
        })
        .and_then(Path::parent)
    else {
        return Err(invalid("fallback entrypoint is invalid"));
    };
    let package_root = canonical(package_root);
    let interpreter_value = Value::Object(interpreter.clone());
    let fallback = mapping(manifest.get("fallback"), "fallback")?;
    let argv = strings(fallback.get("argv"), "fallback argv")?;
    let hook = ["guard", "hook", "--harness", "codex"];
    if argv != fallback_command
        || fallback.get("interpreter") != Some(&interpreter_value)
        || fallback.get("package_roles") != Some(&json!(["fallback_entrypoint"]))
        || argv.get(4..8).is_none_or(|slice| slice != hook)
        || isolated_guard_cli_command(python, &package_root, &argv[4..]) != argv
    {
        return Err(invalid("fallback contract is invalid"));
    }
    let daemon = mapping(manifest.get("daemon_start"), "daemon start")?;
    let argv = strings(daemon.get("argv"), "daemon start argv")?;
    let context = mapping(manifest.get("context"), "context")?;
    let (Some(home), Some(home_dir)) = (
        context.get("runtime_guard_home").and_then(Value::as_str),
        context.get("home_dir").and_then(Value::as_str),
    ) else {
        return Err(invalid("daemon-start contract is invalid"));
    };
    if spelled(&canonical(guard_home)) != home
        || spelled(&canonical(Path::new(home_dir))) != home_dir
        || argv != start_command
        || daemon.get("interpreter") != Some(&interpreter_value)
        || daemon.get("package_roles") != Some(&json!(["daemon_entrypoint", "daemon_manager"]))
        || isolated_daemon_start_command(
            python,
            &package_root,
            guard_home,
            Some(Path::new(home_dir)),
        ) != argv
    {
        return Err(invalid("daemon-start contract is invalid"));
    }
    Ok(())
}

#[path = "codex_hook_launch_trust_generation.rs"]
mod generation;
use generation::{event_argv, registered_bridge_argv, selected_generation};

#[path = "codex_hook_launch_trust_frozen.rs"]
mod frozen;

#[cfg(all(test, unix))]
#[path = "codex_hook_launch_trust_tests.rs"]
mod tests;

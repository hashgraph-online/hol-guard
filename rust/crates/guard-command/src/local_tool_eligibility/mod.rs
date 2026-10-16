//! Authenticated, digest-bound eligibility for read-only local CLI grants.
//!
//! A command earns a reusable grant identity through one of three paths: an
//! authenticated local Node validation routine, a narrow package-run profile,
//! or a verified local executable whose operation and options are read-only.
//! Every refusal, unreadable input or unexpected state yields no eligibility.

mod jq;
mod module_scan;
mod package_profile;
mod python_digit;
mod routine;
mod routine_config;
mod routine_identity;

use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::codex_output_py::{py_strip, PyPath};
use crate::command_model::{parse_shell_command, CommandSegment};
use crate::command_tokens::executable_name;
use crate::launch_identity::{build_runtime_launch_identity, runtime_launch_identity_is_reusable};

/// `(package, version, integrity, tree digest)` of a trusted installed tree.
pub type TrustedTree<'a> = (&'a str, &'a str, &'a str, &'a str);

/// Installed package trees whose content digests authorize routine grants.
pub const TRUSTED_PACKAGE_TREES: &[TrustedTree<'static>] = &[
    (
        "eslint",
        "9.38.0",
        "sha512-t5aPOpmtJcZcz5UJyY2GbvpDlsK5E8JqRqoKtfiKE3cNh437KIqfJr3A3AKf5k64NPx6d0G3dno6XDY05PqPtw==",
        "39f4230ad4489863c6fcced909d99460cc4637f8af83065a9344a9ae2153e768",
    ),
    (
        "next",
        "16.3.0-preview.8",
        "sha512-c9CF1GAZnpB7iwZWCnPdSPfdrmGkvr+lGqcRuH++EIYFxb4Mk6EIve13ExuO4ghbhayQVGyP+hY8BocnQ/aHbA==",
        "14e290417e32af06148c8715812f7b03bd98958e0382032637d8b8d844e5b98d",
    ),
    (
        "typescript",
        "5.9.3",
        "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==",
        "e5e331517b5c57cef26c6ed1c1dd2193ed52002a49a276cf7971b499c7f83b0f",
    ),
];

const INTERPRETERS: [&str; 6] = ["bun", "deno", "node", "nodejs", "python", "python3"];
const READ_ONLY_OPERATIONS: [&str; 13] = [
    "check", "describe", "diff", "find", "get", "inspect", "list", "query", "read", "report",
    "search", "show", "status",
];
const READ_ONLY_HTTP_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];
const HTTP_OPERATIONS: [&str; 4] = ["api", "fetch", "query", "request"];
const SIDE_EFFECTING_OPTIONS: [&str; 17] = [
    "-o",
    "--apply",
    "--create",
    "--delete",
    "--download",
    "--exec",
    "--execute",
    "--force",
    "--out",
    "--output",
    "--publish",
    "--remove",
    "--save",
    "--send",
    "--update",
    "--upload",
    "--write",
];
const HTTP_METHOD_OPTIONS: [&str; 3] = ["-x", "--method", "--request"];
const VARIABLE_READ_SELECTOR_OPTIONS: [&str; 2] = ["--path", "--query"];
const STABLE_IDENTITY_DROPPED_KEYS: [&str; 3] =
    ["argument_sha256", "reuse_nonce", "script_args_sha256"];

/// Inputs for one eligibility decision.
pub struct LocalToolEligibilityInput<'a> {
    pub command: &'a str,
    pub cwd: &'a Path,
    pub home_dir: Option<&'a Path>,
    /// The requesting user's home, used where the retired code read `Path.home()`.
    pub user_home: Option<&'a Path>,
    /// The launch environment (`{name: value}`) used for executable resolution.
    pub launch_env: &'a Value,
}

/// A grant-eligible local tool capability.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalToolEligibility {
    pub tool_name: String,
    pub tool_identity_hash: String,
    pub capability: String,
    pub read_only_reason: String,
    /// `"verified-files"` or `"package-profile"`.
    pub trust_basis: &'static str,
    pub indefinite_allowed: bool,
    /// The canonical material whose SHA-256 is `tool_identity_hash`.
    pub identity_material: Value,
}

/// A refusal that the retired implementation raised instead of returning.
/// It never grants: the public entry point maps it to "not eligible".
#[derive(Debug)]
pub(crate) struct Abort;

pub(crate) type Outcome<T> = Result<T, Abort>;

/// Decide whether `command` is eligible for a reusable local tool grant.
pub fn local_tool_eligibility(
    input: &LocalToolEligibilityInput<'_>,
    trusted_trees: &[TrustedTree<'_>],
) -> Option<LocalToolEligibility> {
    evaluate(input, trusted_trees).ok().flatten()
}

fn evaluate(
    input: &LocalToolEligibilityInput<'_>,
    trusted_trees: &[TrustedTree<'_>],
) -> Outcome<Option<LocalToolEligibility>> {
    let routine_home = input.home_dir.unwrap_or(input.cwd);
    if let Some(profile) = routine::routine_profile(input.command, routine_home, trusted_trees)? {
        return eligible(
            profile.tool_name.to_owned(),
            profile.capability.to_owned(),
            "Authenticated local developer validation command".to_owned(),
            "package-profile",
            false,
            profile.identity_material,
        );
    }
    if input.command.trim().is_empty() {
        return Err(Abort);
    }
    let model = parse_shell_command(
        input.command,
        Some(input.cwd),
        input.home_dir,
        "posix",
        "shell_string",
        "hook_tool_input",
        true,
    );
    if model.confidence != "exact"
        || !model.redirects.is_empty()
        || !model.embedded_commands.is_empty()
        || !matches!(model.segments.len(), 1 | 2)
    {
        return Ok(None);
    }
    let primary = &model.segments[0];
    let package_profile = package_profile::trusted_package_tool_profile(primary, input)?;
    if let Some(profile) = package_profile {
        if model.segments.len() == 1 {
            return eligible(
                "impeccable".to_owned(),
                "scan".to_owned(),
                "profile_impeccable_scan".to_owned(),
                "package-profile",
                profile.indefinite_allowed,
                profile.identity_material,
            );
        }
    }
    if !safe_top_level_segment(primary, 0) {
        return Ok(None);
    }
    let mut processor_binding = Value::Null;
    if model.segments.len() == 2 {
        let processor = &model.segments[1];
        if !safe_top_level_segment(processor, 1)
            || executable_name(processor.executable.as_deref()).as_deref() != Some("jq")
            || !jq::safe_jq_arguments(&processor.arguments)
        {
            return Ok(None);
        }
        let Some(mut binding) = reusable_launch_binding(processor, input) else {
            return Ok(None);
        };
        let arguments = string_array(&processor.arguments);
        binding.insert(
            "arguments_sha256".to_owned(),
            Value::String(canonical_sha256(&arguments)?),
        );
        processor_binding = Value::Object(binding);
    }
    let Some(launch_binding) = reusable_launch_binding(primary, input) else {
        return Ok(None);
    };
    let Some(operation) = local_tool_operation(primary) else {
        return Ok(None);
    };
    let Some(read_only_reason) = read_only_reason(&primary.arguments, &operation) else {
        return Ok(None);
    };
    let tool_name = tool_display_name(primary, &launch_binding);
    let material = json!({
        "version": 1,
        "launch": Value::Object(launch_binding),
        "argument_shape": argument_shape(primary),
        "output_processor": processor_binding,
    });
    eligible(
        tool_name,
        operation,
        read_only_reason,
        "verified-files",
        false,
        material,
    )
}

fn eligible(
    tool_name: String,
    capability: String,
    read_only_reason: String,
    trust_basis: &'static str,
    indefinite_allowed: bool,
    identity_material: Value,
) -> Outcome<Option<LocalToolEligibility>> {
    Ok(Some(LocalToolEligibility {
        tool_name,
        tool_identity_hash: canonical_sha256(&identity_material)?,
        capability,
        read_only_reason,
        trust_basis,
        indefinite_allowed,
        identity_material,
    }))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub(crate) fn canonical_bytes(value: &Value) -> Outcome<Vec<u8>> {
    let mut out = Vec::new();
    guard_contracts::write_canonical_json(value, &mut out).map_err(|_| Abort)?;
    Ok(out)
}

pub(crate) fn canonical_sha256(value: &Value) -> Outcome<String> {
    Ok(sha256_hex(&canonical_bytes(value)?))
}

/// `sha256(prefix + len(encoded).to_bytes(8, "big") + encoded).hexdigest()`.
pub(crate) fn framed_digest(prefix: &[u8], value: &Value) -> Outcome<String> {
    let encoded = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    Ok(hex::encode(hasher.finalize()))
}

/// A `pathlib` predicate: an embedded NUL is `ValueError`, which `pathlib`
/// reports as `False`; any other non-ignorable `OSError` propagates.
pub(crate) fn probe(path: &PyPath, check: fn(&PyPath) -> Result<bool, ()>) -> Outcome<bool> {
    if path.to_string().contains('\0') {
        return Ok(false);
    }
    check(path).map_err(|()| Abort)
}

pub(crate) fn py_path(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

fn string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn is_interpreter(segment: &CommandSegment) -> bool {
    executable_name(segment.executable.as_deref())
        .is_some_and(|name| INTERPRETERS.contains(&name.as_str()))
}

fn safe_top_level_segment(segment: &CommandSegment, pipeline_index: usize) -> bool {
    segment.execution_context == "top:0"
        && segment.pipeline_index == pipeline_index
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.executable.is_some()
}

/// `build_runtime_launch_identity(executable, args=arguments, structured_command=True, cwd=cwd)`.
pub(crate) fn segment_launch_identity(
    segment: &CommandSegment,
    input: &LocalToolEligibilityInput<'_>,
) -> Value {
    let command = segment
        .executable
        .clone()
        .map_or(Value::Null, Value::String);
    let arguments: Vec<Value> = segment
        .arguments
        .iter()
        .cloned()
        .map(Value::String)
        .collect();
    build_runtime_launch_identity(
        &command,
        &arguments,
        true,
        false,
        None,
        Some(input.cwd),
        None,
        Some(input.launch_env),
    )
}

fn reusable_launch_binding(
    segment: &CommandSegment,
    input: &LocalToolEligibilityInput<'_>,
) -> Option<Map<String, Value>> {
    let identity = segment_launch_identity(segment, input);
    if !runtime_launch_identity_is_reusable(&identity) {
        return None;
    }
    let executable = identity.get("executable")?.as_object()?;
    let entrypoint = identity.get("entrypoint")?.as_object()?;
    if executable.get("status").and_then(Value::as_str) != Some("verified") {
        return None;
    }
    if !matches!(
        entrypoint.get("status").and_then(Value::as_str),
        Some("verified" | "bound-by-executable")
    ) {
        return None;
    }
    let script_kind = entrypoint
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.ends_with("-script"));
    if is_interpreter(segment) && !script_kind {
        return None;
    }
    let mut binding = Map::new();
    binding.insert("executable".to_owned(), stable_identity_mapping(executable));
    binding.insert("entrypoint".to_owned(), stable_identity_mapping(entrypoint));
    Some(binding)
}

/// A launch identity without its per-invocation fields.
pub(crate) fn stable_identity_mapping(value: &Map<String, Value>) -> Value {
    Value::Object(
        value
            .iter()
            .filter(|(key, _)| !STABLE_IDENTITY_DROPPED_KEYS.contains(&key.as_str()))
            .map(|(key, item)| (key.clone(), stable_identity_value(item)))
            .collect(),
    )
}

fn stable_identity_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => stable_identity_mapping(map),
        Value::Array(items) => Value::Array(items.iter().map(stable_identity_value).collect()),
        other => other.clone(),
    }
}

fn local_tool_operation(segment: &CommandSegment) -> Option<String> {
    let arguments = &segment.arguments;
    if arguments.is_empty() {
        return None;
    }
    let index = usize::from(is_interpreter(segment));
    let operation = py_strip(arguments.get(index)?).to_lowercase();
    if operation.is_empty() || operation.starts_with('-') {
        return None;
    }
    Some(operation.chars().take(80).collect())
}

fn read_only_reason(arguments: &[String], operation: &str) -> Option<String> {
    if arguments.iter().any(|argument| {
        normalized_option(argument)
            .is_some_and(|option| SIDE_EFFECTING_OPTIONS.contains(&option.as_str()))
    }) {
        return None;
    }
    let mut methods: Vec<String> = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        let Some(option) = normalized_option(argument) else {
            continue;
        };
        if !HTTP_METHOD_OPTIONS.contains(&option.as_str()) {
            continue;
        }
        if let Some((_, value)) = argument.split_once('=') {
            methods.push(value.to_uppercase());
        } else if let Some(next) = arguments.get(index + 1) {
            methods.push(next.to_uppercase());
        } else {
            return None;
        }
    }
    if methods.len() > 1 {
        return None;
    }
    match methods.first() {
        Some(method) => (READ_ONLY_HTTP_METHODS.contains(&method.as_str())
            && HTTP_OPERATIONS.contains(&operation))
        .then(|| format!("http_{}", method.to_lowercase())),
        None => READ_ONLY_OPERATIONS
            .contains(&operation)
            .then(|| format!("operation_{operation}")),
    }
}

fn argument_shape(segment: &CommandSegment) -> Vec<String> {
    let start = if is_interpreter(segment) { 2 } else { 1 };
    let arguments = segment.arguments.get(start..).unwrap_or(&[]);
    let mut shape = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let Some(option) = normalized_option(argument) else {
            shape.push("<positional>".to_owned());
            shape.push(argument.clone());
            index += 1;
            continue;
        };
        shape.push(option.clone());
        let value = if let Some((_, value)) = argument.split_once('=') {
            value.to_owned()
        } else if index + 1 < arguments.len() && normalized_option(&arguments[index + 1]).is_none()
        {
            index += 1;
            arguments[index].clone()
        } else {
            index += 1;
            continue;
        };
        if VARIABLE_READ_SELECTOR_OPTIONS.contains(&option.as_str()) {
            shape.push("<selector>".to_owned());
        } else {
            shape.push(value);
        }
        index += 1;
    }
    shape
}

fn normalized_option(argument: &str) -> Option<String> {
    if !argument.starts_with('-') || argument == "-" {
        return None;
    }
    let head = argument.split_once('=').map_or(argument, |(head, _)| head);
    Some(head.to_lowercase())
}

fn tool_display_name(segment: &CommandSegment, binding: &Map<String, Value>) -> String {
    let entrypoint_path = binding
        .get("entrypoint")
        .and_then(|entrypoint| entrypoint.get("path"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty());
    if let Some(path) = entrypoint_path {
        return PyPath::new(path).name().to_owned();
    }
    let executable = segment
        .executable
        .as_deref()
        .filter(|executable| !executable.is_empty())
        .unwrap_or("local-tool");
    PyPath::new(executable).name().to_owned()
}

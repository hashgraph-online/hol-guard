//! `LocalCliHook` — the hook-time local CLI step in one resident call.
//!
//! Records the CLI a command launches (and refreshes a package script
//! catalog), then refines the hook action with this device's grant. Python's
//! `observe_unlisted_cli` and `apply_local_cli_grant` made one resident call
//! per identity, record and grant read; the same steps run here in-process.
//! The caller supplies only the command, its directories and environment, and
//! the action being refined; none of those can create a grant.
//!
//! A failed or malformed identity derivation records nothing. A grant step
//! without a trustworthy answer is unverified: an allowed command is held for
//! review while any block rule exists. A hook that gets no answer from this op
//! at all answers with the host outage response, as the direct hook path's
//! unverified block does; the transport never picks an action itself.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use guard_command::command_model::parse_shell_command;
use guard_contracts::{
    GuardStoreRequestV1, LocalCliHookRequestV1, LocalCliHookResultV1, LocalCliIdentitySourceV1,
    PackageJsonScriptsV1, PackageScriptCommandV1, UnlistedCliV1, GUARD_STORE_REQUEST_SCHEMA,
    LOCAL_CLI_HOOK_REQUEST_SCHEMA, LOCAL_CLI_HOOK_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::context_digest_local_cli::python_path_name;
use crate::context_digest_package_scripts::package_json_scripts;
use crate::hook_direct::local_cli::block::{match_command_id, valid_package, valid_unlisted};
use crate::local_cli_hook_contained::{self as contained, Refined};
use crate::local_cli_identify::{identify, Request};
use crate::local_store_read;
use crate::native_exact_action_op::runner_bin::runner_split;

const IDENTIFY_BUDGET_MS: u64 = 2_000;
const ROOT_COMMAND_ID: &str = "root";
const OTHER_COMMAND_ID: &str = "other";
/// `MAX_LOCAL_CLI_COMMANDS`: the merged catalog, root and other included.
const MAX_COMMANDS: usize = 101;
/// `_MAX_DEPTH`: command tokens read from one invocation.
const MAX_DEPTH: usize = 4;
const STORE_FAILED: &str = "native_local_cli_hook_store_failed";

/// The CLI a grant is read for, as `matching_local_cli_grant` derives it.
pub(crate) struct Launch {
    pub(crate) cli_id: String,
    pub(crate) identity_hash: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) runner: Option<String>,
    pub(crate) source: LocalCliIdentitySourceV1,
}

/// The resident's package script answer; `Err` is a failed or malformed one.
type Package = Result<Option<PackageJsonScriptsV1>, ()>;

pub(crate) fn evaluate_local_cli_hook_request(
    request: &LocalCliHookRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != LOCAL_CLI_HOOK_REQUEST_SCHEMA {
        return Err("native_local_cli_hook_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match run_refined(request) {
        Ok(refined) => {
            let mut payload = json!({ "action": refined.action });
            if let Some(connector) = refined.connector {
                payload["connector"] = connector;
            }
            if let Some(grant) = refined.contained_grant {
                payload["contained_grant"] = grant;
                payload["contained_route"] = crate::local_cli_hook_contained::contained_route();
            }
            ("ok".to_owned(), "ok".to_owned(), Some(payload))
        }
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&LocalCliHookResultV1 {
        schema: LOCAL_CLI_HOOK_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

fn request_digest(request: &LocalCliHookRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_local_cli_hook_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_local_cli_hook_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

#[cfg(test)]
pub(crate) fn run(request: &LocalCliHookRequestV1) -> Result<String, &'static str> {
    run_with_connector(request).map(|(action, _)| action)
}

/// The refined action, and the connector a `review` waits on when this device
/// has no allow or block decision for the CLI the command launches.
#[cfg(test)]
pub(crate) fn run_with_connector(
    request: &LocalCliHookRequestV1,
) -> Result<(String, Option<Value>), &'static str> {
    run_refined(request).map(|refined| (refined.action, refined.connector))
}

/// Record the launch, then refine the action with this device's grant.
pub(crate) fn run_refined(request: &LocalCliHookRequestV1) -> Result<Refined, &'static str> {
    let package = checked_package(request)?;
    observe(request, &package)?;
    Ok(refined(request, &package))
}

/// The grant refinement alone, recording nothing: what the workspace sink
/// asks again right before it widens a sandbox by a grant.
#[cfg(unix)]
pub(crate) fn decide_refined(request: &LocalCliHookRequestV1) -> Result<Refined, &'static str> {
    let package = checked_package(request)?;
    Ok(refined(request, &package))
}

fn checked_package(request: &LocalCliHookRequestV1) -> Result<Package, &'static str> {
    local_store_read::require_store_path(&request.store_path, &request.guard_home)
        .map_err(|_| "native_local_cli_hook_path_invalid")?;
    let package_home = request.home_dir.as_deref().unwrap_or(&request.cwd);
    Ok(
        match package_json_scripts(&request.command, &request.cwd, package_home) {
            Ok(Some(found)) if !valid_package(&found) => Err(()),
            found => found.map_err(|_| ()),
        },
    )
}

fn refined(request: &LocalCliHookRequestV1, package: &Package) -> Refined {
    if !contained::refinable(request) {
        return Refined {
            action: request.current_action.clone(),
            ..Refined::default()
        };
    }
    contained::refine(request, grant(request, package), || {
        contained::unverified_action(request).to_owned()
    })
}

/// `observe_unlisted_cli`: the package script identity, else every CLI a
/// single or compound invocation launches.
fn observe(request: &LocalCliHookRequestV1, package: &Package) -> Result<(), &'static str> {
    let Ok(package) = package else {
        // A failed derivation can mistake a script for a plain binary.
        return Ok(());
    };
    if let Some(found) = package {
        if let Some(identity) = &found.identity {
            record(
                request,
                [
                    ("cli_id", json!(identity.cli_id)),
                    ("identity_hash", json!(identity.identity_hash)),
                    ("kind", json!("script")),
                    ("name", json!(identity.name)),
                    ("interpreter_name", json!(found.runner)),
                    ("example_label", json!(format!("{} run", found.runner))),
                    ("source_path", json!(found.manifest_path)),
                    ("surface", json!("package-scripts")),
                ],
            )?;
            if !found.commands.is_empty() {
                let mut args = Map::new();
                args.insert("cli_id".to_owned(), json!(identity.cli_id));
                args.insert(
                    "commands".to_owned(),
                    json!(merged_commands(&found.runner, &found.commands)),
                );
                store_call(request, "replace_local_cli_commands", args)?;
            }
            return Ok(());
        }
    }
    let Ok(records) = unlisted(request, true) else {
        return Ok(());
    };
    for record_item in &records {
        let source_path = record_item
            .path_class
            .clone()
            .filter(|class| !class.is_empty())
            .unwrap_or_else(|| {
                crate::custom_extension_suggestion::path_class(record_item.source_path.as_deref())
            });
        record(
            request,
            [
                ("cli_id", json!(record_item.cli_id)),
                ("identity_hash", json!(record_item.identity_hash)),
                ("kind", json!(record_item.kind)),
                ("name", json!(record_item.name)),
                ("interpreter_name", json!(record_item.interpreter_name)),
                ("example_label", json!(record_item.example_label)),
                ("source_path", json!(source_path)),
                ("surface", json!("cli")),
            ],
        )?;
    }
    Ok(())
}

/// `record_local_cli_observation` with the Python store's defaults.
fn record<const N: usize>(
    request: &LocalCliHookRequestV1,
    fields: [(&str, Value); N],
) -> Result<(), &'static str> {
    let now = now_micros().ok_or(STORE_FAILED)?;
    let seen_at =
        crate::policy_bundle_time::micros_to_utc_isoformat(now - now.rem_euclid(1_000_000), "Z")
            .ok_or(STORE_FAILED)?;
    let clock =
        crate::policy_bundle_time::micros_to_utc_isoformat(now, "+00:00").ok_or(STORE_FAILED)?;
    let mut args: Map<String, Value> = fields
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    for key in [
        "help_status",
        "server_identity_hash",
        "server_command",
        "server_args_hash",
        "replayed_at",
    ] {
        args.insert(key.to_owned(), Value::Null);
    }
    args.insert("seen_at".to_owned(), json!(seen_at));
    args.insert("only_if_missing".to_owned(), json!(false));
    args.insert("clock".to_owned(), json!(clock));
    store_call(request, "record_local_cli_observation", args)
}

fn store_call(
    request: &LocalCliHookRequestV1,
    method: &str,
    args: Map<String, Value>,
) -> Result<(), &'static str> {
    crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        store_path: request.store_path.clone(),
        guard_home: request.guard_home.clone(),
        method: method.to_owned(),
        source: request.source.clone(),
        busy_timeout_ms: request.busy_timeout_ms,
        args,
    })
    .map(|_| ())
    // The store's own code keeps the SQLite failure class, so the caller can
    // recover a corrupt store as it would after a store call.
    .map_err(|error| error.code())
}

fn now_micros() -> Option<i64> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_micros()).ok()
}

/// `merge_discovered_commands(f"{runner} run", commands)`: root first, the
/// valid distinct scripts, and the catch-all `other` last.
pub(crate) fn merged_commands(
    runner: &str,
    discovered: &[PackageScriptCommandV1],
) -> Vec<PackageScriptCommandV1> {
    let tool_name = format!("{runner} run");
    let label = match tool_name.trim() {
        "" => "tool",
        trimmed => trimmed,
    };
    let entry =
        |command_id: &str, name: &str, usage: String, description: String| PackageScriptCommandV1 {
            command_id: command_id.to_owned(),
            name: name.to_owned(),
            usage,
            description,
            parent_id: None,
        };
    let mut merged = vec![entry(
        ROOT_COMMAND_ID,
        label,
        label.to_owned(),
        format!("Run {label} without a subcommand."),
    )];
    let mut seen: BTreeSet<&str> = [ROOT_COMMAND_ID, OTHER_COMMAND_ID].into();
    for command in discovered {
        if !crate::local_mcp_grant_identity::is_command_id(&command.command_id)
            || !seen.insert(command.command_id.as_str())
        {
            continue;
        }
        merged.push(command.clone());
        if merged.len() >= MAX_COMMANDS - 1 {
            break;
        }
    }
    merged.push(entry(
        OTHER_COMMAND_ID,
        "Other commands",
        format!("{label} …"),
        "Any other command from this file that --help did not list.".to_owned(),
    ));
    merged
}

fn unlisted(request: &LocalCliHookRequestV1, compound: bool) -> Result<Vec<UnlistedCliV1>, ()> {
    let records = identify(&Request {
        command_text: &request.command,
        cwd: &request.cwd,
        home_dir: request.home_dir.as_deref(),
        user_home: &request.user_home,
        compound,
        env: &request.env,
        budget_ms: IDENTIFY_BUDGET_MS,
    })
    .map_err(|_| ())?;
    if records.iter().all(valid_unlisted) {
        Ok(records)
    } else {
        Err(())
    }
}

/// `matching_local_cli_grant`: the grant state for the launched CLI (`None`
/// when undecided or when it launches none), the CLI, and the decision's
/// capabilities; `Err` when no trustworthy answer exists.
fn grant(request: &LocalCliHookRequestV1, package: &Package) -> contained::Answer {
    let package = package.as_ref().map_err(|_| ())?;
    let Some(launch) = launch(request, package.as_ref())? else {
        return Ok((None, None, Value::Null));
    };
    let catalog = crate::local_cli_grant_op::command_catalog(&request.guard_home, &launch.cli_id)
        .map_err(|_| ())?;
    let command_id = if catalog.is_empty() {
        None
    } else {
        let tokens = match package {
            Some(found) => found.command_tokens.clone(),
            None => invocation_tokens(request, &launch)?,
        };
        Some(match_command_id(&tokens, &catalog))
    };
    let answer = crate::local_cli_grant_op::decide_allowed_launch(
        &request.guard_home,
        &launch.source,
        command_id.as_deref(),
    )
    .map_err(|_| ())?;
    if answer["cli_id"].as_str() != Some(launch.cli_id.as_str())
        || answer["identity_hash"].as_str() != Some(launch.identity_hash.as_str())
    {
        return Err(());
    }
    let state = match answer["state"].as_str() {
        Some("allowed") => Some("allowed"),
        Some("blocked") => Some("blocked"),
        Some("none") => None,
        _ => return Err(()),
    };
    Ok((state, Some(launch), answer["capabilities"].clone()))
}

/// The package script identity, else the first CLI one safe invocation
/// launches.
fn launch(
    request: &LocalCliHookRequestV1,
    package: Option<&PackageJsonScriptsV1>,
) -> Result<Option<Launch>, ()> {
    if let Some(found) = package {
        if let Some(identity) = &found.identity {
            return Ok(Some(Launch {
                cli_id: identity.cli_id.clone(),
                identity_hash: identity.identity_hash.clone(),
                name: identity.name.clone(),
                kind: "script".to_owned(),
                runner: None,
                source: found.source.clone(),
            }));
        }
    }
    Ok(unlisted(request, false)?
        .into_iter()
        .next()
        .map(|record| Launch {
            cli_id: record.cli_id,
            identity_hash: record.identity_hash,
            name: record.name,
            kind: record.kind,
            runner: record.runner,
            source: record.identity_source,
        }))
}

/// `command_tokens_for_invocation` past the package script branch: the first
/// segment's arguments after the runner or script name.
fn invocation_tokens(request: &LocalCliHookRequestV1, launch: &Launch) -> Result<Vec<String>, ()> {
    if request.command.trim().is_empty() {
        return Err(());
    }
    let model = parse_shell_command(
        &request.command,
        Some(std::path::Path::new(&request.cwd)),
        request.home_dir.as_deref().map(std::path::Path::new),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    Ok(model
        .segments
        .first()
        .map(|segment| command_tokens(&segment.arguments, launch))
        .unwrap_or_default())
}

/// `command_tokens_for_invocation` past the package script branch, for a
/// caller that derived the launch identity itself.
pub(crate) fn invocation_command_tokens(
    command: &str,
    cwd: &str,
    home_dir: Option<&str>,
    name: &str,
    kind: &str,
    runner: Option<&str>,
) -> Vec<String> {
    // The daemon reads an invocation only for a command its own rule found,
    // which is never blank; the model refuses blank text outright.
    if command.trim().is_empty() {
        return Vec::new();
    }
    let model = parse_shell_command(
        command,
        Some(std::path::Path::new(cwd)),
        home_dir.map(std::path::Path::new),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    model
        .segments
        .first()
        .map(|segment| tokens_for_identity(&segment.arguments, name, kind, runner))
        .unwrap_or_default()
}

/// Leading command-name tokens, after a runner's own arguments or a script's
/// own path, up to `MAX_DEPTH`.
pub(crate) fn command_tokens(arguments: &[String], launch: &Launch) -> Vec<String> {
    tokens_for_identity(
        arguments,
        &launch.name,
        &launch.kind,
        launch.runner.as_deref(),
    )
}

/// `command_tokens` for an identity the caller holds as plain fields.
fn tokens_for_identity(
    arguments: &[String],
    name: &str,
    kind: &str,
    runner: Option<&str>,
) -> Vec<String> {
    let arguments = match runner {
        Some(runner) => match runner_split(runner, arguments) {
            Some((_, rest)) => rest,
            None => return Vec::new(),
        },
        None if kind == "script"
            && arguments
                .first()
                .is_some_and(|first| python_path_name(first) == name) =>
        {
            &arguments[1..]
        }
        None => arguments,
    };
    arguments
        .iter()
        .take_while(|argument| !argument.starts_with('-') && is_command_name(argument))
        .take(MAX_DEPTH)
        .cloned()
        .collect()
}

/// `_COMMAND_NAME`: `^[A-Za-z][A-Za-z0-9_-]{0,40}$`.
fn is_command_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=41).contains(&bytes.len())
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
#[path = "local_cli_hook_op_tests.rs"]
pub(crate) mod tests;

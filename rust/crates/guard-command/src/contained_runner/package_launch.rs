//! One contained Node or TypeScript launch, read from the shim's own argv.
//!
//! The package shim hands over the manager and argv it received. The launch
//! intent is parsed here, beside the runner that consumes it, so the caller
//! makes one resident request and keeps no decision of its own. An
//! unsupported manager, a workspace that is not canonical or lies beneath a
//! system root, or anything other than exactly one local execution returns to
//! Guard review without running.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::{flows, RunnerLaunch};
use crate::command_launcher_floors::shlex_join;
use crate::package_intent_common::{LocalPackageExecutionEvidence, PackageIntent};
use crate::package_intent_parser::parse_package_intent;

const NODE_MANAGERS: [&str; 2] = ["npx", "bunx"];
const TYPESCRIPT_MANAGERS: [&str; 1] = ["npx"];
const VITEST_REFUSAL: &str =
    "HOL Guard refused uncontained Vitest execution: sandbox startup or enforcement proof failed";

/// What one contained Node launch answered.
#[derive(Debug, Default, PartialEq)]
pub struct NodeCommandOutcome {
    /// The contained run's typed result; `None` returns to Guard review.
    pub result: Option<Value>,
    /// Set when the launch must stop instead of returning to review: an
    /// allowed Vitest handoff from Guard's installed package shims that could
    /// not be contained would otherwise fall through and run uncontained.
    pub refusal: Option<String>,
}

/// Parses the launch intent the way the shim's own `parse_package_intent`
/// call did: canonical workspace, no home override, and only the caller's
/// `PATH` from its environment.
type ParseIntent<'a> =
    &'a dyn Fn(&str, &Path, Option<&BTreeMap<String, String>>) -> Option<PackageIntent>;
/// Runs the selected execution under containment.
type RunExecution<'a> = &'a dyn Fn(&flows::Launch<'_>, &Value) -> Result<Value, String>;

/// Contained local Node runner (`npx`/`bunx` test, lint or diagnostic tool).
pub fn execute_node_command(launch: &RunnerLaunch) -> NodeCommandOutcome {
    node_command(launch, &parse_launch_intent, &run_node)
}

/// Contained local TypeScript compiler check (`npx tsc`).
pub fn execute_typescript_command(launch: &RunnerLaunch) -> Option<Value> {
    typescript_command(launch, &parse_launch_intent, &run_typescript)
}

pub(super) fn node_command(
    launch: &RunnerLaunch,
    parse: ParseIntent<'_>,
    run: RunExecution<'_>,
) -> NodeCommandOutcome {
    let Some(execution) = single_local_execution(launch, &NODE_MANAGERS, parse) else {
        return NodeCommandOutcome::default();
    };
    match run(&launch.launch(), &execution.to_dict()) {
        Ok(result) => NodeCommandOutcome {
            result: Some(result),
            refusal: None,
        },
        Err(_) => NodeCommandOutcome {
            result: None,
            refusal: vitest_refusal(&execution, launch.shim_directory),
        },
    }
}

pub(super) fn typescript_command(
    launch: &RunnerLaunch,
    parse: ParseIntent<'_>,
    run: RunExecution<'_>,
) -> Option<Value> {
    let execution = single_local_execution(launch, &TYPESCRIPT_MANAGERS, parse)?;
    run(&launch.launch(), &execution.to_dict()).ok()
}

/// The one local execution `launch` names, when the manager is supported and
/// the workspace may be contained at all.
fn single_local_execution(
    launch: &RunnerLaunch,
    managers: &[&str],
    parse: ParseIntent<'_>,
) -> Option<LocalPackageExecutionEvidence> {
    let manager = flows::lowered(launch.manager);
    if !managers.contains(&manager.as_str()) {
        return None;
    }
    let workspace = flows::workspace_for(&launch.launch()).ok()?;
    let mut tokens = Vec::with_capacity(launch.argv.len() + 1);
    tokens.push(manager);
    tokens.extend(launch.argv.iter().cloned());
    let environment = launch
        .environment
        .get("PATH")
        .filter(|path| !path.is_empty())
        .map(|path| BTreeMap::from([("PATH".to_owned(), path.clone())]));
    let intent = parse(&shlex_join(&tokens), &workspace, environment.as_ref())?;
    if intent.local_executions.len() != 1 {
        return None;
    }
    intent.local_executions.into_iter().next()
}

fn parse_launch_intent(
    command_text: &str,
    workspace: &Path,
    environment: Option<&BTreeMap<String, String>>,
) -> Option<PackageIntent> {
    parse_package_intent(command_text, Some(workspace), None, None, environment)
}

fn run_node(launch: &flows::Launch, execution: &Value) -> Result<Value, String> {
    flows::run_node(launch, execution)?.to_value()
}

fn run_typescript(launch: &flows::Launch, execution: &Value) -> Result<Value, String> {
    flows::run_typescript(launch, execution)?.to_value()
}

fn vitest_refusal(
    execution: &LocalPackageExecutionEvidence,
    shim_directory: &Path,
) -> Option<String> {
    (execution.package_name.as_deref() == Some("vitest")
        && package_shim_handoff_active(shim_directory))
    .then(|| VITEST_REFUSAL.to_owned())
}

/// Whether this call came from Guard's installed package-shim boundary.
fn package_shim_handoff_active(shim_directory: &Path) -> bool {
    let Ok(canonical) = std::fs::canonicalize(shim_directory) else {
        return false;
    };
    canonical.file_name().is_some_and(|name| name == "bin")
        && canonical
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "package-shims")
}

#[cfg(test)]
#[path = "package_launch_tests.rs"]
mod tests;

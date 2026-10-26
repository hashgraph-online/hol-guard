//! `PackageReviewPlan` — resident op planning how a package review settles.
//!
//! Before it queues a `native_package_review`, the daemon asks the package
//! evaluator for a verdict on the command. This op owns everything up to that
//! evaluation: it reads the command (Copilot's `toolArgs` included), checks it
//! is one plain JS package-manager command, parses its install or exec intent,
//! proves the npm a plain npm install runs, and builds the request artifact the
//! evaluator reads. The caller evaluates the artifact and applies the verdict.
//!
//! A block verdict always applies: stopping a command runs nothing. Only an
//! npm install whose npm the resident proved may continue on an allow or a
//! script-free watch verdict.
//!
//! The edge reads an `npx` or `bunx` launch as a command review, not a package
//! review, because the package's own CLI is what runs. The package is still
//! fetched from the registry, so such a review is planned too, for a block
//! verdict only.

use std::path::Path;
use std::sync::LazyLock;

use guard_command::package_intent_common::build_package_request_artifact;
use guard_command::package_intent_parser::{parse_package_intent, runner_packages};
use guard_command::verified_npm;
use guard_contracts::{
    python_strip, PackageReviewPlanRequestV1, SupplyChainEvalResultV1,
    PACKAGE_AUTHORITY_REQUEST_SCHEMA, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD;
use crate::local_mcp_grant_identity::shlex_split;
use crate::package_authority_op::request_digest;

/// The review reason a package evaluation may settle before it is queued.
pub(crate) const PACKAGE_REVIEW_REASON: &str = "native_package_review";
/// The review reason the edge gives an `npx` or `bunx` launch.
pub(crate) const LAUNCH_REVIEW_REASON: &str = "native_command_review_required";
/// The launchers a command review is planned for.
const LAUNCHERS: [&str; 2] = ["npx", "bunx"];
/// The metadata key that tells the evaluator which npm the install runs.
const VERIFIED_NPM_VERSION_KEY: &str = "verified_npm_version";
/// The programs whose install and exec flows the evaluator reads.
const PACKAGE_MANAGERS: [&str; 6] = ["npm", "npx", "pnpm", "yarn", "bun", "bunx"];
const TOOL_INPUT_FIELDS: [&str; 2] = ["tool_input", "toolInput"];
const COMMAND_FIELDS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];

/// One plain command: no expansion, quoting, globbing, redirection or
/// chaining, and a word may not start with `~` or `=`, which shells expand to
/// paths. Agents trim install output with `2>&1 | tail -3`; these filters read
/// only the pipe: none takes a file operand, and a grep pattern may not start
/// with `-`, so it cannot name a pattern file.
static FILTERED_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    let word = r"[A-Za-z0-9@/._^:+,-][A-Za-z0-9@/._~^:=+,-]*";
    let pattern = r"[A-Za-z0-9@/._^:+,][A-Za-z0-9@/._~^:=+,-]*";
    let filter =
        format!(r"(?:tail|head)(?: +-[0-9]+| +-n *[0-9]+)?|grep(?: +-[iEFvcnw]+)* +{pattern}");
    Regex::new(&format!(
        r"^(?:(?P<command>{word}(?: +{word})*)(?: +2>&1)?(?P<filters>(?: *\| *(?:{filter}))*))$"
    ))
    .expect("filtered command pattern")
});

/// A package-manager command a review may settle.
#[derive(Debug, PartialEq)]
pub(crate) struct ReviewShape {
    pub(crate) tokens: Vec<String>,
    /// The programs the output is piped through, in first-seen order.
    pub(crate) filter_programs: Vec<String>,
}

/// Whether the native result is a review a package evaluation may settle.
pub(crate) fn settles(result: &Map<String, Value>) -> bool {
    result
        .get("reason_code")
        .and_then(Value::as_str)
        .is_some_and(|reason| [PACKAGE_REVIEW_REASON, LAUNCH_REVIEW_REASON].contains(&reason))
        && result.get("minimum_action").and_then(Value::as_str) == Some("review")
}

/// The shape of the command a review with this reason would settle. A
/// command review settles only an `npx` or `bunx` launch.
pub(crate) fn planned_shape(
    payload: &Map<String, Value>,
    review_reason: Option<&str>,
) -> Option<ReviewShape> {
    let shape = review_shape(payload)?;
    let launcher = LAUNCHERS.contains(&shape.tokens[0].as_str());
    // The evaluator judges one package, so a launch that fetches several, or
    // none it can name, is left to its review.
    if launcher && runner_packages(&shape.tokens).len() != 1 {
        return None;
    }
    let launch_only = review_reason == Some(LAUNCH_REVIEW_REASON);
    (!launch_only || launcher).then_some(shape)
}

/// The shape of the command a package review would settle, or `None` when
/// the evaluator is never asked and the review is queued as it stands.
pub(crate) fn review_shape(payload: &Map<String, Value>) -> Option<ReviewShape> {
    let command = review_command(payload)?;
    let shape = FILTERED_COMMAND.captures(python_strip(&command))?;
    let tokens: Vec<String> = shape
        .name("command")?
        .as_str()
        .split(' ')
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    if !PACKAGE_MANAGERS.contains(&tokens.first()?.as_str()) {
        return None;
    }
    let filters = shape.name("filters").map_or("", |filters| filters.as_str());
    Some(ReviewShape {
        tokens,
        filter_programs: filter_programs(filters),
    })
}

/// The first non-blank command text the hook names: the tool input, the
/// arguments, the payload itself, then Copilot's `toolArgs`, which arrives as
/// a map or as JSON text. This reads `toolArgs` for the evaluator only; the
/// review's approval binding keeps its own command lookup.
fn review_command(payload: &Map<String, Value>) -> Option<String> {
    let tool_input = TOOL_INPUT_FIELDS
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_object));
    let arguments = payload.get("arguments").and_then(Value::as_object);
    let tool_args = match payload.get("toolArgs") {
        Some(Value::Object(map)) => Some(map.clone()),
        Some(Value::String(text)) => match serde_json::from_str(text) {
            Ok(Value::Object(map)) => Some(map),
            _ => None,
        },
        _ => None,
    };
    [tool_input, arguments, Some(payload)]
        .into_iter()
        .flatten()
        .find_map(command_field)
        .or_else(|| tool_args.as_ref().and_then(command_field))
}

fn command_field(candidate: &Map<String, Value>) -> Option<String> {
    COMMAND_FIELDS.iter().find_map(|key| {
        candidate
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !python_strip(value).is_empty())
            .map(str::to_owned)
    })
}

fn filter_programs(filters: &str) -> Vec<String> {
    let mut programs: Vec<String> = Vec::new();
    for segment in filters.split('|') {
        if let Some(program) = segment.split_whitespace().next() {
            if !programs.iter().any(|seen| seen == program) {
                programs.push(program.to_owned());
            }
        }
    }
    programs
}

/// The request artifact for the review's command and whether the evaluator's
/// verdict may let it continue.
fn plan(
    payload: &Map<String, Value>,
    harness: &str,
    workspace: &Path,
    home_dir: Option<&Path>,
    review_reason: Option<&str>,
) -> Option<(Value, bool)> {
    let shape = planned_shape(payload, review_reason)?;
    let launch_only = review_reason == Some(LAUNCH_REVIEW_REASON);
    let tokens = &shape.tokens;
    let intent = parse_package_intent(
        &crate::mcp_proxy_shlex::join(tokens),
        Some(workspace),
        home_dir,
        None,
        None,
    )?;
    // The evaluator reads the redacted command, so it must be the command
    // that runs, token for token.
    if !matches!(intent.intent_kind, "install" | "execute")
        || &intent.command_tokens != tokens
        || shlex_split(&intent.redacted_command).as_ref() != Some(tokens)
    {
        return None;
    }
    let mut artifact =
        build_package_request_artifact(harness, &intent, "hol-guard.toml", "project");
    // The npm layout proof is unproven off Unix, so Windows applies blocks
    // only, as does a command review.
    let version = (!cfg!(windows)
        && !launch_only
        && intent.package_manager == "npm"
        && intent.intent_kind == "install"
        && intent.local_executions.is_empty())
    .then(|| npm_proof(payload, workspace, &shape.filter_programs))
    .flatten();
    if let (Some(version), Value::Object(metadata)) = (&version, &mut artifact.metadata) {
        metadata.insert(
            VERIFIED_NPM_VERSION_KEY.to_owned(),
            Value::String(version.clone()),
        );
    }
    Some((artifact.to_wire(), version.is_some()))
}

/// The npm version the install runs, when its `PATH` and config files prove
/// it and every output filter resolves outside the workspace.
fn npm_proof(
    payload: &Map<String, Value>,
    workspace: &Path,
    programs: &[String],
) -> Option<String> {
    let environment =
        verified_npm::ExecutionEnvironment::from_value(payload.get(EXECUTION_ENVIRONMENT_FIELD));
    let version = verified_npm::verified_npm_version(&environment, workspace)?;
    verified_npm::filters_outside_workspace(programs, &environment, workspace).then_some(version)
}

fn invalid() -> String {
    "native_package_review_plan_invalid".to_owned()
}

pub(crate) fn evaluate_package_review_plan(
    request: &PackageReviewPlanRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_review_plan_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() || request.guard_home.is_empty() || request.harness.is_empty()
    {
        return Err(invalid());
    }
    let workspace = Path::new(&request.workspace);
    if !workspace.is_absolute() {
        return Err(invalid());
    }
    let planned = request.payload.as_object().and_then(|payload| {
        plan(
            payload,
            &request.harness,
            workspace,
            request.home_dir.as_deref().map(Path::new),
            request.review_reason.as_deref(),
        )
    });
    let (artifact, may_allow) = planned.unwrap_or((Value::Null, false));
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(json!({"artifact": artifact, "may_allow": may_allow})),
    })
}

#[cfg(test)]
#[path = "package_review_plan_op_tests.rs"]
mod tests;

//! `CodexToolOutput` resident op.
//!
//! Rust owns every verdict about Codex tool-output commands: read-only source
//! inspection, secret-like source names, git pathspec identities, local content
//! reads and focused pytest. Python sends the command text and observed facts
//! and relays the answer. A malformed or oversized request is an error result
//! with `allowed = false`; nothing here falls back to Python.

use std::collections::BTreeMap;

use guard_command::{review_codex_tool_output, Ctx, GitCheck, GitRun, InspectionHost};
use guard_contracts::{
    CodexToolOutputActionV1, CodexToolOutputFactsV1, CodexToolOutputRequestV1,
    CodexToolOutputResultV1, GitExecutionSafetyCheckV1, GitExecutionSafetyRequestV1,
    CODEX_TOOL_OUTPUT_MAX_BYTES, CODEX_TOOL_OUTPUT_REQUEST_SCHEMA, CODEX_TOOL_OUTPUT_RESULT_SCHEMA,
    GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

use super::context_digest_json::write_canonical_json_with_limit;
use crate::codex_tool_output_git::run_pathspec_git;

const INVALID: &str = "native_codex_tool_output_invalid";
const SCHEMA_MISMATCH: &str = "native_codex_tool_output_schema_mismatch";
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_COMMANDS: usize = 256;
const MAX_ENVIRONMENT: usize = 128;
const MAX_GROUPS: usize = 256;

struct ResidentInspectionHost<'a> {
    facts: &'a CodexToolOutputFactsV1,
}

impl InspectionHost for ResidentInspectionHost<'_> {
    fn env(&self, name: &str) -> Option<String> {
        self.facts.environment.get(name).cloned()
    }

    fn git_executable(&self) -> Option<String> {
        self.facts.git_executable.clone()
    }

    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, arguments: &[String]) -> bool {
        let check = match check {
            GitCheck::ResolveBinary => GitExecutionSafetyCheckV1::ResolveBinary,
            GitCheck::ConfigEnvironmentClean => GitExecutionSafetyCheckV1::ConfigEnvironmentClean,
            GitCheck::StatusArguments => GitExecutionSafetyCheckV1::StatusArguments,
            GitCheck::StatusConfig => GitExecutionSafetyCheckV1::StatusConfig,
        };
        let request = GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            check,
            cwd: cwd.unwrap_or(&self.facts.home).to_owned(),
            home: self.facts.home.clone(),
            account_home: self.facts.account_home.clone(),
            groups: self.facts.groups.clone(),
            environment: self.facts.environment.clone(),
            git_binary: None,
            git_path: None,
            arguments: arguments.to_vec(),
            branch: None,
            reference: None,
        };
        crate::git_execution_safety_checks::decide(&request).allowed
    }

    fn run_git(&self, git: &str, args: &[String], cwd: &str) -> GitRun {
        run_pathspec_git(git, args, cwd, &self.facts.environment)
    }
}

fn request_digest(request: &CodexToolOutputRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, CODEX_TOOL_OUTPUT_MAX_BYTES)
        .map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

fn text_is_bounded(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES
}

fn path_is_bounded(value: &str) -> bool {
    text_is_bounded(value) && !value.contains('\0')
}

fn option_path_is_bounded(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(path_is_bounded)
}

fn action_is_bounded(action: &CodexToolOutputActionV1) -> bool {
    use CodexToolOutputActionV1 as Action;
    match action {
        Action::ReadOnlyInspection(scope) => {
            text_is_bounded(&scope.command)
                && option_path_is_bounded(&scope.cwd)
                && option_path_is_bounded(&scope.home_dir)
        }
        Action::PostToolReadOnly(scope) => {
            scope.commands.len() <= MAX_COMMANDS
                && scope
                    .commands
                    .iter()
                    .all(|command| text_is_bounded(command))
                && option_path_is_bounded(&scope.cwd)
                && option_path_is_bounded(&scope.home_dir)
        }
        Action::SecretLikeSourceName(scope) => {
            text_is_bounded(&scope.command)
                && option_path_is_bounded(&scope.cwd)
                && option_path_is_bounded(&scope.home_dir)
        }
        Action::GitPathspecIdentity(scope)
        | Action::LocalContentTail(scope)
        | Action::GitMetadata(scope) => {
            text_is_bounded(&scope.command) && option_path_is_bounded(&scope.cwd)
        }
        Action::ReadsEnvironmentPipeline(text) | Action::FocusedPytest(text) => {
            text_is_bounded(&text.command)
        }
    }
}

fn environment_is_bounded(environment: &BTreeMap<String, String>) -> bool {
    environment.len() <= MAX_ENVIRONMENT
        && environment
            .iter()
            .all(|(key, value)| key.len() <= 256 && path_is_bounded(value))
}

fn request_is_bounded(request: &CodexToolOutputRequestV1) -> bool {
    let facts = &request.facts;
    request.request_id.len() <= 128
        && action_is_bounded(&request.action)
        && path_is_bounded(&facts.process_cwd)
        && path_is_bounded(&facts.home)
        && option_path_is_bounded(&facts.account_home)
        && option_path_is_bounded(&facts.git_executable)
        && facts.groups.len() <= MAX_GROUPS
        && environment_is_bounded(&facts.environment)
}

pub(crate) fn evaluate_codex_tool_output_request(
    request: &CodexToolOutputRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, allowed, value) = if request.schema != CODEX_TOOL_OUTPUT_REQUEST_SCHEMA {
        ("error", SCHEMA_MISMATCH, false, None)
    } else if !request_is_bounded(request) {
        ("error", INVALID, false, None)
    } else {
        let host = ResidentInspectionHost {
            facts: &request.facts,
        };
        let ctx = Ctx::new(&host, &request.facts.process_cwd, &request.facts.home);
        let outcome = review_codex_tool_output(&ctx, &request.action);
        ("ok", "ok", outcome.allowed, outcome.value)
    };
    crate::encode_response(&CodexToolOutputResultV1 {
        schema: CODEX_TOOL_OUTPUT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        allowed,
        value,
    })
}

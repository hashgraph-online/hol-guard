//! `secret_file_request_services/shell_initial_risk.py`: the early
//! high-confidence shell risk classification (`initial_shell_risk_match`,
//! `_direct_shell_risk_match`, `_github_shell_risk_match`,
//! `_missing_workspace_read_only_search`, `_unwrap_search_invocation` and
//! `_search_command_executes_unreviewed_code`).

// Consumed by the dispatcher wiring.
#![allow(dead_code)]

use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::codex_output_source_paths::py_path;
use crate::command_model::CanonicalCommand;
use crate::sfrs_destructive::contains_shell_credential_exfiltration;
use crate::sfrs_destructive_classifier::looks_destructive_shell_command;
use crate::sfrs_developer_inspection::read_only_lookup_search_args_are_safe;
use crate::sfrs_dispatcher_request::ToolActionRequestMatch;
use crate::sfrs_encoded_commands::{contains_encoded_or_encrypted_shell_command, EncodedScan};
use crate::sfrs_gh_actions_read::is_nonexecuting_github_actions_read_workflow;
use crate::sfrs_gh_ephemeral_body::gh_pr_create_uses_safe_ephemeral_body;
use crate::sfrs_gh_pr_expansion::{
    gh_pr_create_body_has_shell_command_substitution, gh_pr_create_has_active_shell_expansion,
    gh_pr_edit_has_shell_command_substitution,
};
use crate::sfrs_interpreter_trust::contains_shell_network_file_upload;
use crate::sfrs_self_approval::{
    is_guard_approval_mutation_command, SELF_APPROVAL_ACTION_CLASS, SELF_APPROVAL_REASON,
};
use crate::shell_secret_reads::assess_shell_reads;

pub(crate) const LOCAL_SCRIPT_ACTION_CLASS: &str = "local script execution shell command";
pub(crate) const LOCAL_SECRET_READ_ACTION_CLASS: &str = "local secret read shell command";
const READ_ONLY_SEARCH_COMMANDS: &[&str] = &["grep", "egrep", "fgrep", "rg", "ag", "ack"];
const LOCAL_CODE_REASON: &str =
    "This command executes local or incompletely inspected code. Review it before execution.";

/// `CommandExtensionInteractionMatch`: the action class and reason of the
/// command-extension interaction that takes priority.
#[derive(Clone, Debug)]
pub(crate) struct InteractionMatch {
    pub action_class: String,
    pub reason: String,
}

/// The keyword arguments the three matchers share.
pub(crate) struct RiskInputs<'a> {
    pub tool_name: &'a str,
    pub normalized_tool_name: &'a str,
    pub command_text: &'a str,
    pub detection_command_text: &'a str,
    pub raw_command_text: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub home_dir: Option<&'a Path>,
    pub canonical_command: &'a CanonicalCommand,
    pub interpreter_executable_identities: &'a [Value],
    pub ctx: &'a Ctx<'a>,
}

impl RiskInputs<'_> {
    /// A match that carries the canonical command and interpreter evidence.
    fn request(&self, action_class: &str, reason: &str) -> ToolActionRequestMatch {
        ToolActionRequestMatch {
            canonical_command: Some(self.canonical_command.clone()),
            interpreter_executable_identities: self.interpreter_executable_identities.to_vec(),
            ..ToolActionRequestMatch::new(
                self.tool_name,
                self.normalized_tool_name,
                self.command_text,
                action_class,
                reason,
            )
        }
    }

    fn reviewed_script(&self, script_identity: Option<String>) -> ToolActionRequestMatch {
        ToolActionRequestMatch {
            guard_default_action: Some("require-reapproval".to_owned()),
            reason_code: Some("shell_local_script_execution_review".to_owned()),
            script_read_identity_sha256: script_identity,
            ..self.request(LOCAL_SCRIPT_ACTION_CLASS, LOCAL_CODE_REASON)
        }
    }
}

/// `initial_shell_risk_match`: `(handled, match)`.
pub(crate) fn initial_shell_risk_match(
    inputs: &RiskInputs,
    extension_interaction: Option<&InteractionMatch>,
) -> (bool, Option<ToolActionRequestMatch>) {
    let matched = direct_shell_risk_match(inputs);
    let deferred_review_match = matched.clone().filter(|found| {
        found.action_class == LOCAL_SCRIPT_ACTION_CLASS
            || found.action_class == LOCAL_SECRET_READ_ACTION_CLASS
    });
    if matched.is_some() && deferred_review_match.is_none() {
        return (true, matched);
    }
    if let Some(priority) = extension_interaction {
        return (
            true,
            Some(inputs.request(&priority.action_class, &priority.reason)),
        );
    }
    let (detection, raw, ctx) = (
        inputs.detection_command_text,
        inputs.raw_command_text,
        inputs.ctx,
    );
    if gh_pr_create_uses_safe_ephemeral_body(detection, ctx)
        && raw.is_none_or(|raw| raw == detection || gh_pr_create_uses_safe_ephemeral_body(raw, ctx))
    {
        return (deferred_review_match.is_none(), deferred_review_match);
    }
    if let Some(found) = github_shell_risk_match(inputs) {
        return (true, Some(found));
    }
    let py_cwd = inputs.cwd.map(py_path);
    if is_nonexecuting_github_actions_read_workflow(detection, py_cwd.as_ref(), ctx)
        && raw.is_none_or(|raw| {
            raw == detection
                || is_nonexecuting_github_actions_read_workflow(raw, py_cwd.as_ref(), ctx)
        })
    {
        return (deferred_review_match.is_none(), deferred_review_match);
    }
    // The generic execution floor stays available after more specific
    // policies classify the command.
    (false, deferred_review_match)
}

/// `_missing_workspace_read_only_search`.
pub(crate) fn missing_workspace_read_only_search(
    cwd: Option<&Path>,
    command: &CanonicalCommand,
    ctx: &Ctx,
) -> bool {
    let cwd_exists = cwd.is_some_and(|cwd| pyfs::exists(&py_path(cwd)).unwrap_or(false));
    if cwd_exists
        || !command.redirects.is_empty()
        || !command.embedded_commands.is_empty()
        || !command.wrapper_chain.is_empty()
        || command.segments.len() != 1
    {
        return false;
    }
    let segment = &command.segments[0];
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    if !segment.environment_names.is_empty() || segment.pipeline_index != 0 {
        return false;
    }
    if executable.contains('/') || executable.contains('\\') || executable.starts_with('.') {
        return false;
    }
    let name = PyPath::new(executable).name().to_lowercase();
    if !READ_ONLY_SEARCH_COMMANDS.contains(&name.as_str()) {
        return false;
    }
    read_only_lookup_search_args_are_safe(&name, &segment.arguments, None, ctx)
}

/// `_unwrap_search_invocation`: strip `command`/`exec` prefixes so
/// preprocessor flags stay visible.
pub(crate) fn unwrap_search_invocation(
    executable: Option<&str>,
    args: &[String],
) -> (Option<String>, Vec<String>) {
    let Some(executable) = executable else {
        return (None, args.to_vec());
    };
    let mut name = PyPath::new(executable).name().to_lowercase();
    let mut remaining: Vec<String> = args.to_vec();
    for _ in 0..8 {
        if name != "command" && name != "exec" {
            return (Some(name), remaining);
        }
        if name == "command" {
            while remaining.first().is_some_and(|token| token == "-p") {
                remaining.remove(0);
            }
            if remaining.first().is_some_and(|token| token == "--") {
                remaining.remove(0);
            } else if remaining
                .first()
                .is_some_and(|token| token == "-v" || token == "-V")
            {
                return (Some(name), remaining);
            }
        } else {
            while let Some(token) = remaining.first().cloned() {
                if token == "--" {
                    remaining.remove(0);
                    break;
                }
                if token == "-a" {
                    remaining = if remaining.len() > 1 {
                        remaining[2..].to_vec()
                    } else {
                        Vec::new()
                    };
                    continue;
                }
                if token.starts_with("-a") && token.chars().count() > 2 {
                    remaining.remove(0);
                    continue;
                }
                if token.chars().count() > 1
                    && token.starts_with('-')
                    && token.chars().skip(1).all(|flag| flag == 'c' || flag == 'l')
                {
                    remaining.remove(0);
                    continue;
                }
                break;
            }
        }
        if remaining.is_empty() {
            return (None, remaining);
        }
        name = PyPath::new(&remaining[0]).name().to_lowercase();
        remaining.remove(0);
    }
    (None, remaining)
}

/// `_search_command_executes_unreviewed_code`.
pub(crate) fn search_command_executes_unreviewed_code(
    command: &CanonicalCommand,
    ctx: &Ctx,
) -> bool {
    if !command.redirects.is_empty()
        || !command.embedded_commands.is_empty()
        || command.segments.len() != 1
    {
        return false;
    }
    let segment = &command.segments[0];
    if !segment.environment_names.is_empty() || segment.pipeline_index != 0 {
        return false;
    }
    let (name, args) = unwrap_search_invocation(segment.executable.as_deref(), &segment.arguments);
    let Some(name) = name else {
        return true;
    };
    if !READ_ONLY_SEARCH_COMMANDS.contains(&name.as_str()) {
        return false;
    }
    !read_only_lookup_search_args_are_safe(&name, &args, None, ctx)
}

/// `_direct_shell_risk_match`.
pub(crate) fn direct_shell_risk_match(inputs: &RiskInputs) -> Option<ToolActionRequestMatch> {
    let (detection, cwd, home_dir, ctx) = (
        inputs.detection_command_text,
        inputs.cwd,
        inputs.home_dir,
        inputs.ctx,
    );
    if is_guard_approval_mutation_command(detection) {
        return Some(ToolActionRequestMatch {
            canonical_command: Some(inputs.canonical_command.clone()),
            ..ToolActionRequestMatch::new(
                inputs.tool_name,
                inputs.normalized_tool_name,
                inputs.command_text,
                SELF_APPROVAL_ACTION_CLASS,
                SELF_APPROVAL_REASON,
            )
        });
    }
    let destructive = |text: &str, text_cwd: Option<&Path>, text_home: Option<&Path>| {
        looks_destructive_shell_command(text, text_cwd, text_home, ctx)
    };
    let scan = EncodedScan {
        cwd,
        home_dir,
        allowed_roots: None,
        visited_script_paths: &[],
        destructive: &destructive,
    };
    if contains_encoded_or_encrypted_shell_command(detection, &scan, 0) {
        return Some(inputs.request(
            "encoded or encrypted shell command",
            "Guard treats encoded or encrypted decode-and-exec shell flows as sensitive and inspects bounded payloads in-process without executing them during evaluation.",
        ));
    }
    if contains_shell_credential_exfiltration(detection, cwd, home_dir, None, 0, &[]) {
        return Some(inputs.request(
            "credential exfiltration shell command",
            "Guard treats shell scripts that combine credential-looking material with outbound HTTP posting as sensitive because they can exfiltrate local secrets before the user confirms the action.",
        ));
    }
    if contains_shell_network_file_upload(detection, cwd, home_dir, None) {
        return Some(inputs.request(
            "shell file upload command",
            "Guard treats shell-driven local file uploads as sensitive because they can exfiltrate local file contents to a network endpoint before the user confirms the action.",
        ));
    }
    let assessment = assess_shell_reads(detection, cwd, home_dir);
    if !assessment.sensitive_paths.is_empty() {
        return Some(ToolActionRequestMatch {
            guard_default_action: Some("require-reapproval".to_owned()),
            reason_code: Some("shell_local_secret_read".to_owned()),
            script_read_identity_sha256: Some(assessment.identity_sha256()),
            ..inputs.request(
                LOCAL_SECRET_READ_ACTION_CLASS,
                "This command or a local script reads a protected credential file. Review the read before execution.",
            )
        });
    }
    let search_executes_code =
        search_command_executes_unreviewed_code(inputs.canonical_command, ctx);
    if assessment.requires_review() {
        if !search_executes_code
            && missing_workspace_read_only_search(cwd, inputs.canonical_command, ctx)
        {
            return None;
        }
        return Some(inputs.reviewed_script(Some(assessment.identity_sha256())));
    }
    if search_executes_code {
        return Some(inputs.reviewed_script(None));
    }
    None
}

/// `_github_shell_risk_match`.
pub(crate) fn github_shell_risk_match(inputs: &RiskInputs) -> Option<ToolActionRequestMatch> {
    let detection = inputs.detection_command_text;
    let mut texts = vec![detection];
    if let Some(raw) = inputs.raw_command_text.filter(|raw| !raw.is_empty()) {
        if raw != detection {
            texts.push(raw);
        }
    }
    let (action_class, reason) = if texts
        .iter()
        .any(|text| gh_pr_create_body_has_shell_command_substitution(text, 0))
    {
        (
            "GitHub PR body shell substitution",
            "Guard treats command substitution inside `gh pr create --body` as sensitive because shell backticks or `$()` run before GitHub receives the PR text. Use single quotes around Markdown code spans or `--body-file` for PR descriptions.",
        )
    } else if texts
        .iter()
        .any(|text| gh_pr_edit_has_shell_command_substitution(text))
    {
        (
            "GitHub PR edit shell substitution",
            "Guard reviews shell substitution around `gh pr edit` because it can execute local commands before GitHub receives the pull-request metadata.",
        )
    } else if texts
        .iter()
        .any(|text| gh_pr_create_has_active_shell_expansion(text, 0))
    {
        (
            "GitHub PR dynamic content",
            "Guard reviews `gh pr create` arguments with active shell expansion because environment variables or command substitutions can publish local secrets as pull-request metadata. Quote literal `$` and backticks with single quotes to keep static PR creation prompt-free.",
        )
    } else {
        return None;
    };
    Some(inputs.request(action_class, reason))
}

//! `is_explicitly_benign_tool_action_request`
//! (`runtime/secret_file_request_services/benign_requests.py`).
//!
//! The recognizer composes the already ported classifiers. Every input that
//! cannot be computed here (a host service the resident does not provide, an
//! unavailable control catalog, an unresolvable path) means "not benign".

use std::path::Path;

use serde_json::Value;

use crate::benign_request_api::ToolActionControls;
use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, PyPath};
use crate::codex_output_source_paths::py_path;
use crate::direct_vitest::direct_local_typescript_execution_context;
use crate::extension_control::{resolve_extension_controls, ControlSurface};
use crate::github_capability_contract::GitHubCommandAssessment;
use crate::github_capability_interaction::github_capability_requires_confirmation;
use crate::github_command_capabilities::classify_github_cli;
use crate::hook_adapter_value::OValue;
use crate::native_command_catalog::packaged_command_catalog;
use crate::package_intent_common::candidate_command_texts;
use crate::sfrs_agent_guidance::is_benign_agent_guidance_read;
use crate::sfrs_constants::SHELL_TOOL_NAMES;
use crate::sfrs_destructive::shell_command_names_from_parts;
use crate::sfrs_developer_graph::GraphInputs;
use crate::sfrs_developer_routines::{
    looks_like_safe_cli_metadata_command, looks_like_safe_compound_developer_inspection,
    looks_like_safe_kubernetes_inventory_command, safe_dependency_symlink_execution_context,
};
use crate::sfrs_gh_actions_read::is_nonexecuting_github_actions_read_workflow;
use crate::sfrs_gh_ephemeral_body::gh_pr_create_uses_safe_ephemeral_body;
use crate::sfrs_gh_service::classify_github_shell_capabilities;
use crate::sfrs_git_audit::is_read_only_git_ancestry_audit;
use crate::sfrs_git_routines::{
    looks_like_safe_git_branch_switch_command, looks_like_safe_git_status_command,
    looks_like_safe_standalone_git_routine,
};
use crate::sfrs_interpreter_identity::{python_interpreter_executable_identities, IdentityInputs};
use crate::sfrs_interpreter_observers::{
    looks_like_benign_interpreter_wait, looks_like_benign_interpreter_wait_chain,
    looks_like_read_only_interpreter_command, looks_like_safe_read_only_lookup_command,
};
use crate::sfrs_quote_tokens::{shell_token_segments, shell_tokens_preserving_quote_context};
use crate::sfrs_requests::normalize_tool_name;
use crate::sfrs_routine_dirs::is_safe_routine_directory_creation;
use crate::sfrs_routine_setup::{is_safe_codex_memory_registry_search, is_safe_git_worktree_add};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};
use crate::sfrs_shlex::{split_with, STRICT_LEXER};
use crate::sfrs_static_safety::without_safe_inspection_redirections;
use crate::sfrs_substitution::github_argument_token_has_untrusted_expansion;
use crate::shell_command_wrappers::normalize_transparent_shell_command;
use crate::shell_secret_reads::assess_shell_reads;

/// Everything the recognizer reads from outside the tool call.
pub(crate) struct ToolActionInputs<'a> {
    pub cwd: Option<&'a Path>,
    pub home_dir: Option<&'a Path>,
    pub ctx: &'a Ctx<'a>,
    /// `None` is "no snapshot is active": no control can block.
    pub controls: Option<&'a ToolActionControls>,
}

/// `is_explicitly_benign_tool_action_request`.
pub(crate) fn is_explicitly_benign_tool_action_request(
    tool_name: &OValue,
    arguments: &Value,
    inputs: &ToolActionInputs,
) -> bool {
    let Some(name) = normalize_tool_name(tool_name) else {
        return false;
    };
    if !SHELL_TOOL_NAMES.contains(&name.as_str()) {
        return false;
    }
    let mut found_benign_candidate = false;
    for command_text in candidate_command_texts(arguments) {
        match command_verdict(&command_text, inputs) {
            Verdict::Benign => found_benign_candidate = true,
            Verdict::Skip => {}
            Verdict::Refuse => return false,
        }
    }
    found_benign_candidate
}

enum Verdict {
    Benign,
    Skip,
    Refuse,
}

fn command_verdict(raw_command_text: &str, inputs: &ToolActionInputs) -> Verdict {
    let (cwd, home_dir, ctx) = (inputs.cwd, inputs.home_dir, inputs.ctx);
    if assess_shell_reads(raw_command_text, cwd, home_dir).requires_review() {
        return Verdict::Refuse;
    }
    if !interpreters_are_trusted(raw_command_text, inputs) {
        return Verdict::Refuse;
    }
    let normalization = normalize_transparent_shell_command(raw_command_text, cwd, home_dir);
    let command_text = normalization.normalized_command;
    if !normalization.wrapper_chain.is_empty() {
        let raw_assessment = classify_github_shell_capabilities(raw_command_text, home_dir, ctx);
        if raw_assessment
            .as_ref()
            .is_some_and(github_capability_requires_confirmation)
        {
            return Verdict::Refuse;
        }
        let invokes_guard = iter_shell_command_segments(&split_shell_parts(&command_text))
            .iter()
            .any(|segment| {
                shell_segment_primary_command(segment).0.as_deref() == Some("hol-guard")
            });
        if invokes_guard && command_text != raw_command_text {
            return Verdict::Refuse;
        }
    }
    let stripped = py_strip(&command_text);
    if stripped.is_empty() {
        return Verdict::Skip;
    }
    let py_cwd = cwd.map(py_path);
    if is_nonexecuting_github_actions_read_workflow(stripped, py_cwd.as_ref(), ctx)
        || gh_pr_create_uses_safe_ephemeral_body(stripped, ctx)
    {
        return Verdict::Benign;
    }
    let assessment = classify_github_shell_capabilities(stripped, home_dir, ctx);
    if assessment
        .as_ref()
        .is_some_and(github_capability_requires_confirmation)
    {
        return Verdict::Refuse;
    }
    if let Some(found) = &assessment {
        if controls_block(found, inputs.controls) {
            return Verdict::Refuse;
        }
    }
    if quote_aware_direct_github_read_is_safe(stripped, assessment.is_some()) {
        return Verdict::Benign;
    }
    if home_dir.is_some_and(|home| is_benign_agent_guidance_read(stripped, cwd, home)) {
        return Verdict::Benign;
    }
    let parts = split_shell_parts(stripped);
    if parts.is_empty() {
        return Verdict::Refuse;
    }
    if recognized_command(stripped, &parts, inputs) {
        Verdict::Benign
    } else {
        Verdict::Refuse
    }
}

/// Every Python interpreter the command can launch is a trusted one.
fn interpreters_are_trusted(command_text: &str, inputs: &ToolActionInputs) -> bool {
    let cwd = inputs.cwd.map(py_path);
    let home = inputs.home_dir.map(py_path);
    let identity = IdentityInputs {
        cwd: cwd.as_ref(),
        home_dir: home.as_ref(),
        environment: None,
        workspace_root: None,
        execution_context: None,
    };
    python_interpreter_executable_identities(command_text, &identity, 0, inputs.ctx)
        .iter()
        .all(|evidence| {
            matches!(
                evidence.get("trust").and_then(Value::as_str),
                Some("trusted_guard" | "trusted_system")
            )
        })
}

/// A GitHub command whose permission a control disables is not benign.
fn controls_block(
    assessment: &GitHubCommandAssessment,
    controls: Option<&ToolActionControls>,
) -> bool {
    let Some(controls) = controls else {
        return false;
    };
    let Ok(catalog) = packaged_command_catalog() else {
        return true;
    };
    let mut extension_ids = Vec::new();
    let mut permission_ids = Vec::new();
    for capability in &assessment.capabilities {
        if let Some(permission) = catalog.permission_for_typed_capability(capability.as_str()) {
            extension_ids.push(permission.extension_id.clone());
            permission_ids.push(permission.permission_id.clone());
        }
    }
    extension_ids.sort();
    extension_ids.dedup();
    permission_ids.sort();
    permission_ids.dedup();
    resolve_extension_controls(
        &controls.layers,
        Some(&*catalog),
        &extension_ids,
        &permission_ids,
        ControlSurface::CommandEvaluation,
        &[],
        controls.authority_failure,
    )
    .blocked
}

/// `_quote_aware_direct_github_read_is_safe`: one plain `gh` invocation whose
/// arguments carry no untrusted shell expansion.
pub(crate) fn quote_aware_direct_github_read_is_safe(
    command_text: &str,
    has_assessment: bool,
) -> bool {
    if !has_assessment {
        return false;
    }
    let segments = shell_token_segments(&shell_tokens_preserving_quote_context(command_text));
    let [segment] = segments.as_slice() else {
        return false;
    };
    if segment.first().is_none_or(|token| token.raw != "gh") {
        return false;
    }
    let plain: Vec<String> = segment.iter().map(|token| token.plain.clone()).collect();
    let (name, index) = shell_segment_primary_command(&plain);
    if name.as_deref() != Some("gh") || index != Some(0) {
        return false;
    }
    without_safe_inspection_redirections(&plain[1..]).is_some()
        && !segment[1..]
            .iter()
            .any(|token| github_argument_token_has_untrusted_expansion(&token.raw))
}

/// `_looks_like_safe_existence_probe`: `test -e PATH && echo exists || echo
/// absent` for a literal path below the working or home directory.
pub(crate) fn looks_like_safe_existence_probe(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let Ok(parts) = split_with(STRICT_LEXER, command_text) else {
        return false;
    };
    let [test, flag, target, tail @ ..] = parts.as_slice() else {
        return false;
    };
    if test != "test" || flag != "-e" || parts.len() != 9 {
        return false;
    }
    if tail != ["&&", "echo", "exists", "||", "echo", "absent"] {
        return false;
    }
    if target
        .chars()
        .any(|ch| matches!(ch, '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return false;
    }
    let Some(candidate) = ctx.expanduser(target) else {
        return false;
    };
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        let Some(cwd) = cwd else {
            return false;
        };
        if candidate.components().iter().any(|part| part == "..") {
            return false;
        }
        py_path(cwd).join(&candidate.to_string())
    };
    let Some(resolved) = pyfs::resolve(&candidate) else {
        return false;
    };
    let mut roots: Vec<PyPath> = Vec::new();
    for root in [cwd, home_dir].into_iter().flatten() {
        let Some(root) = pyfs::resolve(&py_path(root)) else {
            return false;
        };
        roots.push(root);
    }
    roots
        .iter()
        .any(|root| resolved.relative_to(root).is_some())
}

/// The ordered recognizers that follow the GitHub and guidance checks.
fn recognized_command(command: &str, parts: &[String], inputs: &ToolActionInputs) -> bool {
    let (cwd, home_dir, ctx) = (inputs.cwd, inputs.home_dir, inputs.ctx);
    let names = shell_command_names_from_parts(parts);
    if looks_like_benign_interpreter_wait(command, parts, &names)
        || looks_like_benign_interpreter_wait_chain(command, parts)
        || looks_like_read_only_interpreter_command(command, parts, &names)
        || looks_like_safe_read_only_lookup_command(command, parts, home_dir, ctx)
        || looks_like_safe_existence_probe(command, cwd, home_dir, ctx)
        || is_safe_routine_directory_creation(command, cwd, home_dir)
        || looks_like_safe_cli_metadata_command(command, parts, cwd, ctx, &[])
        || looks_like_safe_git_branch_switch_command(command, parts, cwd, ctx)
        || looks_like_safe_git_status_command(command, parts, cwd, ctx)
        || looks_like_safe_standalone_git_routine(command, cwd, home_dir, ctx)
    {
        return true;
    }
    if let Some(home) = home_dir {
        if home_recognized(command, home, inputs) {
            return true;
        }
    }
    looks_like_safe_kubernetes_inventory_command(command, parts, cwd, ctx)
}

/// Recognizers that need a home directory.
fn home_recognized(command: &str, home: &Path, inputs: &ToolActionInputs) -> bool {
    let (cwd, ctx) = (inputs.cwd, inputs.ctx);
    if is_safe_git_worktree_add(command, cwd, home, ctx)
        || is_safe_codex_memory_registry_search(command, cwd, home, ctx)
    {
        return true;
    }
    if ctx.host.direct_tool_authority().is_some_and(|authority| {
        direct_local_typescript_execution_context(command, cwd, home, authority).is_some()
    }) {
        return true;
    }
    if safe_dependency_symlink_execution_context(command, cwd, home, ctx).is_some() {
        return true;
    }
    let graph = GraphInputs {
        cwd,
        home_dir: home,
        ctx,
        managed_bin_dirs: &[],
        classify_github: classify_github_cli,
    };
    looks_like_safe_compound_developer_inspection(command, &graph)
        || is_read_only_git_ancestry_audit(command, cwd, home, ctx)
}

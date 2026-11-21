//! Compose GitHub capabilities across nested shell command structures
//! (`runtime/github_shell_capabilities.py`).

// Consumed by the request classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::github_capability_contract::{
    combine_github_assessments, github_assessment, GitHubCommandAssessment, GitHubCommandCapability,
};
use crate::hook_adapter_pytext::{is_py_space, py_strip};
use crate::sfrs_gh_bindings::{
    apply_assignment_updates, assignment_updates, case_arm_segments,
    complex_control_flow_may_invoke_github, conditional_pipeline_indexes, definition_payload,
    dynamic_command_may_invoke_github, executable_control_flow_segment,
    function_definition_payloads, normalize_github_lookup_assignments,
    parent_expanded_variable_names, persistent_assignment_updates, pipeline_executes_github_text,
    scoped_command_substitutions, update_exported_bindings, value_names_github_executable,
    Bindings, Updates,
};
use crate::sfrs_gh_control_flow::pipeline_control_flow;
use crate::sfrs_gh_environment::{
    github_pipeline_companion_is_read_only, shell_segment_is_command_builtin_lookup,
};
use crate::sfrs_gh_redirections::github_shell_args_and_redirection;
use crate::sfrs_shell_tokens::shell_segment_primary_command;
use crate::sfrs_substitution::{
    env_split_string_payloads, iter_shell_pipelines, shell_command_scripts,
    shell_command_substitution_payloads, split_parts,
};

/// Per-request state the shell analysis needs.
pub(crate) struct Scope<'a> {
    pub home_dir: Option<&'a Path>,
    /// Text of the outermost command; the pipeline-companion check reads it.
    pub root_text: &'a str,
    pub ctx: &'a Ctx<'a>,
    /// GitHub CLI argument classifier; the production value is the native
    /// command model, tests substitute a deterministic stand-in.
    pub classify: fn(&[String]) -> GitHubCommandAssessment,
}

/// The four binding sets a recursive call inherits.
#[derive(Clone, Default)]
pub(crate) struct Tracked {
    pub variables: Bindings,
    pub text_variables: Bindings,
    pub exported_variables: Bindings,
    pub exported_text_variables: Bindings,
}

fn unknown(reason: &str, detail: &str) -> GitHubCommandAssessment {
    github_assessment(&[GitHubCommandCapability::Unknown], reason, detail)
}

fn with_variables(variables: Bindings, text_variables: Bindings) -> Tracked {
    Tracked {
        variables,
        text_variables,
        ..Tracked::default()
    }
}

fn text_value_is_github_command(
    value: &str,
    scope: &Scope,
    depth: usize,
    variables: &Bindings,
    text_variables: &Bindings,
) -> bool {
    let stripped = py_strip(value);
    let first_token = stripped.split(is_py_space).next().unwrap_or("");
    if value_names_github_executable(first_token) {
        return true;
    }
    let inherited = with_variables(variables.clone(), text_variables.clone());
    classify_github_shell_capabilities(value, scope, depth + 1, &inherited).is_some()
}

fn text_assignment_updates(
    segment: &[String],
    command_index: Option<usize>,
    scope: &Scope,
    depth: usize,
    tracked: &Tracked,
) -> Updates {
    let classify = |value: &str| {
        text_value_is_github_command(
            value,
            scope,
            depth,
            &tracked.variables,
            &tracked.text_variables,
        )
    };
    assignment_updates(segment, command_index, true, Some(&classify))
}

fn persistent_text_assignment_updates(
    segment: &[String],
    command_name: Option<&str>,
    command_index: Option<usize>,
    scope: &Scope,
    depth: usize,
    tracked: &Tracked,
) -> Updates {
    let classify = |value: &str| {
        text_value_is_github_command(
            value,
            scope,
            depth,
            &tracked.variables,
            &tracked.text_variables,
        )
    };
    persistent_assignment_updates(segment, command_name, command_index, true, Some(&classify))
}

fn variables_after_prefix(prefix: &str, initial: &Bindings) -> Option<Bindings> {
    let mut bindings = initial.clone();
    let normalized = normalize_github_lookup_assignments(prefix)?;
    let parts = split_parts(&normalized);
    let conditional = conditional_pipeline_indexes(&parts);
    for (index, pipeline) in iter_shell_pipelines(&parts).iter().enumerate() {
        if pipeline.len() == 1 {
            let (name, command_index) = shell_segment_primary_command(&pipeline[0]);
            let mut updates = persistent_assignment_updates(
                &pipeline[0],
                name.as_deref(),
                command_index,
                false,
                None,
            );
            if conditional.contains(&index) {
                updates.retain(|update| update.1);
            }
            apply_assignment_updates(&mut bindings, &updates);
        }
    }
    Some(bindings)
}

fn text_variables_after_prefix(
    prefix: &str,
    scope: &Scope,
    initial: &Bindings,
) -> Option<Bindings> {
    let mut bindings = initial.clone();
    let normalized = normalize_github_lookup_assignments(prefix)?;
    let parts = split_parts(&normalized);
    let conditional = conditional_pipeline_indexes(&parts);
    for (index, pipeline) in iter_shell_pipelines(&parts).iter().enumerate() {
        if pipeline.len() == 1 {
            let (name, command_index) = shell_segment_primary_command(&pipeline[0]);
            let tracked = with_variables(Bindings::new(), bindings.clone());
            let mut updates = persistent_text_assignment_updates(
                &pipeline[0],
                name.as_deref(),
                command_index,
                scope,
                0,
                &tracked,
            );
            if conditional.contains(&index) {
                updates.retain(|update| update.1);
            }
            apply_assignment_updates(&mut bindings, &updates);
        }
    }
    Some(bindings)
}

fn classify_github_shell_segment(
    scope: &Scope,
    segment: &[String],
    command_index: usize,
) -> GitHubCommandAssessment {
    let (args, has_redirection) = github_shell_args_and_redirection(segment, command_index);
    let operation = (scope.classify)(&args);
    if !has_redirection {
        return operation;
    }
    let redirection = github_assessment(
        &[GitHubCommandCapability::WriteLocal],
        "github.command.shell-redirection",
        "The GitHub CLI invocation includes local input or output redirection.",
    );
    combine_github_assessments(&[operation, redirection]).expect("two assessments combine")
}

fn classify_indirect_github_segment(
    segment: &[String],
    command_name: Option<&str>,
    command_index: Option<usize>,
    scope: &Scope,
    depth: usize,
    tracked: &Tracked,
) -> Option<GitHubCommandAssessment> {
    let (Some(command_name), Some(command_index)) = (command_name, command_index) else {
        return None;
    };
    let inherited = with_variables(tracked.variables.clone(), tracked.text_variables.clone());
    if command_name == "alias" {
        let payload = definition_payload(segment, command_name, command_index);
        return classify_github_shell_capabilities(&payload, scope, depth + 1, &inherited).map(
            |_| {
                unknown(
                    "github.shell.deferred-definition",
                    "A shell function or alias defers execution of a GitHub command.",
                )
            },
        );
    }
    if !matches!(
        command_name,
        "builtin" | "eval" | "exec" | "timeout" | "trap" | "watch" | "xargs"
    ) {
        return None;
    }
    let github_index = segment
        .iter()
        .enumerate()
        .skip(command_index + 1)
        .find(|(_, token)| value_names_github_executable(token))
        .map(|(index, _)| index);
    if let Some(index) = github_index {
        return Some(classify_github_shell_segment(scope, segment, index));
    }
    let joined = segment[command_index + 1..].join(" ");
    classify_github_shell_capabilities(py_strip(&joined), scope, depth + 1, &inherited)
}

/// `classify_github_shell_capabilities`: every GitHub capability observed in a
/// shell composition.
pub(crate) fn classify_github_shell_capabilities(
    command_text: &str,
    scope: &Scope,
    depth: usize,
    inherited: &Tracked,
) -> Option<GitHubCommandAssessment> {
    if depth > 3 {
        return Some(unknown(
            "github.shell.nesting-depth",
            "The nested shell composition exceeds the statically reviewed depth.",
        ));
    }
    let mismatch = || {
        unknown(
            "github.shell.parse-failure",
            "The shell composition could not be analysed within the matcher budget.",
        )
    };
    let definitions = function_definition_payloads(command_text);
    let mut blanked: Vec<char> = command_text.chars().collect();
    for definition in definitions.iter().rev() {
        let start = command_text[..definition.start].chars().count();
        let end = command_text[..definition.end].chars().count();
        blanked[start..end].fill(' ');
    }
    let blanked: String = blanked.into_iter().collect();
    let Some(analysis_text) = normalize_github_lookup_assignments(&blanked) else {
        return Some(mismatch());
    };
    let parts = split_parts(&analysis_text);
    let pipelines = iter_shell_pipelines(&parts);
    let (conditional_indexes, skipped_pipelines) = pipeline_control_flow(&parts, &pipelines);
    let parent_expanded = parent_expanded_variable_names(command_text);
    let mut persistent = inherited.variables.clone();
    let mut persistent_text = inherited.text_variables.clone();
    let mut exported = inherited.exported_variables.clone();
    let mut exported_text = inherited.exported_text_variables.clone();
    if complex_control_flow_may_invoke_github(command_text, &persistent, &persistent_text) {
        return Some(unknown(
            "github.shell.compound-control-flow",
            "Compound shell control flow prevents a statically proven GitHub capability classification.",
        ));
    }
    let mut assessments: Vec<GitHubCommandAssessment> = Vec::new();
    for definition in &definitions {
        let (Some(variables), Some(text_variables)) = (
            variables_after_prefix(&definition.prefix, &persistent),
            text_variables_after_prefix(&definition.prefix, scope, &persistent_text),
        ) else {
            return Some(mismatch());
        };
        let nested = with_variables(variables, text_variables);
        if classify_github_shell_capabilities(&definition.body, scope, depth + 1, &nested).is_some()
        {
            assessments.push(unknown(
                "github.shell.deferred-definition",
                "A shell function defers execution of a GitHub command.",
            ));
        }
    }
    let payloads = shell_command_substitution_payloads(command_text);
    for (nested_command, prefix) in scoped_command_substitutions(command_text, &payloads) {
        let (Some(variables), Some(text_variables)) = (
            variables_after_prefix(&prefix, &persistent),
            text_variables_after_prefix(&prefix, scope, &persistent_text),
        ) else {
            return Some(mismatch());
        };
        let nested = Tracked {
            variables,
            text_variables,
            exported_variables: exported.clone(),
            exported_text_variables: exported_text.clone(),
        };
        if let Some(found) =
            classify_github_shell_capabilities(&nested_command, scope, depth + 1, &nested)
        {
            assessments.push(found);
        }
    }
    for (pipeline_index, pipeline) in pipelines.iter().enumerate() {
        if skipped_pipelines.contains(&pipeline_index) {
            continue;
        }
        let mut contains_github_command = false;
        for raw_segment in pipeline {
            let case_arms = case_arm_segments(raw_segment);
            if !case_arms.is_empty() {
                for arm in &case_arms {
                    let arm_tracked = with_variables(persistent.clone(), persistent_text.clone());
                    if let Some(found) = classify_github_shell_capabilities(
                        &arm.join(" "),
                        scope,
                        depth + 1,
                        &arm_tracked,
                    ) {
                        assessments.push(found);
                        contains_github_command = true;
                    }
                }
                continue;
            }
            let segment = executable_control_flow_segment(raw_segment);
            if segment.is_empty() {
                continue;
            }
            let (command_name, command_index) = shell_segment_primary_command(&segment);
            let updates = assignment_updates(&segment, command_index, false, None);
            let current = with_variables(persistent.clone(), persistent_text.clone());
            let text_updates =
                text_assignment_updates(&segment, command_index, scope, depth, &current);
            let mut segment_variables = persistent.clone();
            let mut segment_text_variables = persistent_text.clone();
            apply_assignment_updates(&mut segment_variables, &updates);
            apply_assignment_updates(&mut segment_text_variables, &text_updates);
            let mut nested_variables = exported.clone();
            let mut nested_text_variables = exported_text.clone();
            nested_variables.extend(persistent.intersection(&parent_expanded).cloned());
            nested_text_variables.extend(persistent_text.intersection(&parent_expanded).cloned());
            apply_assignment_updates(&mut nested_variables, &updates);
            apply_assignment_updates(&mut nested_text_variables, &text_updates);
            let mut nested_commands = env_split_string_payloads(&segment);
            nested_commands.extend(shell_command_scripts(&segment));
            for nested_command in &nested_commands {
                let nested = Tracked {
                    variables: nested_variables.clone(),
                    text_variables: nested_text_variables.clone(),
                    exported_variables: nested_variables.clone(),
                    exported_text_variables: nested_text_variables.clone(),
                };
                if let Some(found) =
                    classify_github_shell_capabilities(nested_command, scope, depth + 1, &nested)
                {
                    assessments.push(found);
                }
            }
            if shell_segment_is_command_builtin_lookup(&segment) {
                continue;
            }
            if let Some(name) = command_name.as_deref() {
                let token = command_index.map_or(name, |index| segment[index].as_str());
                if dynamic_command_may_invoke_github(
                    token,
                    &segment_variables,
                    &segment_text_variables,
                ) {
                    contains_github_command = true;
                    assessments.push(unknown(
                        "github.shell.dynamic-command",
                        "A dynamically resolved command may invoke an unverified GitHub operation.",
                    ));
                    continue;
                }
            }
            let segment_tracked = with_variables(segment_variables, segment_text_variables);
            if let Some(indirect) = classify_indirect_github_segment(
                &segment,
                command_name.as_deref(),
                command_index,
                scope,
                depth,
                &segment_tracked,
            ) {
                contains_github_command = true;
                assessments.push(indirect);
                continue;
            }
            let Some(index) = command_index else {
                continue;
            };
            if !value_names_github_executable(command_name.as_deref().unwrap_or("")) {
                continue;
            }
            contains_github_command = true;
            assessments.push(classify_github_shell_segment(scope, &segment, index));
        }
        if pipeline.len() == 1 {
            let segment = executable_control_flow_segment(&pipeline[0]);
            let (name, index) = shell_segment_primary_command(&segment);
            let conditional = conditional_indexes.contains(&pipeline_index);
            let mut executable_updates =
                persistent_assignment_updates(&segment, name.as_deref(), index, false, None);
            let current = with_variables(persistent.clone(), persistent_text.clone());
            let mut text_updates = persistent_text_assignment_updates(
                &segment,
                name.as_deref(),
                index,
                scope,
                depth,
                &current,
            );
            if conditional {
                executable_updates.retain(|update| update.1);
                text_updates.retain(|update| update.1);
            }
            apply_assignment_updates(&mut persistent, &executable_updates);
            apply_assignment_updates(&mut persistent_text, &text_updates);
            update_exported_bindings(
                &segment,
                name.as_deref(),
                index,
                &persistent,
                &mut exported,
                conditional,
            );
            update_exported_bindings(
                &segment,
                name.as_deref(),
                index,
                &persistent_text,
                &mut exported_text,
                conditional,
            );
        }
        if !contains_github_command || pipeline.len() < 2 {
            if pipeline.len() >= 2 && pipeline_executes_github_text(pipeline, &persistent_text) {
                assessments.push(unknown(
                    "github.pipeline.indirect-execution",
                    "A pipeline passes GitHub command text to an indirect command executor.",
                ));
            }
            continue;
        }
        for segment in pipeline {
            let (name, _) = shell_segment_primary_command(segment);
            if name.as_deref() == Some("gh") {
                continue;
            }
            if !github_pipeline_companion_is_read_only(
                segment,
                scope.home_dir,
                scope.root_text,
                scope.ctx,
            ) {
                assessments.push(unknown(
                    "github.pipeline.unverified-companion",
                    "A GitHub command is composed with a pipeline stage that has not been proven read-only.",
                ));
            }
        }
    }
    combine_github_assessments(&assessments)
}

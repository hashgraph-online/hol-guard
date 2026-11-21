//! Parity of the GitHub shell classifier and its helpers against recorded
//! Python output.

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::codex_output_env::Ctx;
use crate::github_capability_contract::{
    github_assessment, GitHubCommandAssessment, GitHubCommandCapability,
};
use crate::sfrs_gh_bindings::{
    assignment_updates, case_arm_segments, complex_control_flow_may_invoke_github,
    conditional_pipeline_connectors, contains_github_command_text, definition_payload,
    dynamic_command_may_invoke_github, executable_control_flow_segment,
    function_definition_payloads, is_shell_variable_name, normalize_github_lookup_assignments,
    parent_expanded_variable_names, persistent_assignment_updates, pipeline_executes_github_text,
    scoped_command_substitutions, segment_is_standalone_assignment, token_is_shell_assignment,
    tokens_reference_github_variable, update_exported_bindings, value_names_github_executable,
    Bindings, Updates,
};
use crate::sfrs_gh_control_flow::pipeline_control_flow;
use crate::sfrs_gh_redirections::github_shell_args_and_redirection;
use crate::sfrs_gh_service::classify_with;
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, shell_segment_primary_command, split_shell_parts,
};
use crate::sfrs_substitution::{iter_shell_pipelines, shell_command_substitution_payloads};
use crate::sfrs_token_vectors::{records, NoEnvHost};

fn names() -> [Bindings; 3] {
    let set =
        |items: &[&str]| -> Bindings { items.iter().map(|item| (*item).to_owned()).collect() };
    [set(&[]), set(&["x"]), set(&["gh2", "y"])]
}

fn sorted(set: &HashSet<usize>) -> Value {
    let mut items: Vec<usize> = set.iter().copied().collect();
    items.sort_unstable();
    items.into()
}

fn updates(items: Updates) -> Value {
    items
        .into_iter()
        .map(|(name, flag)| json!([name, flag]))
        .collect()
}

fn pairs(grid: &[bool]) -> Value {
    grid.to_vec().into()
}

fn product(rule: impl Fn(&Bindings, &Bindings) -> bool) -> Value {
    let sets = names();
    let mut out = Vec::new();
    for one in &sets {
        for two in &sets {
            out.push(rule(one, two));
        }
    }
    pairs(&out)
}

/// Mirrors the recorder stand-in for the native GitHub CLI classifier.
fn stand_in(args: &[String]) -> GitHubCommandAssessment {
    let joined = args.join(" ");
    let capability = if joined.starts_with("pr merge") {
        GitHubCommandCapability::MergeRemote
    } else if joined.contains("delete") {
        GitHubCommandCapability::DeleteRemote
    } else if joined.starts_with("pr view") || joined.starts_with("repo view") {
        GitHubCommandCapability::ReadRemote
    } else {
        GitHubCommandCapability::Unknown
    };
    github_assessment(&[capability], &format!("stub.{joined}"), "stub")
}

fn assessment(host: &NoEnvHost, text: &str) -> Value {
    let ctx = Ctx::new(host, "/", "/");
    classify_with(text, None, &ctx, stand_in).map_or(Value::Null, |found| {
        json!({
            "capability": found.capability.as_str(),
            "capabilities": found.capabilities.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "reason_code": found.reason_code,
            "detail": found.detail,
        })
    })
}

fn segment_record(segment: &[String]) -> Value {
    let (name, index) = shell_segment_primary_command(segment);
    let mut exports = Vec::new();
    for current in [Vec::<&str>::new(), vec!["x", "gh2"]] {
        let current: Bindings = current.into_iter().map(str::to_owned).collect();
        for suppress in [false, true] {
            let mut exported: Bindings = ["x", "z"].iter().map(|item| (*item).to_owned()).collect();
            update_exported_bindings(
                segment,
                name.as_deref(),
                index,
                &current,
                &mut exported,
                suppress,
            );
            let mut list: Vec<String> = exported.into_iter().collect();
            list.sort();
            exports.push(json!(list));
        }
    }
    let flags = [false, true];
    let arms: Vec<Vec<String>> = case_arm_segments(segment);
    json!({
        "exec": executable_control_flow_segment(segment),
        "case": arms,
        "standalone": segment_is_standalone_assignment(segment),
        "updates": flags.iter().map(|flag| updates(assignment_updates(segment, index, *flag, None))).collect::<Vec<_>>(),
        "persistent": flags.iter().map(|flag| {
            updates(persistent_assignment_updates(segment, name.as_deref(), index, *flag, None))
        }).collect::<Vec<_>>(),
        "redirection": index.map_or(Value::Null, |at| {
            let (args, flag) = github_shell_args_and_redirection(segment, at);
            json!([args, flag])
        }),
        "definition": match (index, name.as_deref()) {
            (Some(at), Some(_)) => json!(["alias", "function"].iter().map(|kind| definition_payload(segment, kind, at)).collect::<Vec<_>>()),
            _ => Value::Null,
        },
        "exported": exports,
    })
}

fn shell_record(host: &NoEnvHost, text: &str) -> Value {
    let parts = split_shell_parts(text);
    let segments = iter_shell_command_segments(&parts);
    let pipelines = iter_shell_pipelines(&parts);
    let (conditional, skipped) = pipeline_control_flow(&parts, &pipelines);
    let mut connectors: Vec<(usize, String)> = conditional_pipeline_connectors(&parts)
        .into_iter()
        .collect();
    connectors.sort();
    let sets = names();
    let functions: Vec<Value> = function_definition_payloads(text)
        .iter()
        .map(|found| {
            json!([
                found.body,
                found.prefix,
                text[found.start..found.end].chars().count()
            ])
        })
        .collect();
    let mut parent: Vec<String> = parent_expanded_variable_names(text).into_iter().collect();
    parent.sort();
    let payloads = shell_command_substitution_payloads(text);
    let tokens: Vec<Value> = parts
        .iter()
        .map(|part| {
            json!([
                value_names_github_executable(part),
                is_shell_variable_name(part),
                token_is_shell_assignment(part),
                product(|one, two| dynamic_command_may_invoke_github(part, one, two)),
                product(|one, two| tokens_reference_github_variable(
                    std::slice::from_ref(part),
                    one,
                    two
                )),
            ])
        })
        .collect();
    json!({
        "assessment": assessment(host, text),
        "normalized": normalize_github_lookup_assignments(text),
        "command_text": contains_github_command_text(text),
        "functions": functions,
        "parent": parent,
        "complex": product(|one, two| complex_control_flow_may_invoke_github(text, one, two)),
        "connectors": connectors.iter().map(|(key, value)| json!([key, value])).collect::<Vec<_>>(),
        "control": [sorted(&conditional), sorted(&skipped)],
        "scoped": scoped_command_substitutions(text, &payloads)
            .iter()
            .map(|(one, two)| json!([one, two]))
            .collect::<Vec<_>>(),
        "executes": pipelines
            .iter()
            .map(|pipeline| sets.iter().map(|one| pipeline_executes_github_text(pipeline, one)).collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "tokens": tokens,
        "segments": segments.iter().map(|segment| segment_record(segment)).collect::<Vec<_>>(),
    })
}

#[test]
fn github_shell_classifier_matches_recorded_python() {
    let host = NoEnvHost;
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let expected = &record["gh_shell"];
        if expected.is_null() {
            continue;
        }
        compared += 1;
        let actual = shell_record(&host, text);
        for (label, want) in expected.as_object().expect("object") {
            if &actual[label] != want {
                failures.push(format!("{text:?} {label}: {} vs {want}", actual[label]));
            }
        }
    }
    assert!(compared > 100, "too few gh_shell records: {compared}");
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}

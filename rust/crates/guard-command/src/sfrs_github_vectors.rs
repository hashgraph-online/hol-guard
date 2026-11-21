//! Parity of the GitHub shell helpers against recorded Python output.

use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::sfrs_gh_environment::{
    github_environment_name, github_environment_requires_review,
    github_pipeline_companion_is_read_only, github_script_requires_review,
    github_shell_has_dynamic_arguments, persistent_github_environment_requires_review,
    shell_segment_is_command_builtin_lookup,
};
use crate::sfrs_shell_tokens::{iter_shell_command_segments, split_shell_parts};
use crate::sfrs_substitution::{
    env_split_string_payloads, github_argument_token_has_untrusted_expansion, iter_shell_pipelines,
    shell_command_scripts, shell_command_substitution_payloads, shell_segment_env_index,
    shell_token_has_expansion,
};
use crate::sfrs_token_vectors::{environment_cases, records, NoEnvHost};

fn check(failures: &mut Vec<String>, text: &str, label: &str, actual: Value, expected: &Value) {
    if &actual != expected {
        failures.push(format!("{text:?} {label}: {actual} vs {expected}"));
    }
}

#[test]
fn github_shell_helpers_match_recorded_python() {
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let mut failures = Vec::new();
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let expected = &record["github"];
        let parts = split_shell_parts(text);
        let segments = iter_shell_command_segments(&parts);
        let mut run = |label: &str, actual: Value| {
            check(&mut failures, text, label, actual, &expected[label])
        };
        run(
            "substitutions",
            shell_command_substitution_payloads(text).into(),
        );
        run("dynamic", github_shell_has_dynamic_arguments(text).into());
        let tokens: Vec<Vec<bool>> = parts
            .iter()
            .map(|part| {
                vec![
                    shell_token_has_expansion(part),
                    github_argument_token_has_untrusted_expansion(part),
                    github_environment_name(part),
                ]
            })
            .collect();
        run("tokens", tokens.into());
        run("pipelines", iter_shell_pipelines(&parts).into());
        let env_index: Vec<Value> = segments
            .iter()
            .map(|segment| shell_segment_env_index(segment).map_or(Value::Null, Value::from))
            .collect();
        run("env_index", env_index.into());
        run("env_split", env_split_string_payloads(&parts).into());
        run("scripts", shell_command_scripts(&parts).into());
        run(
            "persistent",
            persistent_github_environment_requires_review(&parts).into(),
        );
        let builtin: Vec<bool> = segments
            .iter()
            .map(|segment| shell_segment_is_command_builtin_lookup(segment))
            .collect();
        run("builtin", builtin.into());
        let companion: Vec<bool> = segments
            .iter()
            .map(|segment| github_pipeline_companion_is_read_only(segment, None, text, &ctx))
            .collect();
        run("companion", companion.into());
        run("script_review", github_script_requires_review(text).into());
    }
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}

#[test]
fn github_environment_review_matches_recorded_python() {
    for case in environment_cases() {
        let assignments: Vec<(String, String)> = case[0]
            .as_array()
            .expect("assignments")
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().expect("name").to_owned(),
                    pair[1].as_str().expect("value").to_owned(),
                )
            })
            .collect();
        assert_eq!(
            Value::from(github_environment_requires_review(&assignments)),
            case[1],
            "{assignments:?}"
        );
    }
}

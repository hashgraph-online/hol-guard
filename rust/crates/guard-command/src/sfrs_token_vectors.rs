//! Parity of the tokenization helpers against vectors recorded from the
//! retired Python implementation.

use std::io::Read;

use serde_json::Value;

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::sfrs_docker_args::{
    docker_build_args_are_sensitive, docker_buildx_subcommand_index,
    docker_subcommand_help_requested, docker_subcommand_index, shell_variable_names,
};
use crate::sfrs_quote_tokens::{shell_token_segments, shell_tokens_preserving_quote_context};
use crate::sfrs_read_only_filters::{
    read_only_lookup_arg_is_redirection, read_only_lookup_filter_segment_is_safe,
    read_only_lookup_head_tail_args_are_safe, read_only_lookup_sed_args_are_safe,
    read_only_lookup_target_is_safe, split_attached_redirection_token,
};
use crate::sfrs_search_filters::{
    read_only_lookup_filter_grep_args_are_safe, read_only_lookup_filter_rg_args_are_safe,
};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name, shell_segment_primary_command,
    split_shell_parts,
};
use crate::shell_secret_read_support::{
    cat_file_operand_tokens, plain_file_operand_tokens, ripgrep_args_expand_hidden_files,
    search_file_operand_roles, search_glob_pattern_is_safe, search_operands_are_safe,
    sed_file_operand_tokens, shell_segment_file_operand_tokens,
};

pub(crate) fn records() -> Vec<Value> {
    let bytes = include_bytes!("../tests/fixtures/sfrs/intermediate_tokens.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    let document: Value = serde_json::from_str(&text).expect("json");
    document["tokens"].as_array().expect("tokens").clone()
}

pub(crate) fn script_records() -> Vec<Value> {
    let bytes = include_bytes!("../tests/fixtures/sfrs/intermediate_tokens.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    let document: Value = serde_json::from_str(&text).expect("json");
    document["scripts"].as_array().expect("scripts").clone()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("list")
        .iter()
        .map(|item| item.as_str().expect("str").to_owned())
        .collect()
}

#[test]
fn tokenization_helpers_match_recorded_python() {
    let mut failures = Vec::new();
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let parts = split_shell_parts(text);
        if parts != strings(&record["parts"]) {
            failures.push(format!("parts {text:?}: {parts:?} vs {}", record["parts"]));
            continue;
        }
        let segments = iter_shell_command_segments(&parts);
        let expected_segments: Vec<Vec<String>> = record["segments"]
            .as_array()
            .expect("segments")
            .iter()
            .map(strings)
            .collect();
        if segments != expected_segments {
            failures.push(format!("segments {text:?}"));
            continue;
        }
        for (index, segment) in segments.iter().enumerate() {
            let (name, at) = shell_segment_primary_command(segment);
            let expected = &record["primaries"][index];
            let actual = serde_json::json!([name, at]);
            if &actual != expected {
                failures.push(format!("primary {segment:?}: {actual} vs {expected}"));
            }
            let args = &segment[1..];
            let docker = &record["docker"][index];
            let actual = serde_json::json!([
                docker_subcommand_index(args),
                docker_build_args_are_sensitive(args),
                docker_buildx_subcommand_index(args),
                docker_subcommand_help_requested(args),
            ]);
            if &actual != docker {
                failures.push(format!("docker {segment:?}: {actual} vs {docker}"));
            }
        }
        if shell_variable_names(text) != strings(&record["variables"]) {
            failures.push(format!("variables {text:?}"));
        }
        let names: Vec<String> = parts
            .iter()
            .map(|part| normalized_shell_command_name(part))
            .collect();
        if names != strings(&record["names"]) {
            failures.push(format!("names {text:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}

pub(crate) struct NoEnvHost;

impl InspectionHost for NoEnvHost {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("vector host does not run git")
    }
}

fn pair(token: &crate::sfrs_quote_tokens::QuotedToken) -> Value {
    serde_json::json!([token.raw, token.plain])
}

#[test]
fn filters_and_quote_tokens_match_recorded_python() {
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let mut failures = Vec::new();
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let parts = strings(&record["parts"]);
        let filters = &record["filters"];
        for (index, part) in parts.iter().enumerate() {
            let actual = serde_json::json!([
                read_only_lookup_target_is_safe(part, false, None),
                read_only_lookup_target_is_safe(part, true, None),
            ]);
            if actual != filters["targets"][index] {
                failures.push(format!("target {part:?}: {actual}"));
            }
            let split = split_attached_redirection_token(part)
                .map(|(prefix, fd, op, target)| serde_json::json!([prefix, fd, op, target]));
            let actual = serde_json::json!([
                read_only_lookup_arg_is_redirection(part),
                split.unwrap_or(Value::Null)
            ]);
            if actual != filters["redirections"][index] {
                failures.push(format!("redirection {part:?}: {actual}"));
            }
        }
        let segments = iter_shell_command_segments(&parts);
        for (index, segment) in segments.iter().enumerate() {
            let (command, args) = (segment[0].as_str(), &segment[1..]);
            let actual = serde_json::json!([
                read_only_lookup_filter_segment_is_safe(command, args, None, false, &ctx),
                read_only_lookup_filter_segment_is_safe(command, args, None, true, &ctx),
                read_only_lookup_sed_args_are_safe(args, true, None),
                read_only_lookup_head_tail_args_are_safe(args, true, None),
                read_only_lookup_filter_grep_args_are_safe(args, None),
                read_only_lookup_filter_rg_args_are_safe(args, &ctx),
            ]);
            if actual != filters["segments"][index] {
                failures.push(format!("filter segment {segment:?}: {actual}"));
            }
        }
        let tokens = shell_tokens_preserving_quote_context(text);
        let actual: Vec<Value> = tokens.iter().map(pair).collect();
        if Value::Array(actual) != record["quote"]["tokens"] {
            failures.push(format!("quote tokens {text:?}"));
        }
        let quoted: Vec<Value> = shell_token_segments(&tokens)
            .iter()
            .map(|segment| Value::Array(segment.iter().map(pair).collect()))
            .collect();
        if Value::Array(quoted) != record["quote"]["segments"] {
            failures.push(format!("quote segments {text:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}

#[test]
fn local_read_operands_match_recorded_python() {
    let mut failures = Vec::new();
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let parts = strings(&record["parts"]);
        let operands = &record["operands"];
        for (index, part) in parts.iter().enumerate() {
            let actual = serde_json::json!(search_glob_pattern_is_safe(part, None));
            if actual != operands["globs"][index] {
                failures.push(format!("glob {part:?}: {actual}"));
            }
        }
        let segments = iter_shell_command_segments(&parts);
        for (index, segment) in segments.iter().enumerate() {
            let args = &segment[1..];
            let expected = &operands["segments"][index];
            let roles = |name: &str| -> Value {
                search_file_operand_roles(name, args)
                    .into_iter()
                    .map(|(operand, glob)| serde_json::json!([operand, glob]))
                    .collect()
            };
            let actual = serde_json::json!({
                "tokens": shell_segment_file_operand_tokens(segment),
                "hidden": ripgrep_args_expand_hidden_files(args),
                "roles": [roles("grep"), roles("rg")],
                "cat": cat_file_operand_tokens(args),
                "plain": plain_file_operand_tokens(args),
                "sed": sed_file_operand_tokens(args),
                "search": [
                    search_operands_are_safe("grep", args, None),
                    search_operands_are_safe("rg", args, None),
                ],
            });
            if &actual != expected {
                failures.push(format!(
                    "operands {segment:?}\n  {actual}\n  {expected} ({text:?})"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(6)]
    );
}

pub(crate) fn environment_cases() -> Vec<Value> {
    let bytes = include_bytes!("../tests/fixtures/sfrs/intermediate_tokens.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    let document: Value = serde_json::from_str(&text).expect("json");
    document["environments"]
        .as_array()
        .expect("environments")
        .clone()
}

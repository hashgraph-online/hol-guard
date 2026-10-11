//! Parity of the static-safety helpers against recorded Python output.

use std::path::Path;

use serde_json::Value;

use crate::sfrs_interpreter_scripts::{
    interpreter_flag_payload, is_python_interpreter_command, is_script_interpreter_command,
    script_interpreter_texts, script_is_benign_wait, script_is_read_only_observer,
};
use crate::sfrs_jq::github_jq_filter_args_are_safe;
use crate::sfrs_python_imports::script_has_aliased_risky_import;
use crate::sfrs_shell_tokens::{iter_shell_command_segments, split_shell_parts};
use crate::sfrs_static_safety::{
    shell_syntax_check_segment_is_safe, shell_token_escapes_root,
    shell_token_has_command_substitution, without_safe_inspection_redirections,
};
use crate::sfrs_token_vectors::{records, script_records};

fn check(failures: &mut Vec<String>, text: &str, label: &str, actual: Value, expected: &Value) {
    if &actual != expected {
        failures.push(format!("{text:?} {label}: {actual} vs {expected}"));
    }
}

fn finish(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}

#[test]
fn static_command_helpers_match_recorded_python() {
    let cwd = Path::new("/sfrs-nonexistent-cwd");
    let root = Path::new("/sfrs-nonexistent-root");
    let mut failures = Vec::new();
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let expected = &record["static"];
        let parts = split_shell_parts(text);
        let segments = iter_shell_command_segments(&parts);
        let jq: Vec<bool> = segments
            .iter()
            .map(|segment| github_jq_filter_args_are_safe(&segment[1..]))
            .collect();
        check(&mut failures, text, "jq", jq.into(), &expected["jq"]);
        check(
            &mut failures,
            text,
            "texts",
            script_interpreter_texts(&parts).into(),
            &expected["texts"],
        );
        let redirections: Vec<Value> = segments
            .iter()
            .map(|segment| {
                without_safe_inspection_redirections(segment).map_or(Value::Null, Value::from)
            })
            .collect();
        check(
            &mut failures,
            text,
            "redirections",
            redirections.into(),
            &expected["redirections"],
        );
        let syntax: Vec<bool> = segments
            .iter()
            .map(|segment| shell_syntax_check_segment_is_safe(&segment[0], &segment[1..]))
            .collect();
        check(
            &mut failures,
            text,
            "syntax",
            syntax.into(),
            &expected["syntax"],
        );
        let escapes: Vec<bool> = parts
            .iter()
            .map(|part| shell_token_escapes_root(part, cwd, root))
            .collect();
        check(
            &mut failures,
            text,
            "escapes",
            escapes.into(),
            &expected["escapes"],
        );
        let substitution: Vec<bool> = parts
            .iter()
            .map(|part| shell_token_has_command_substitution(part))
            .collect();
        check(
            &mut failures,
            text,
            "substitution",
            substitution.into(),
            &expected["substitution"],
        );
        let interpreter: Vec<Vec<bool>> = parts
            .iter()
            .map(|part| {
                vec![
                    is_python_interpreter_command(part),
                    is_script_interpreter_command(part),
                ]
            })
            .collect();
        check(
            &mut failures,
            text,
            "interpreter",
            interpreter.into(),
            &expected["interpreter"],
        );
        let payloads: Vec<Value> = (0..parts.len())
            .map(|index| {
                Value::from(vec![interpreter_flag_payload(&parts, index).map_or(
                    Value::Null,
                    |found| {
                        Value::from(vec![
                            Value::from(found.script_text),
                            Value::from(found.tokens_consumed),
                        ])
                    },
                )])
            })
            .collect();
        check(
            &mut failures,
            text,
            "payloads",
            payloads.into(),
            &expected["payloads"],
        );
    }
    finish(&failures);
}

#[test]
fn script_helpers_match_recorded_python() {
    let mut failures = Vec::new();
    let mut aliased = 0usize;
    let mut observers = 0usize;
    let mut unparsable = 0usize;
    for record in script_records() {
        let text = record["text"].as_str().expect("text");
        let (found, observer) = (
            script_has_aliased_risky_import(text),
            script_is_read_only_observer(text),
        );
        let wait = script_is_benign_wait(text);
        check(&mut failures, text, "wait", wait.into(), &record["wait"]);
        if record["parses"].as_bool() == Some(false) {
            // Python rejects a script it cannot parse and reports no alias;
            // the lexical scanner may only be stricter, never more lenient.
            unparsable += 1;
            let python_aliased = record["aliased"].as_bool().unwrap_or(false);
            let python_observer = record["observer"].as_bool().unwrap_or(false);
            if (python_aliased && !found) || (observer && !python_observer && !found) {
                failures.push(format!("{text:?}: lenient on unparsable script"));
            }
            continue;
        }
        aliased += usize::from(record["aliased"].as_bool().unwrap_or(false));
        observers += usize::from(record["observer"].as_bool().unwrap_or(false));
        check(
            &mut failures,
            text,
            "aliased",
            found.into(),
            &record["aliased"],
        );
        check(
            &mut failures,
            text,
            "observer",
            observer.into(),
            &record["observer"],
        );
    }
    assert!(
        aliased > 3 && observers > 3 && unparsable > 0,
        "corpus coverage"
    );
    finish(&failures);
}

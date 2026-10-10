//! Shared-vector tests for the complete-or-fail lockfile parser.

use super::lockfile_parse::lockfile_parse_budget_for_bytes;
use super::*;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../../tests/fixtures/supply-chain-eval/cases.v1.json");

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn case_bytes(case: &Value) -> Vec<u8> {
    if let Some(hex) = case.get("bytes_hex").and_then(Value::as_str) {
        return decode_hex(hex);
    }
    if let Some(generate) = case.get("generate") {
        let unit = generate["unit"].as_str().unwrap();
        let count = generate["count"].as_u64().unwrap() as usize;
        let prefix = generate.get("prefix").and_then(Value::as_str).unwrap_or("");
        let closing = generate
            .get("closing_unit")
            .and_then(Value::as_str)
            .unwrap_or("");
        let suffix = generate.get("suffix").and_then(Value::as_str).unwrap_or("");
        return format!(
            "{prefix}{}{}{suffix}",
            unit.repeat(count),
            closing.repeat(count)
        )
        .into_bytes();
    }
    case["text"].as_str().unwrap().as_bytes().to_vec()
}

#[test]
fn lockfile_vectors_match_expected_outcome() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = vectors["lockfile_parse"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let path = case["path"].as_str().unwrap();
        let result = parse_lockfile_with_budget(path, &case_bytes(case), 30.0);
        let expect = &case["expect"];
        assert_eq!(
            result.complete,
            expect["complete"].as_bool().unwrap(),
            "{name}: complete"
        );
        assert_eq!(result.parser_version, LOCKFILE_PARSER_VERSION, "{name}");
        if result.complete {
            let got: Vec<Value> = result
                .entries
                .iter()
                .map(|entry| {
                    serde_json::json!([entry.dependency_path, entry.package_name, entry.version])
                })
                .collect();
            assert_eq!(&Value::Array(got), &expect["entries"], "{name}: entries");
        } else {
            assert_eq!(
                result.error_reason.as_deref(),
                expect["error_reason"].as_str(),
                "{name}: error_reason"
            );
            assert!(result.entries.is_empty(), "{name}: no partial entries");
        }
    }
}

#[test]
fn parse_budget_scales_with_size_and_caps() {
    assert!((lockfile_parse_budget_for_bytes(0) - 0.5).abs() < 1e-9);
    assert!((lockfile_parse_budget_for_bytes(1024 * 1024) - 1.25).abs() < 1e-9);
    assert!((lockfile_parse_budget_for_bytes(64 * 1024 * 1024) - 1.5).abs() < 1e-9);
}

#[test]
fn zero_budget_reports_deadline_exceeded() {
    let result = parse_lockfile_with_budget("package-lock.json", b"{}", 0.0);
    assert!(!result.complete);
    assert_eq!(result.error_reason.as_deref(), Some("deadline_exceeded"));
}

#[test]
fn lockfile_ecosystem_maps_parser_format_labels_and_file_names() {
    for (input, want) in [
        ("bundler-lock", "rubygems"),
        ("Gemfile.lock", "rubygems"),
        ("pipenv-lock", "pypi"),
        ("Pipfile.lock", "pypi"),
        ("poetry-lock", "pypi"),
        ("uv-lock", "pypi"),
        ("cargo-lock", "cargo"),
        ("Cargo.lock", "cargo"),
        ("composer-lock", "packagist"),
        ("composer.lock", "packagist"),
        ("npm-package-lock", "npm"),
        ("pnpm-lock", "npm"),
        ("yarn-lock", "npm"),
        ("bun-lock", "npm"),
        ("package-lock.json", "npm"),
    ] {
        assert_eq!(lockfile_ecosystem(input), want, "{input}");
    }
}

#[test]
fn incomplete_lockfile_message_follows_the_decision() {
    let parse_result = parse_lockfile_with_budget("package-lock.json", b"{", 30.0);
    assert!(!parse_result.complete);
    let target: Map<String, Value> = serde_json::from_value(serde_json::json!({
        "ecosystem": "npm",
        "package_name": "react",
        "requested_specifier": "18.0.0",
    }))
    .unwrap();
    for (decision, outcome, other) in [("ask", "paused", "blocked"), ("block", "blocked", "paused")]
    {
        let package = super::lockfile_evidence::incomplete_lockfile_package_result(
            &target,
            &parse_result,
            decision,
        );
        assert_eq!(package["decision"], decision);
        let message = package["reasons"][0]["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("so this package request is {outcome}.")),
            "{message}"
        );
        assert!(!message.contains(other), "{message}");
        assert!(message.ends_with("Repair the lockfile, then retry."));
    }
}

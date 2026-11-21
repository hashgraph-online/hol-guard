//! Parity vectors recorded from the retired Python implementation.
//!
//! Environment-dependent verdicts are pinned by `StubFacts`, so each vector
//! isolates argument shape, path resolution and shell-context semantics.

use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::{CompoundGitCheckV1, CompoundGitSegmentV1};
use serde_json::Value;

use crate::compound_git_chain::safe_bound_segment;
use crate::compound_git_inspection_op::decide;
use crate::compound_git_inspection_op_tests::{request, StubFacts};

const VECTORS: &str = include_str!("../tests/fixtures/compound_git_inspection_vectors.json");

fn substitute(value: &mut Value, root: &str) {
    match value {
        Value::String(text) => *text = text.replace("${ROOT}", root),
        Value::Array(items) => items.iter_mut().for_each(|item| substitute(item, root)),
        Value::Object(map) => map.values_mut().for_each(|item| substitute(item, root)),
        _ => {}
    }
}

#[cfg(unix)]
fn build_tree(vectors: &Value) -> PathBuf {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cgi-vectors-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for dir in vectors["dirs"].as_array().unwrap() {
        fs::create_dir_all(root.join(dir.as_str().unwrap())).unwrap();
    }
    for file in vectors["files"].as_array().unwrap() {
        fs::write(root.join(file.as_str().unwrap()), b"").unwrap();
    }
    for (link, target) in vectors["symlinks"].as_object().unwrap() {
        std::os::unix::fs::symlink(target.as_str().unwrap(), root.join(link)).unwrap();
    }
    root
}

fn optional(case: &Value, key: &str) -> Option<String> {
    case.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn evaluate(case: &Value, root: &Path) -> Value {
    let facts = StubFacts::default();
    let check = case["check"].as_str().unwrap();
    let segments: Vec<CompoundGitSegmentV1> = case
        .get("segments")
        .map(|value| serde_json::from_value(value.clone()).unwrap())
        .unwrap_or_default();
    if check == "bound_pair" {
        return Value::Bool(safe_bound_segment(&segments[1], &segments[0]));
    }
    let kind = match check {
        "segment" => CompoundGitCheckV1::Segment,
        "standalone" => CompoundGitCheckV1::Standalone,
        "compound" => CompoundGitCheckV1::Compound,
        "push_segment" => CompoundGitCheckV1::PushSegment,
        "show_config" => CompoundGitCheckV1::ShowConfig,
        "repository_path" => CompoundGitCheckV1::RepositoryPath,
        "home_git_c_path" => CompoundGitCheckV1::HomeGitCPath,
        "object_existence_query" => CompoundGitCheckV1::ObjectExistenceQuery,
        other => panic!("unknown vector check {other}"),
    };
    let mut req = request(kind);
    req.segments = segments;
    req.complete = case
        .get("complete")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    req.command_text = optional(case, "command_text");
    req.value = optional(case, "value");
    req.home_dir = optional(case, "home_dir");
    req.repository_path = optional(case, "repository_path");
    req.cwd = optional(case, "cwd").map(|cwd| root.join(cwd).to_string_lossy().into_owned());
    let verdict = decide(&req, &facts).expect("vector request is well formed");
    if check == "home_git_c_path" {
        return verdict.value.map_or(Value::Null, Value::String);
    }
    Value::Bool(verdict.allowed)
}

#[cfg(unix)]
#[test]
fn compound_git_inspection_matches_the_retired_python_vectors() {
    let mut vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let root = build_tree(&vectors);
    let root_text = root.to_string_lossy().into_owned();
    substitute(&mut vectors, &root_text);
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 2000, "vector corpus shrank: {}", cases.len());
    let mismatches: Vec<String> = cases
        .iter()
        .enumerate()
        .filter_map(|(index, case)| {
            let actual = evaluate(case, &root);
            (actual != case["expected"]).then(|| {
                format!(
                    "#{index} {} {:?}: expected {} got {actual}",
                    case["check"],
                    case.get("command"),
                    case["expected"]
                )
            })
        })
        .collect();
    let _ = fs::remove_dir_all(&root);
    assert!(
        mismatches.is_empty(),
        "{} vector mismatches, first: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(20)]
    );
}

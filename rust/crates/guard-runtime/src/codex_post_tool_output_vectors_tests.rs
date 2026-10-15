//! Post-tool output vectors recorded from the retired Python
//! `_codex_post_tool_output_artifact`, replayed through the resident
//! `codex_tool_output` request path with the real inspection host.
//!
//! A fingerprint or metadata value that names the fixture root is compared
//! after substituting this run's root; a fingerprint over an absolute
//! execution context or a Git pathspec identity depends on the recording
//! root, so those cases compare everything except that hash.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::{
    CodexPostToolOutputV1, CodexToolOutputActionV1, CodexToolOutputFactsV1,
    CodexToolOutputRequestV1, CODEX_TOOL_OUTPUT_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use crate::codex_tool_output_op::evaluate_codex_tool_output_request;

const VECTORS: &str = include_str!("../tests/fixtures/codex_post_tool_output_vectors.json");
const ROOT: &str = "${ROOT}";
/// The recorder stores secret-shaped fixture text as placeholders.
const PLACEHOLDERS: [(&str, &str); 2] = [
    ("${PRIVATE_KEY_FENCE}", concat!("PRIVATE ", "KEY-----")),
    (
        "${OPENAI_KEY}",
        concat!("sk-", "proj-4f8a9b2c7d1e6f3a5b8c9d0e1f2a3b4c"),
    ),
];
const IDENTITY: &str = "git_pathspec_selection_identity";
/// Hashes the absolute initial and segment working directories, so it is bound
/// to the recording root and only its shape replays.
const CONTEXT_HASH: &str = "shell_execution_context_hash";

fn find_git() -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

fn build_tree(vectors: &Value) -> PathBuf {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cpto-vectors-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for dir in vectors["dirs"].as_array().unwrap() {
        fs::create_dir_all(root.join(dir.as_str().unwrap())).unwrap();
    }
    for (file, text) in vectors["files"].as_object().unwrap() {
        let path = root.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text.as_str().unwrap()).unwrap();
    }
    root
}

fn substitute(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(ROOT, root)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| substitute(item, root)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), substitute(item, root)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn scoped(root: &Path, value: &Value) -> Value {
    value
        .as_str()
        .map_or(Value::Null, |name| json!(root.join(name).to_string_lossy()))
}

fn review(case: &Value, root: &Path, git: Option<String>) -> Value {
    let root_text = root.to_string_lossy();
    let mut body = substitute(&case["body"], &root_text);
    let fields = body.as_object_mut().unwrap();
    fields.insert("cwd".to_owned(), scoped(root, &case["cwd"]));
    fields.insert("home_dir".to_owned(), scoped(root, &case["home_dir"]));
    fields.insert("deadline_ms".to_owned(), json!(30_000));
    let request = CodexToolOutputRequestV1 {
        schema: CODEX_TOOL_OUTPUT_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        action: CodexToolOutputActionV1::PostToolOutput(CodexPostToolOutputV1 { body }),
        facts: CodexToolOutputFactsV1 {
            process_cwd: root.join("proc").to_string_lossy().into_owned(),
            home: root.join("home").to_string_lossy().into_owned(),
            account_home: None,
            groups: Vec::new(),
            environment: BTreeMap::new(),
            git_executable: git,
        },
    };
    let bytes = evaluate_codex_tool_output_request(&request).unwrap();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    if envelope["allowed"] != json!(true) {
        return json!({"error": envelope["code"]});
    }
    serde_json::from_str(envelope["value"].as_str().unwrap()).unwrap()
}

/// The recorded artifact against the replayed one; `None` when they agree.
fn artifact_mismatch(expected: &Value, actual: &Value, root: &str) -> Option<String> {
    let expected_pairs = expected["metadata"].as_array().unwrap();
    let Some(actual_pairs) = actual["metadata"].as_array() else {
        return Some(format!("no metadata in {actual}"));
    };
    if expected_pairs.len() != actual_pairs.len() {
        return Some(format!("metadata {expected_pairs:?} != {actual_pairs:?}"));
    }
    let mut portable = !expected["metadata"].to_string().contains(ROOT);
    for (want, got) in expected_pairs.iter().zip(actual_pairs) {
        if want[0] == IDENTITY {
            portable = false;
            if got[0] != IDENTITY || !got[1].is_string() {
                return Some(format!("identity {got:?}"));
            }
        } else if want[0] == CONTEXT_HASH {
            portable = false;
            let hashed = got[1]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:"));
            if got[0] != CONTEXT_HASH || !hashed {
                return Some(format!("context hash {got:?}"));
            }
        } else if substitute(want, root) != *got {
            return Some(format!("pair {want:?} != {got:?}"));
        }
    }
    (portable && expected["fingerprint"] != actual["fingerprint"]).then(|| {
        format!(
            "fingerprint {} != {}",
            expected["fingerprint"], actual["fingerprint"]
        )
    })
}

fn mismatch(expected: &Value, actual: &Value, root: &str) -> Option<String> {
    if expected.get("error").is_some() || actual.get("error").is_some() {
        let both = expected.get("error").is_some() && actual.get("error").is_some();
        return (!both).then(|| format!("{expected} != {actual}"));
    }
    match (&expected["artifact"], &actual["artifact"]) {
        (Value::Null, Value::Null) if expected.get("artifact").is_some() => {
            (expected["read_only"] != actual["read_only"]).then(|| {
                format!(
                    "read_only {} != {}",
                    expected["read_only"], actual["read_only"]
                )
            })
        }
        (want @ Value::Object(_), got @ Value::Object(_)) => artifact_mismatch(want, got, root),
        _ => Some(format!("{expected} != {actual}")),
    }
}

#[test]
fn post_tool_output_matches_the_retired_python_vectors() {
    let text = PLACEHOLDERS
        .iter()
        .fold(VECTORS.to_owned(), |text, (placeholder, secret)| {
            text.replace(placeholder, secret)
        });
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let root = build_tree(&vectors);
    let root_text = root.to_string_lossy().into_owned();
    let git = find_git();
    let mut failures = Vec::new();
    let mut checked = 0;
    for case in vectors["cases"].as_array().unwrap() {
        let expected = &case["expected"];
        let needs_git = expected["artifact"]["metadata"]
            .as_array()
            .is_some_and(|pairs| pairs.iter().any(|pair| pair[0] == IDENTITY));
        if needs_git && git.is_none() {
            continue;
        }
        checked += 1;
        let actual = review(case, &root, git.clone());
        if let Some(reason) = mismatch(expected, &actual, &root_text) {
            failures.push(format!(
                "{} cwd={}: {reason}",
                case["body"]["command_texts"], case["cwd"]
            ));
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(checked > 200, "only {checked} vectors replayed");
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures[..failures.len().min(12)].join("\n")
    );
}

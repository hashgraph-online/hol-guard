//! Replays embedded-script evidence recorded from the retired Python owner.
//!
//! A vector may be hand-corrected where the owner disagreed with bash:
//! `heredoc_comment` recorded a declaration for `<<EOF` written inside a `#`
//! comment, which bash never reads as one. `record_vectors.py` documents each
//! such case.
use crate::embedded_script_evidence::embedded_script_evidence_entries;
use crate::shell_helpers;
use serde_json::{json, Value};

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../testdata/embedded_script_evidence/vectors.json"
    ))
    .expect("vectors parse")
}

/// The vectors were recorded on POSIX. On Windows the shell tokenizer keeps
/// unquoted backslashes literal (as the Python owner's `windows_tokens` path
/// did), so a vector whose owner depends on that carries `windows_entries`.
fn expected(vector: &Value) -> &Value {
    match vector.get("windows_entries") {
        Some(entries) if cfg!(windows) => entries,
        _ => &vector["entries"],
    }
}

#[test]
fn embedded_script_evidence_matches_recorded_python_vectors() {
    let vectors = vectors();
    assert!(vectors.len() >= 60, "vector corpus shrank");
    let mut mismatches = Vec::new();
    for vector in &vectors {
        let name = vector["name"].as_str().expect("vector name");
        let command = vector["command"].as_str().expect("vector command");
        let observed = Value::Array(embedded_script_evidence_entries(command));
        if &observed != expected(vector) {
            mismatches.push(format!(
                "{name}: rust={observed} python={}",
                expected(vector)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn shell_helpers_action_projects_the_same_entries() {
    for vector in vectors() {
        let command = vector["command"].as_str().expect("vector command");
        let observed =
            shell_helpers::evaluate("embedded_script_evidence", &json!({"command": command}))
                .expect("action evaluates");
        assert_eq!(&observed, expected(&vector), "{}", vector["name"]);
    }
}

#[test]
fn shell_helpers_action_rejects_unknown_fields() {
    let input = json!({"command": "bash <<EOF\necho\nEOF", "cwd": "/"});
    assert_eq!(
        shell_helpers::evaluate("embedded_script_evidence", &input),
        Err("shell_helpers_invalid")
    );
}

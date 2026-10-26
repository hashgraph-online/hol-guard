use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::compound_artifact;
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};

/// Recorded from `_compound_runtime_artifact` before the port, with the
/// workspace and home paths tokenized and the inode-bound context hash masked.
const VECTORS: &str = include_str!("../tests/fixtures/compound_runtime_artifact_vectors.json");
const INODE_BOUND: &str = "<inode-bound>";

struct Host;

impl InspectionHost for Host {
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
        GitRun::Failed("unavailable")
    }
}

/// A fresh `ws/src` workspace and `home` directory, removed on drop.
struct Roots {
    root: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
}

impl Roots {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-compound-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ws/src")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        let root = root.canonicalize().unwrap();
        Self {
            workspace: root.join("ws"),
            home: root.join("home"),
            root,
        }
    }

    fn tokenize(&self, value: &Value) -> Value {
        let text = value
            .to_string()
            .replace(
                &self.workspace.to_string_lossy().into_owned(),
                "{workspace}",
            )
            .replace(&self.home.to_string_lossy().into_owned(), "{home}");
        serde_json::from_str(&text).unwrap()
    }
}

impl Drop for Roots {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn compose(roots: &Roots, input: &Value, workspace: bool) -> Result<Value, &'static str> {
    let host = Host;
    let process_cwd = roots.workspace.to_string_lossy().into_owned();
    let ctx = Ctx::new(&host, &process_cwd, "/nonexistent-default-home");
    let workspace = workspace.then_some(roots.workspace.as_path());
    compound_artifact(input, workspace, Some(roots.home.as_path()), &ctx)
}

/// The primary's metadata after Python applies the reply.
fn applied(primary: &Value, findings: usize, reply: &Value) -> Vec<(String, Value)> {
    let mut metadata: Vec<(String, Value)> = primary["metadata"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if findings > 1 {
        metadata.retain(|(key, _)| key != "extension_allow_hint");
    }
    for pair in reply["metadata"].as_array().unwrap() {
        let key = pair[0].as_str().unwrap().to_owned();
        let value = pair[1].clone();
        match metadata.iter_mut().find(|(seen, _)| *seen == key) {
            Some(slot) => slot.1 = value,
            None => metadata.push((key, value)),
        }
    }
    metadata
}

#[test]
fn recorded_python_vectors_compose_identically() {
    let fixture: Value = serde_json::from_str(VECTORS).unwrap();
    let roots = Roots::new("vectors");
    let vectors = fixture["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 100);
    for vector in vectors {
        let findings = &fixture["artifact_sets"][vector["set"].as_str().unwrap()];
        let command = &vector["command_text"];
        let decision = command.is_string().then(|| {
            json!({
                "command_action_floor": "require-reapproval",
                "command_evaluation_status": "native_unavailable",
            })
        });
        let input = json!({"artifacts": findings, "command_text": command, "decision": decision});
        let reply = compose(&roots, &input, vector["workspace"].as_bool().unwrap()).unwrap();
        assert_eq!(reply["primary"], vector["primary"], "{vector}");
        let expected = &vector["expected"];
        if expected.is_null() {
            assert!(reply["metadata"].is_null(), "{vector}");
            continue;
        }
        assert_eq!(reply["artifact_id"], expected["artifact_id"], "{vector}");
        assert_eq!(reply["name"], expected["name"], "{vector}");
        let primary = &findings[vector["primary"].as_u64().unwrap() as usize];
        let actual = applied(primary, findings.as_array().unwrap().len(), &reply);
        let expected_pairs = expected["metadata"].as_array().unwrap();
        assert_eq!(actual.len(), expected_pairs.len(), "{vector}");
        // serde_json maps sort their keys, so only the keys the reply adds
        // keep a comparable order; the primary's own keys compare by value.
        let original = primary["metadata"].as_object().unwrap();
        let added = |key: &str| !original.contains_key(key);
        let actual_added: Vec<&str> = actual
            .iter()
            .map(|(key, _)| key.as_str())
            .filter(|key| added(key))
            .collect();
        let expected_added: Vec<&str> = expected_pairs
            .iter()
            .map(|pair| pair[0].as_str().unwrap())
            .filter(|key| added(key))
            .collect();
        assert_eq!(actual_added, expected_added, "{vector}");
        for pair in expected_pairs {
            let key = pair[0].as_str().unwrap();
            let (_, value) = actual
                .iter()
                .find(|(seen, _)| seen == key)
                .unwrap_or_else(|| panic!("{key} in {vector}"));
            if pair[1] == INODE_BOUND {
                assert!(value
                    .as_str()
                    .is_some_and(|hash| hash.starts_with("sha256:")));
                continue;
            }
            assert_eq!(roots.tokenize(value), pair[1], "{key} in {vector}");
        }
    }
}

#[test]
fn a_bounded_model_failure_is_an_incomplete_context() {
    let roots = Roots::new("bounds");
    let command = "true;".repeat(guard_contracts::MAX_REQUEST_CONTEXT_SEGMENTS + 1);
    let input = json!({
        "artifacts": [{"artifact_id": "a:b", "artifact_type": "tool_action_request", "name": "n", "metadata": {}}],
        "command_text": command,
    });
    let reply = compose(&roots, &input, true).unwrap();
    let metadata: Map<String, Value> = reply["metadata"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].clone()))
        .collect();
    assert_eq!(metadata["compound_complete"], false);
    assert_eq!(metadata["shell_execution_context_complete"], false);
    assert_eq!(
        metadata["shell_execution_context_reason_code"],
        "shell_cwd_native_unavailable"
    );
    assert_eq!(metadata["guard_default_action"], "require-reapproval");
}

#[test]
fn malformed_input_is_rejected() {
    let roots = Roots::new("malformed");
    let finding = json!({"artifact_id": "a", "artifact_type": "t", "name": "n", "metadata": {}});
    for input in [
        json!({"artifacts": [], "command_text": "ls"}),
        json!({"artifacts": [{"artifact_id": "a"}], "command_text": "ls"}),
        json!({"artifacts": [finding], "command_text": "  "}),
        json!({"artifacts": [finding], "command_text": 3}),
        json!({"artifacts": [finding], "command_text": "ls", "decision": []}),
    ] {
        assert_eq!(
            compose(&roots, &input, true),
            Err("native_sensitive_request_input_invalid"),
            "{input}"
        );
    }
    let host = Host;
    let ctx = Ctx::new(&host, "/work", "/home/user");
    let input = json!({"artifacts": [finding], "command_text": "ls"});
    assert_eq!(
        compound_artifact(&input, Some(Path::new("/work")), None, &ctx),
        Err("native_sensitive_request_input_invalid")
    );
}

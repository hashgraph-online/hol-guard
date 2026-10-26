use std::path::PathBuf;

use serde_json::{json, Value};
use sha2::Digest;

use super::unmodeled_shell_artifact;
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};

/// Recorded from `_unmodeled_shell_runtime_artifact` before the port, with
/// the workspace and home paths tokenized and the inode-bound context hash
/// masked.
const VECTORS: &str = include_str!("../tests/fixtures/unmodeled_shell_artifact_vectors.json");
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

/// A fresh `ws/src` workspace and `home/proj` directory, removed on drop.
struct Roots {
    root: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
}

impl Roots {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-unmodeled-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ws/src")).unwrap();
        std::fs::create_dir_all(root.join("home/proj")).unwrap();
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

fn review(roots: &Roots, input: &Value) -> Result<Value, &'static str> {
    let host = Host;
    let process_cwd = roots.workspace.to_string_lossy().into_owned();
    let ctx = Ctx::new(&host, &process_cwd, "/nonexistent-default-home");
    unmodeled_shell_artifact(input, &ctx)
}

/// The artifact id Python derives from the reply's own inode-bound context
/// hash, for vectors whose recorded hash cannot be replayed.
fn rebound_artifact_id(reply: &Value) -> String {
    let field = |key: &str| {
        reply["metadata"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pair| pair[0] == key)
            .map(|pair| pair[1].clone())
            .unwrap()
    };
    let identity = json!({
        "version": 1,
        "command_security_identity": field("command_security_identity"),
        "shell_execution_context_hash": field("shell_execution_context_hash"),
        "reason_code": field("command_uncertainty_reason"),
    });
    let mut canonical = Vec::new();
    guard_contracts::write_canonical_json(&identity, &mut canonical).unwrap();
    format!(
        "codex:project:unmodeled-shell:{:x}",
        sha2::Sha256::digest(&canonical)
    )
}

#[test]
fn recorded_python_vectors_review_identically() {
    let fixture: Value = serde_json::from_str(VECTORS).unwrap();
    let roots = Roots::new("vectors");
    let vectors = fixture["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 60);
    let mut reviewed = 0;
    for vector in vectors {
        let workspace = vector["workspace"]
            .as_bool()
            .unwrap()
            .then(|| roots.workspace.to_string_lossy().into_owned());
        let input = json!({
            "command_text": vector["command_text"],
            "workspace": workspace,
            "home": roots.home.to_string_lossy(),
        });
        let reply = review(&roots, &input).unwrap();
        let expected = &vector["expected"];
        if expected.is_null() {
            assert!(reply.is_null(), "{vector} -> {reply}");
            continue;
        }
        reviewed += 1;
        let artifact_id = format!(
            "codex:project:unmodeled-shell:{}",
            reply["fingerprint"].as_str().unwrap()
        );
        if expected["artifact_id"] == INODE_BOUND {
            assert_eq!(artifact_id, rebound_artifact_id(&reply), "{vector}");
        } else {
            assert_eq!(artifact_id, expected["artifact_id"], "{vector}");
        }
        let actual = reply["metadata"].as_array().unwrap();
        let expected_pairs = expected["metadata"].as_array().unwrap();
        assert_eq!(actual.len(), expected_pairs.len(), "{vector}");
        for (pair, expected_pair) in actual.iter().zip(expected_pairs) {
            assert_eq!(pair[0], expected_pair[0], "{vector}");
            if expected_pair[1] == INODE_BOUND {
                assert!(pair[1]
                    .as_str()
                    .is_some_and(|hash| hash.starts_with("sha256:")));
                continue;
            }
            assert_eq!(roots.tokenize(&pair[1]), expected_pair[1], "{vector}");
        }
    }
    assert!(reviewed >= 20);
}

#[test]
fn malformed_input_is_rejected() {
    let roots = Roots::new("malformed");
    for input in [
        json!({"command_text": "ls", "workspace": null}),
        json!({"command_text": 3, "home": "/h"}),
        json!({"command_text": "ls", "workspace": 1, "home": "/h"}),
        json!({"command_text": "ls", "home": "/h\u{0}"}),
    ] {
        assert_eq!(
            review(&roots, &input),
            Err("native_sensitive_request_input_invalid"),
            "{input}"
        );
    }
}

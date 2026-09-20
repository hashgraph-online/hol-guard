#[path = "../src/policy_scoped_artifact_identity.rs"]
mod artifact_identity;

use artifact_identity::derive_typed_shell_artifact;
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::{json, Value};
use std::path::PathBuf;

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let path =
            std::env::temp_dir().join(format!("guard-typed-identity-{}", hex::encode(random)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn envelope(&self, payload: Value, harness: &str) -> GuardHookEnvelopeV2 {
        serde_json::from_value(json!({
            "schema":"guard-hook-envelope.v2", "harness":harness,"event":"PreToolUse",
            "raw_payload":payload,"policy_generation":1,"policy_snapshot":{},
            "source":{"cwd":self.0,"home_dir":self.0,"guard_home":self.0}
        }))
        .unwrap()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn typed_artifacts_match_shared_actual_python_producer_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/typed-artifact-sources.json")).unwrap();
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 32);
    for case in fixture["cases"].as_array().unwrap() {
        let workspace = Workspace::new();
        for path in case["workspaceFiles"].as_array().unwrap() {
            std::fs::write(workspace.0.join(path.as_str().unwrap()), "{}").unwrap();
        }
        let harness = case["harness"].as_str().unwrap();
        let source = workspace.envelope(case["payload"].clone(), harness);
        let identity = derive_typed_shell_artifact(&source, harness).unwrap();
        assert_eq!(identity.artifact_id, case["artifactId"], "{}", case["name"]);
        assert_eq!(
            identity.artifact_type, case["artifactType"],
            "{}",
            case["name"]
        );
        assert_eq!(
            identity.exact_command_sha256, case["sha256"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn changing_observed_workspace_paths_changes_the_package_identity() {
    let workspace = Workspace::new();
    let source = workspace.envelope(
        json!({"tool_name":"Bash","tool_input":{"command":"npm ci"}}),
        "codex",
    );
    let original = derive_typed_shell_artifact(&source, "codex").unwrap();
    std::fs::write(workspace.0.join("package-lock.json"), "{}").unwrap();
    let changed = derive_typed_shell_artifact(&source, "codex").unwrap();
    assert_ne!(original.artifact_id, changed.artifact_id);
    assert_eq!(original.exact_command_sha256, changed.exact_command_sha256);
}

#[test]
fn caller_labels_do_not_replace_identity_and_original_command_bytes_remain_distinct() {
    let workspace = Workspace::new();
    let mut source = workspace.envelope(
        json!({"tool_name":"Bash","tool_input":{"command":"npm ci"}}),
        "codex",
    );
    let original = derive_typed_shell_artifact(&source, "codex").unwrap();
    source.raw_payload["artifact_id"] = json!("synthetic:forged-artifact");
    source.raw_payload["exact_command_sha256"] = json!("0".repeat(64));
    assert_eq!(
        derive_typed_shell_artifact(&source, "codex").unwrap(),
        original
    );
    source.raw_payload["tool_input"]["command"] = json!("\t npm ci \r\n");
    let changed = derive_typed_shell_artifact(&source, "codex").unwrap();
    assert_eq!(original.artifact_id, changed.artifact_id);
    assert_ne!(original.exact_command_sha256, changed.exact_command_sha256);
    assert!(derive_typed_shell_artifact(&source, "claude-code").is_err());
    source.event = "PostToolUse".to_owned();
    assert!(derive_typed_shell_artifact(&source, "codex").is_err());
}

#[cfg(unix)]
#[test]
fn unbounded_manifest_symlink_is_not_an_observed_workspace_dependency() {
    use std::os::unix::fs::symlink;
    let workspace = Workspace::new();
    let outside = Workspace::new();
    std::fs::write(outside.0.join("package.json"), "{}").unwrap();
    symlink(
        outside.0.join("package.json"),
        workspace.0.join("package.json"),
    )
    .unwrap();
    let source = workspace.envelope(
        json!({"tool_name":"Bash","tool_input":{"command":"npm ci"}}),
        "codex",
    );
    assert!(derive_typed_shell_artifact(&source, "codex").is_err());
    std::fs::remove_file(workspace.0.join("package.json")).unwrap();
    std::fs::write(workspace.0.join("manifest.json"), "{}").unwrap();
    symlink(
        workspace.0.join("manifest.json"),
        workspace.0.join("package.json"),
    )
    .unwrap();
    assert!(derive_typed_shell_artifact(&source, "codex").is_err());
}

#[test]
fn a_dependency_path_directory_requires_a_separate_producer_shape() {
    let workspace = Workspace::new();
    std::fs::create_dir(workspace.0.join("package.json")).unwrap();
    let source = workspace.envelope(
        json!({"tool_name":"Bash","tool_input":{"command":"npm ci"}}),
        "codex",
    );
    assert!(derive_typed_shell_artifact(&source, "codex").is_err());
}

#[test]
fn unproven_execution_context_or_ambiguous_source_is_refused() {
    let workspace = Workspace::new();
    for command in [
        "cd . && npm ci",
        "env npm ci",
        "PATH=/synthetic npm ci",
        "npm ci; pwd",
        "npm exec synthetic-package",
        "npm install git+https://example.invalid/source",
        "npm install --global synthetic-package",
        "npm install ../source",
        "npm install @@synthetic/package",
        "npm install @synthetic/package@",
        "npm ci > output",
        "ssh -o ProxyCommand=anything synthetic-host id",
        "ssh synthetic-host 'id'",
        "ssh synthetic-host rm",
        "ssh synthetic-host",
        "npm  ci",
    ] {
        let source = workspace.envelope(
            json!({"tool_name":"Bash","tool_input":{"command":command}}),
            "codex",
        );
        assert!(
            derive_typed_shell_artifact(&source, "codex").is_err(),
            "{command}"
        );
    }
    let original = json!({"tool_name":"Bash","tool_input":{"command":"npm ci"}});
    for (key, value) in [
        ("arguments", json!({"command":"npm ci"})),
        ("toolName", json!("Bash")),
        ("guard_source_ref", json!({})),
        ("source_scope", json!("user")),
        ("sourceScope", json!("user")),
        ("eventName", json!("PostToolUse")),
        ("hookEventName", json!("PostToolUse")),
        ("hookName", json!("PermissionRequest")),
    ] {
        let mut payload = original.clone();
        payload[key] = value;
        assert!(
            derive_typed_shell_artifact(&workspace.envelope(payload, "codex"), "codex").is_err()
        );
    }
    let mut source = workspace.envelope(original, "codex");
    source.source.cwd = Some(workspace.0.join("missing").to_string_lossy().into_owned());
    assert!(derive_typed_shell_artifact(&source, "codex").is_err());
}

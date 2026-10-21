//! Parity vectors recorded from the retired Python implementation
//! (`github_workflow_operations.py`, `github_workflow_authorization.py`,
//! `github_workflow_context.py` digests, and `_persisted_command_matches_record`),
//! (stub-executable runs live in `github_workflow_prepare_op_stub_tests.rs`).

use super::*;
use crate::store_vectors_support_tests::gunzip_json;
use guard_command::command_model::CanonicalCommand;
use guard_command::github_workflow_operations::GitHubWorkflowOperation;
#[cfg(unix)]
use std::path::PathBuf;

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/github_workflow_vectors.json.gz");

fn vectors() -> Value {
    gunzip_json(VECTORS)
}

fn parse_plain(text: &str) -> Option<CanonicalCommand> {
    parse(text, None, None)
}

#[cfg(unix)]
pub(super) fn temp_dir(label: &str) -> PathBuf {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("ghwf-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn operations_match_the_retired_python() {
    let vectors = vectors();
    let cases = vectors["operations"].as_array().unwrap();
    assert!(cases.len() > 400);
    for (index, case) in cases.iter().enumerate() {
        let text = case["command"].as_str().unwrap();
        let repository = case["repository"].as_str();
        let executable = case["expected_executable"].as_str().unwrap();
        let actual = parse_plain(text)
            .and_then(|command| parse_github_workflow_operation(&command, repository, executable))
            .map(|operation| serde_json::to_value(operation).unwrap());
        let expected = (!case["expected"].is_null()).then(|| case["expected"].clone());
        assert_eq!(
            actual, expected,
            "case {index}: {text:?} repo={repository:?}"
        );
    }
}

fn context_from(value: &Value) -> GitHubWorkflowBindingContext {
    let text = |key: &str| value[key].as_str().unwrap().to_owned();
    GitHubWorkflowBindingContext {
        repository_sha256: text("repository_sha256"),
        workspace_sha256: text("workspace_sha256"),
        executable_sha256: text("executable_sha256"),
        cwd_sha256: text("cwd_sha256"),
        environment_sha256: text("environment_sha256"),
        configuration_sha256: text("configuration_sha256"),
        manifest_sha256: text("manifest_sha256"),
        lockfile_sha256: text("lockfile_sha256"),
        sandbox_sha256: text("sandbox_sha256"),
        policy_id: text("policy_id"),
        policy_version: text("policy_version"),
        effect_id: text("effect_id"),
        effect_version: text("effect_version"),
        decision_id: text("decision_id"),
        decision_version: text("decision_version"),
        rules: value["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| WorkflowCapabilityRuleBinding {
                rule_id: rule["rule_id"].as_str().unwrap().to_owned(),
                rule_version: rule["rule_version"].as_str().unwrap().to_owned(),
            })
            .collect(),
    }
}

#[test]
fn records_match_the_retired_python() {
    let vectors = vectors();
    let cases = vectors["bindings"].as_array().unwrap();
    assert_eq!(cases.len(), 100);
    for (index, case) in cases.iter().enumerate() {
        let operation: GitHubWorkflowOperation =
            serde_json::from_value(case["operation"].clone()).unwrap();
        let actual = approval_record_from_operation(&operation, &context_from(&case["context"]));
        match (&case["expected"]["record"], &case["expected"]["error"]) {
            (record, Value::Null) => {
                assert_eq!(actual.unwrap().to_value(), *record, "case {index}");
            }
            (_, error) => {
                assert_eq!(actual.err().as_deref(), error.as_str(), "case {index}");
            }
        }
    }
}

#[test]
fn framed_digests_match_the_retired_python() {
    let vectors = vectors();
    for case in vectors["digests"].as_array().unwrap() {
        let purpose = case["purpose"].as_str().unwrap();
        let actual = framed_digest(purpose, &case["payload"]);
        assert_eq!(actual.as_deref(), case["expected"].as_str(), "{purpose}");
    }
}

#[cfg(unix)]
#[test]
fn workspace_file_digests_match_the_retired_python() {
    let vectors = vectors();
    let root = temp_dir("files");
    for case in vectors["workspace_files"].as_array().unwrap() {
        for child in std::fs::read_dir(&root).unwrap() {
            let path = child.unwrap().path();
            if path.is_dir() && !path.is_symlink() {
                std::fs::remove_dir_all(path).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
        }
        for (name, content) in case["files"].as_object().unwrap() {
            let path = root.join(name);
            match content {
                Value::Null => std::fs::create_dir(&path).unwrap(),
                Value::Object(link) => {
                    std::os::unix::fs::symlink(link["symlink"].as_str().unwrap(), &path).unwrap();
                }
                text => std::fs::write(&path, text.as_str().unwrap()).unwrap(),
            }
        }
        let names: Vec<&str> = case["names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        let actual = workspace_file_entries(&root, &names)
            .and_then(|entries| workspace_files_digest(&entries));
        assert_eq!(
            actual.as_deref(),
            case["expected"]["digest"].as_str(),
            "{}",
            case["name"]
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
pub(super) fn write_executable(path: &Path, content: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn persisted_verification_matches_the_retired_python() {
    let vectors = vectors();
    let root = temp_dir("persisted");
    let contents = &vectors["persisted_executables"];
    let primary = root.join("gh");
    let other = root.join("gh-other");
    let noexec = root.join("gh-noexec");
    let link = root.join("gh-link");
    write_executable(&primary, contents["primary"].as_str().unwrap(), 0o755);
    write_executable(&other, contents["other"].as_str().unwrap(), 0o755);
    write_executable(&noexec, contents["noexec"].as_str().unwrap(), 0o644);
    std::os::unix::fs::symlink(&primary, &link).unwrap();
    let path_for = |name: &str| match name {
        "link" => &link,
        "other" => &other,
        "noexec" => &noexec,
        _ => &primary,
    };
    for case in vectors["persisted"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let fill = |template: &str, executable: &str| {
            template.replace("{exe}", path_for(executable).to_str().unwrap())
        };
        let record_exe = case["record_executable"].as_str().unwrap();
        let record_text = fill(
            case["record_command_template"].as_str().unwrap(),
            record_exe,
        );
        let record_command = parse_plain(&record_text).unwrap();
        let operation = parse_github_workflow_operation(
            &record_command,
            Some("example/repo"),
            path_for(record_exe).to_str().unwrap(),
        )
        .unwrap_or_else(|| panic!("{name}: record command must parse"));
        let mut context = vectors_context(case["context_executable_sha256"].as_str().unwrap());
        context.executable_sha256 = case["context_executable_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let record = approval_record_from_operation(&operation, &context).unwrap();
        let mut value = record.to_value();
        if let Some(mutation) = case["mutation"].as_object() {
            for (key, replacement) in mutation {
                match key.split_once('.') {
                    Some((outer, inner)) => value[outer][inner] = replacement.clone(),
                    None => value[key] = replacement.clone(),
                }
            }
        }
        let executable = case["executable"].as_str().unwrap_or("primary");
        let text = fill(case["command_template"].as_str().unwrap(), executable);
        let actual = GitHubWorkflowApprovalRecord::decode(&value)
            .is_ok_and(|decoded| persisted_matches(&text, &decoded));
        assert_eq!(actual, case["expected"].as_bool().unwrap(), "{name}");
    }
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
fn label_sha(label: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(label.as_bytes()))
}

#[cfg(unix)]
pub(super) fn vectors_context(executable_sha256: &str) -> GitHubWorkflowBindingContext {
    GitHubWorkflowBindingContext {
        repository_sha256: github_repository_sha256("example/repo").unwrap(),
        workspace_sha256: label_sha("workspace"),
        executable_sha256: executable_sha256.to_owned(),
        cwd_sha256: label_sha("cwd"),
        environment_sha256: label_sha("env"),
        configuration_sha256: label_sha("cfg"),
        manifest_sha256: label_sha("manifest"),
        lockfile_sha256: label_sha("lock"),
        sandbox_sha256: label_sha("sandbox"),
        policy_id: "guard.command-policy".to_owned(),
        policy_version: "policy.v1@abc".to_owned(),
        effect_id: "github.maintain-remote".to_owned(),
        effect_version: "effect.v1".to_owned(),
        decision_id: "github.workflow-authorized".to_owned(),
        decision_version: "decision.v1".to_owned(),
        rules: vec![WorkflowCapabilityRuleBinding {
            rule_id: "github.maintain-remote".to_owned(),
            rule_version: "rule.v1".to_owned(),
        }],
    }
}

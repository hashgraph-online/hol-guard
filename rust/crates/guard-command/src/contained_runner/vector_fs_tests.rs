//! Parity of snapshots, TypeScript inputs and launch evidence with vectors
//! recorded from the original Python implementation.

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::contract::Input;
use super::node_evidence::build_local_node_runner_evidence;
use super::script_evidence::build_local_package_script_evidence;
use super::snapshot::complete_workspace_snapshot;
use super::ts_inputs::typescript_snapshot_inputs;
use super::vector_support::{fixture_of, section, strings, text, Workspace};

fn pairs(inputs: &[Input]) -> Value {
    Value::Array(
        inputs
            .iter()
            .map(|item| serde_json::json!([item.snapshot_path, item.content_digest]))
            .collect(),
    )
}

fn framed(prefix: &[u8], encoded: &str) -> String {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoded.as_bytes());
    hex::encode(Sha256::digest(&bytes))
}

#[test]
fn workspace_snapshots_match_python() {
    for case in section("workspace_snapshot") {
        let id = text(case, "id");
        let workspace = Workspace::with_fixture(fixture_of(case));
        let observed = complete_workspace_snapshot(
            &workspace.path,
            case["exclude_protected"] == Value::Bool(true),
        );
        let expected = &case["expected"];
        match (observed, expected["error"].as_str()) {
            (Ok((digest, inputs)), None) => {
                assert_eq!(digest, text(expected, "digest"), "{id}");
                assert_eq!(pairs(&inputs), expected["inputs"], "{id}");
            }
            (Err(error), Some(message)) => assert_eq!(error, message, "{id}"),
            (observed, _) => panic!(
                "{id}: diverged: {:?} vs {expected}",
                observed.map(|(digest, _)| digest)
            ),
        }
    }
}

#[test]
fn typescript_inputs_match_python() {
    for case in section("typescript_inputs") {
        let id = text(case, "id");
        let workspace = Workspace::with_fixture(fixture_of(case));
        let package = workspace.path.join(text(case, "package"));
        let observed =
            typescript_snapshot_inputs(&workspace.path, &package, &strings(&case["sources"]));
        let expected = &case["expected"];
        match (observed, expected["error"].as_str()) {
            (Ok(inputs), None) => {
                assert_eq!(inputs.tree_digest, text(expected, "tree_digest"), "{id}");
                assert_eq!(
                    pairs(&inputs.package_inputs),
                    expected["package_inputs"],
                    "{id}"
                );
                assert_eq!(
                    inputs.closure_digest,
                    text(expected, "closure_digest"),
                    "{id}"
                );
                assert_eq!(
                    pairs(&inputs.closure_inputs),
                    expected["closure_inputs"],
                    "{id}"
                );
            }
            (Err(error), Some(message)) => assert_eq!(error, message, "{id}"),
            (observed, _) => panic!(
                "{id}: diverged: {:?} vs {expected}",
                observed.map(|item| item.tree_digest)
            ),
        }
    }
}

fn optional(workspace: &Workspace, value: &Value) -> Option<String> {
    value.as_str().map(|item| workspace.expand(item))
}

#[test]
fn node_runner_evidence_matches_python() {
    for case in section("node_evidence") {
        let id = text(case, "id");
        let workspace = Workspace::with_fixture(fixture_of(case));
        let execution = workspace.expand_value(&case["execution"]);
        let observed = build_local_node_runner_evidence(
            &text(case, "manager"),
            &strings(&case["argv"]),
            &execution,
            &workspace.path,
        )
        .expect("evidence");
        let expected = &case["expected"];
        if expected.is_null() {
            assert!(observed.is_none(), "{id}");
            continue;
        }
        let evidence = observed.unwrap_or_else(|| panic!("{id}: missing evidence"));
        assert_eq!(evidence.complete, expected["status"] == "complete", "{id}");
        assert_eq!(evidence.reasons, strings(&expected["reasons"]), "{id}");
        assert_eq!(evidence.runner, text(expected, "runner"), "{id}");
        assert_eq!(
            evidence.operation_id,
            text(expected, "operation_id"),
            "{id}"
        );
        assert_eq!(
            evidence.runner_args,
            strings(&expected["runner_args"]),
            "{id}"
        );
        assert_eq!(
            evidence.input_files,
            strings(&expected["input_files"]),
            "{id}"
        );
        assert_eq!(
            evidence.executable_path,
            optional(&workspace, &expected["executable_path"]),
            "{id}"
        );
        assert_eq!(
            evidence.executable_hash.as_deref(),
            expected["executable_hash"].as_str(),
            "{id}"
        );
        assert_eq!(
            evidence.root_manifest_hash.as_deref(),
            expected["root_manifest_hash"].as_str(),
            "{id}"
        );
        assert_eq!(
            evidence.lockfile_hash.as_deref(),
            expected["lockfile_hash"].as_str(),
            "{id}"
        );
        assert_eq!(
            evidence.package_manifest_hash.as_deref(),
            expected["package_manifest_hash"].as_str(),
            "{id}"
        );
        let encoded = workspace.expand(&text(expected, "binding_encoded"));
        assert_eq!(
            evidence.binding_digest,
            framed(b"hol-guard:local-node-runner-evidence:v1\0", &encoded),
            "{id}"
        );
    }
}

#[test]
fn package_script_evidence_matches_python() {
    for case in section("package_script_evidence") {
        let id = text(case, "id");
        let workspace = Workspace::with_fixture(fixture_of(case));
        let observed = build_local_package_script_evidence(
            &text(case, "manager"),
            &strings(&case["argv"]),
            &workspace.path,
        )
        .expect("evidence");
        let expected = &case["expected"];
        if expected.is_null() {
            assert!(observed.is_none(), "{id}");
            continue;
        }
        let evidence = observed.unwrap_or_else(|| panic!("{id}: missing evidence"));
        assert_eq!(evidence.complete, expected["status"] == "complete", "{id}");
        assert_eq!(evidence.reasons, strings(&expected["reasons"]), "{id}");
        assert_eq!(evidence.runner, text(expected, "runner"), "{id}");
        assert_eq!(
            evidence.operation_id,
            text(expected, "operation_id"),
            "{id}"
        );
        assert_eq!(
            evidence.runner_args,
            strings(&expected["runner_args"]),
            "{id}"
        );
        assert_eq!(
            evidence.input_files,
            strings(&expected["input_files"]),
            "{id}"
        );
        assert_eq!(
            evidence.executable_path,
            optional(&workspace, &expected["executable_path"]),
            "{id}"
        );
        assert_eq!(
            evidence.executable_hash.as_deref(),
            expected["executable_hash"].as_str(),
            "{id}"
        );
        assert_eq!(
            evidence.root_manifest_hash.as_deref(),
            expected["root_manifest_hash"].as_str(),
            "{id}"
        );
        assert_eq!(
            evidence.lockfile_hash.as_deref(),
            expected["lockfile_hash"].as_str(),
            "{id}"
        );
        assert_eq!(
            evidence.package_manifest_hash.as_deref(),
            expected["package_manifest_hash"].as_str(),
            "{id}"
        );
        let encoded = workspace.expand(&text(expected, "binding_encoded"));
        assert_eq!(evidence.binding_digest, framed(b"", &encoded), "{id}");
    }
}

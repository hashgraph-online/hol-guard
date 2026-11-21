//! What the resident may rebuild from an intent the host already holds.
//!
//! Every field these decoders read is hashed into the package request
//! fingerprint, which is the key a saved package approval is stored under. The
//! tests pin the two halves of that: an exact payload rebuilds the intent that
//! produced it, and a payload Guard cannot read exactly is refused outright
//! rather than repaired into an intent with a different name.

use serde_json::{json, Value};

use crate::package_intent_common::{
    build_package_request_artifact, LocalPackageExecutionEvidence, PackageExecutionFileEvidence,
    PackageIntent, PackageIntentTarget,
};

fn target() -> PackageIntentTarget {
    PackageIntentTarget {
        ecosystem: "npm".to_owned(),
        package_name: Some("left-pad".to_owned()),
        raw_spec: "git+https://token@example.test/left-pad.git#v1".to_owned(),
        requested_specifier: Some("1.3.0".to_owned()),
        source_url: Some("https://token@example.test/left-pad.git".to_owned()),
        source_kind: Some("registry".to_owned()),
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: None,
        alias: None,
        dependency_group: Some("dev".to_owned()),
        extras: vec!["cli".to_owned()],
        editable: false,
    }
}

fn evidence() -> LocalPackageExecutionEvidence {
    LocalPackageExecutionEvidence {
        manager_name: "npm".to_owned(),
        path_source: "workspace".to_owned(),
        effective_cwd: "/work".to_owned(),
        cwd_source: "tool_input".to_owned(),
        manager_is_guard_shim: false,
        local_only_requested: true,
        context_hash: "ctx-1".to_owned(),
        package_name: Some("left-pad".to_owned()),
        executable_name: Some("npm".to_owned()),
        declared_version: Some("1.3.0".to_owned()),
        manager: Some(PackageExecutionFileEvidence {
            path: "/work/node_modules/.bin/npm".to_owned(),
            resolved_path: Some("/work/node_modules/.bin/npm".to_owned()),
            status: "available",
            file_identity: Some("dev:ino".to_owned()),
            content_hash: Some("sha256:abc".to_owned()),
        }),
        local_executable: Some(PackageExecutionFileEvidence {
            // A path Guard could not resolve carries a null, and the null is
            // what the fingerprint hashed.
            path: "/work/node_modules/.bin/left-pad".to_owned(),
            resolved_path: None,
            status: "missing",
            file_identity: None,
            content_hash: None,
        }),
        manifests: vec![PackageExecutionFileEvidence {
            path: "/work/package.json".to_owned(),
            resolved_path: Some("/work/package.json".to_owned()),
            status: "available",
            file_identity: None,
            content_hash: Some("sha256:manifest".to_owned()),
        }],
        lockfiles: Vec::new(),
        typescript_launch: Some(json!({"runner": "tsx"})),
    }
}

fn intent() -> PackageIntent {
    PackageIntent {
        package_manager: "npm".to_owned(),
        intent_kind: "install",
        command_tokens: vec![
            "npm".to_owned(),
            "install".to_owned(),
            "git+https://token@example.test/left-pad.git#v1".to_owned(),
        ],
        redacted_command: "npm install git+https://example.test/left-pad.git".to_owned(),
        targets: vec![target()],
        manifest_paths: vec!["/work/package.json".to_owned()],
        lockfile_paths: vec!["/work/package-lock.json".to_owned()],
        flags: vec!["--save-dev".to_owned()],
        notes: vec!["dev dependency".to_owned()],
        local_executions: vec![evidence()],
        execution_context_hashes: vec!["ctx-1".to_owned()],
        execution_context_cwds: vec!["/work".to_owned()],
        execution_context_reason_codes: Vec::new(),
        routine_local_runner: false,
    }
}

/// The `asdict` form of `intent()` — `PackageIntent.to_execution_dict` has no
/// Python spelling of its own, so the wire carries `asdict(intent)`: nested
/// dataclasses as plain dicts and exact values throughout.
fn exact_payload() -> Value {
    json!({
        "package_manager": "npm",
        "intent_kind": "install",
        "command_tokens": [
            "npm",
            "install",
            "git+https://token@example.test/left-pad.git#v1",
        ],
        "redacted_command": "npm install git+https://example.test/left-pad.git",
        "targets": [{
            "ecosystem": "npm",
            "package_name": "left-pad",
            "raw_spec": "git+https://token@example.test/left-pad.git#v1",
            "requested_specifier": "1.3.0",
            "source_url": "https://token@example.test/left-pad.git",
            "source_kind": "registry",
            "source_repository": null,
            "source_revision_kind": null,
            "source_identity": null,
            "source_invalid_reason": null,
            "alias": null,
            "dependency_group": "dev",
            "extras": ["cli"],
            "editable": false,
        }],
        "manifest_paths": ["/work/package.json"],
        "lockfile_paths": ["/work/package-lock.json"],
        "flags": ["--save-dev"],
        "notes": ["dev dependency"],
        "local_executions": [{
            "manager_name": "npm",
            "path_source": "workspace",
            "effective_cwd": "/work",
            "cwd_source": "tool_input",
            "manager_is_guard_shim": false,
            "local_only_requested": true,
            "context_hash": "ctx-1",
            "package_name": "left-pad",
            "executable_name": "npm",
            "declared_version": "1.3.0",
            "manager": {
                "path": "/work/node_modules/.bin/npm",
                "resolved_path": "/work/node_modules/.bin/npm",
                "status": "available",
                "file_identity": "dev:ino",
                "content_hash": "sha256:abc",
            },
            "local_executable": {
                "path": "/work/node_modules/.bin/left-pad",
                "resolved_path": null,
                "status": "missing",
                "file_identity": null,
                "content_hash": null,
            },
            "manifests": [{
                "path": "/work/package.json",
                "resolved_path": "/work/package.json",
                "status": "available",
                "file_identity": null,
                "content_hash": "sha256:manifest",
            }],
            "lockfiles": [],
            "typescript_launch": {"runner": "tsx"},
        }],
        "execution_context_hashes": ["ctx-1"],
        "execution_context_cwds": ["/work"],
        "execution_context_reason_codes": [],
        "routine_local_runner": false,
    })
}

fn artifact_id(intent: &PackageIntent) -> String {
    build_package_request_artifact("codex", intent, "hol-guard.toml", "project").artifact_id
}

#[test]
fn exact_payload_rebuilds_the_intent_that_produced_it() {
    let decoded = PackageIntent::from_exact_dict(&exact_payload()).expect("decodes");
    let expected = intent();

    assert_eq!(decoded.package_manager, expected.package_manager);
    assert_eq!(decoded.intent_kind, expected.intent_kind);
    assert_eq!(decoded.command_tokens, expected.command_tokens);
    assert_eq!(decoded.redacted_command, expected.redacted_command);
    assert_eq!(decoded.manifest_paths, expected.manifest_paths);
    assert_eq!(decoded.lockfile_paths, expected.lockfile_paths);
    assert_eq!(decoded.flags, expected.flags);
    assert_eq!(decoded.notes, expected.notes);
    assert_eq!(decoded.routine_local_runner, expected.routine_local_runner);

    // The exact spellings, not the redacted ones the public metadata carries.
    assert_eq!(decoded.targets[0].raw_spec, expected.targets[0].raw_spec);
    assert_eq!(
        decoded.targets[0].source_url,
        expected.targets[0].source_url
    );

    let execution = &decoded.local_executions[0];
    assert_eq!(
        execution.local_executable.as_ref().unwrap().resolved_path,
        None
    );
    assert_eq!(
        execution.local_executable.as_ref().unwrap().status,
        "missing"
    );
    assert_eq!(execution.typescript_launch, Some(json!({"runner": "tsx"})));

    // The point of the round trip: the review keeps its name.
    assert_eq!(artifact_id(&decoded), artifact_id(&expected));
}

#[test]
fn a_resolved_path_is_never_filled_in_from_the_path() {
    let decoded = PackageIntent::from_exact_dict(&exact_payload()).expect("decodes");
    let mut filled = intent();
    filled.local_executions[0]
        .local_executable
        .as_mut()
        .unwrap()
        .resolved_path = Some("/work/node_modules/.bin/left-pad".to_owned());

    // Filling the null in would be a different request, under a different id.
    assert_ne!(artifact_id(&decoded), artifact_id(&filled));
}

#[test]
fn an_undefined_intent_kind_is_no_intent() {
    let mut payload = exact_payload();
    payload["intent_kind"] = json!("uninstall");

    assert!(PackageIntent::from_exact_dict(&payload).is_none());
}

#[test]
fn a_missing_package_manager_is_no_intent() {
    let mut payload = exact_payload();
    payload.as_object_mut().unwrap().remove("package_manager");

    assert!(PackageIntent::from_exact_dict(&payload).is_none());
}

#[test]
fn an_undefined_evidence_status_is_refused_rather_than_relabelled() {
    let mut payload = exact_payload();
    payload["local_executions"][0]["manager"]["status"] = json!("present");

    assert!(PackageIntent::from_exact_dict(&payload).is_none());
}

#[test]
fn a_non_string_argv_token_is_no_intent() {
    let mut payload = exact_payload();
    payload["command_tokens"] = json!(["npm", 7]);

    assert!(PackageIntent::from_exact_dict(&payload).is_none());
}

#[test]
fn a_target_missing_its_exact_spec_is_no_intent() {
    let mut payload = exact_payload();
    payload["targets"][0]
        .as_object_mut()
        .unwrap()
        .remove("raw_spec");

    assert!(PackageIntent::from_exact_dict(&payload).is_none());
}

#[test]
fn an_empty_intent_decodes_with_the_dataclass_defaults() {
    let decoded = PackageIntent::from_exact_dict(&json!({
        "package_manager": "pip",
        "intent_kind": "sync",
        "redacted_command": "pip install -r requirements.txt",
    }))
    .expect("decodes");

    assert!(decoded.targets.is_empty());
    assert!(decoded.local_executions.is_empty());
    assert!(decoded.command_tokens.is_empty());
    assert!(!decoded.routine_local_runner);
}

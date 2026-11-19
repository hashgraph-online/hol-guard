use std::path::Path;

use serde_json::{json, Value};

use super::{add, artifact, generations, Object, REPAIR};
use crate::codex_hook_manifest_build::bridge_argv_sha256;
use crate::transition_files::dispatch;
use crate::transition_files::Fault;

fn object(value: Value) -> Object {
    value.as_object().cloned().unwrap()
}

fn integrity(fault: Fault) -> String {
    match fault {
        Fault::Integrity(reason, _) => reason,
        Fault::Transition(reason) => reason.to_owned(),
        _ => String::new(),
    }
}

fn manifest(retained_argv: &[&str], allowed: &[&str]) -> Object {
    let argv: Vec<Value> = retained_argv.iter().map(|item| json!(item)).collect();
    let hashes: Vec<String> = allowed
        .iter()
        .map(|item| {
            let argv: Vec<Value> = item.split(' ').map(|part| json!(part)).collect();
            bridge_argv_sha256(&argv).unwrap()
        })
        .collect();
    object(json!({
        "schema_version": 2,
        "harness": "codex",
        "installation_id": "install",
        "config": {"target": "/home/.codex/config.toml"},
        "context": {"guard_home": "/home/.hol-guard"},
        "events": [{"argv": ["/new/runtime", "codex-hook-bridge", "{}"]}],
        "compatible_bridge_argv_sha256": hashes,
        "retained_bridge_generations": [{
            "schema_version": 2,
            "harness": "codex",
            "installation_id": "install",
            "config": {"target": "/home/.codex/config.toml"},
            "context": {"guard_home": "/home/.hol-guard"},
            "events": [{"argv": argv}],
        }],
    }))
}

#[test]
fn a_retained_generation_is_repaired_only_when_install_registered_it() {
    let registered = manifest(&["/old", "bridge", "{}"], &["/old bridge {}"]);
    assert_eq!(generations(&registered, REPAIR).unwrap().len(), 2);
    let unregistered = manifest(&["/old", "bridge", "{}"], &["/other bridge {}"]);
    assert_eq!(
        integrity(generations(&unregistered, REPAIR).unwrap_err()),
        "codex_hook_repair_retained_identity_invalid"
    );
    let mut moved = registered.clone();
    moved["retained_bridge_generations"][0]["installation_id"] = json!("elsewhere");
    assert_eq!(
        integrity(generations(&moved, REPAIR).unwrap_err()),
        "codex_hook_repair_retained_identity_invalid"
    );
    let mut malformed = registered;
    malformed.insert("compatible_bridge_argv_sha256".into(), json!(["XYZ"]));
    assert!(generations(&malformed, REPAIR).is_err());
}

fn identity(role: &str) -> Object {
    object(json!({
        "role": role,
        "path": "/opt/guard/bin/runtime",
        "mode": 0o755,
        "sha256": "a".repeat(64),
        "size": 10,
        "owner_uid": 0,
    }))
}

#[test]
fn an_artifact_is_pinned_by_digest_with_its_invocation() {
    let interpreter = object(json!({
        "invocation_path": "/usr/bin/runtime",
        "invocation_mode": 0o755,
        "invocation_owner_uid": 0,
        "link_target": "/opt/guard/bin/runtime",
    }));
    let pinned = artifact(&identity("interpreter"), Some(&interpreter)).unwrap();
    assert_eq!(pinned["before"], Value::Null);
    assert_eq!(pinned["expected_digest"], json!("a".repeat(64)));
    assert_eq!(pinned["artifact_identity"]["role"], json!("interpreter"));
    assert_eq!(
        pinned["invocation_identity"]["path"],
        json!("/usr/bin/runtime")
    );
    let mut boolean = identity("bridge");
    boolean.insert("mode".into(), json!(true));
    assert_eq!(
        integrity(artifact(&boolean, None).unwrap_err()),
        "artifact_dependency_invalid"
    );
}

#[test]
fn shared_artifacts_merge_and_the_manifest_cannot_be_pinned() {
    let manifest = Path::new("/opt/guard/managed/hooks-x.manifest.json");
    let mut files = Vec::new();
    add(
        &mut files,
        artifact(&identity("bridge"), None).unwrap(),
        Some(manifest),
    )
    .unwrap();
    add(
        &mut files,
        artifact(&identity("cli"), None).unwrap(),
        Some(manifest),
    )
    .unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["artifact_identity"]["role"], json!("artifact"));
    let mut own = identity("bridge");
    own.insert("path".into(), json!(manifest.to_string_lossy()));
    let error = add(&mut files, artifact(&own, None).unwrap(), Some(manifest)).unwrap_err();
    assert_eq!(integrity(error), "adapter_preparation_generation_conflict");
}

fn inverse_error(extra: Value) -> Value {
    let mut request = json!({
        "op": "publication_inverse_dependencies",
        "home": std::env::temp_dir().join("inverse-manifest-text-home").to_string_lossy(),
    });
    request
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap());
    dispatch(&request).unwrap()["error"].clone()
}

#[test]
fn captured_manifest_text_is_authenticated_by_the_runtime_or_refused() {
    assert_eq!(
        inverse_error(json!({"manifest_text": "not json"})),
        json!({"integrity": "codex_hook_manifest_invalid", "message":
            "The authenticated Codex hook manifest is unreadable; run `hol-guard install codex` to repair it."}),
    );
    let unsigned = inverse_error(json!({"manifest_text": "{\"installation_id\": \"x\"}"}));
    assert_eq!(
        unsigned["integrity"],
        json!("codex_hook_manifest_authentication_missing")
    );
    assert_eq!(
        inverse_error(json!({"manifest_text": 7})),
        json!({"transition": "files_invalid"}),
    );
    assert_eq!(
        inverse_error(json!({})),
        json!({"transition": "files_invalid"})
    );
}

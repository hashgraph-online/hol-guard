use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{generic_hook_components, runtime_hook_components, Effects, LaunchRequest};
#[cfg(unix)]
use crate::context_digest::build_context_token;
use crate::context_digest_json::write_canonical_json;
#[cfg(unix)]
use crate::store_vectors_support_tests::gunzip_json;

/// The recorder's stand-in for `build_runtime_launch_identity`: a digest of
/// the exact call, so any drift in command, args, cwd or environment shows.
fn fixture_launch(request: &LaunchRequest<'_>) -> Value {
    let call = json!({
        "args": request.args,
        "command": request.command,
        "cwd": request.cwd,
        "direct_executable": false,
        "home_dir": request.home_dir,
        "launch_env": request.launch_env,
        "search_path": request.search_path,
        "structured_command": request.structured_command,
    });
    let mut bytes = Vec::new();
    write_canonical_json(&call, &mut bytes).expect("canonical launch call");
    let digest = hex::encode(Sha256::digest(&bytes));
    json!({
        "argv_sha256": digest,
        "entrypoint": {"digest": &digest[16..32], "status": "fixture"},
        "executable": format!("exe:{}", &digest[..16]),
        "launch_cwd": request.cwd,
    })
}

#[cfg(unix)]
fn vectors() -> Vec<Value> {
    let document = gunzip_json(include_bytes!(
        "../tests/fixtures/hook_approval_context_vectors.json.gz"
    ));
    assert_eq!(document["schema"], "hook-approval-context-vectors.v1");
    document["vectors"].as_array().expect("vectors").clone()
}

#[cfg(unix)]
#[test]
fn hook_approval_context_matches_recorded_python() {
    let vectors = vectors();
    assert!(vectors.len() > 500);
    let mut failures = Vec::new();
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap_or_default();
        let mut counter = 0u32;
        let mut nonce = || {
            counter += 1;
            Ok(format!("{counter:032x}"))
        };
        let mut effects = Effects {
            launch: &fixture_launch,
            nonce: &mut nonce,
        };
        let composed = match vector["kind"].as_str() {
            Some("runtime") => runtime_hook_components(&vector["inputs"], &mut effects),
            Some("generic") => generic_hook_components(&vector["inputs"], &mut effects),
            other => panic!("unknown vector kind {other:?}"),
        };
        if vector["error"] == json!(true) {
            if composed.is_ok() {
                failures.push(format!("{name}: expected an error"));
            }
            continue;
        }
        let components = match composed {
            Ok(components) => components,
            Err(code) => {
                failures.push(format!("{name}: {code}"));
                continue;
            }
        };
        let expected = &vector["components"];
        for (key, actual) in [
            ("identity", &components.identity),
            ("content", &components.content),
            ("capabilities", &components.capabilities),
            ("policy", &components.policy),
            ("sandbox", &components.sandbox),
        ] {
            if &expected[key] != actual {
                failures.push(format!(
                    "{name}: {key}\n  want {}\n  got  {actual}",
                    expected[key]
                ));
            }
        }
        let token = build_context_token(&components).expect("token");
        if vector["token"] != json!(token) {
            failures.push(format!("{name}: token"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn malformed_inputs_are_rejected() {
    let mut nonce = || Ok(String::from("0"));
    let mut effects = Effects {
        launch: &fixture_launch,
        nonce: &mut nonce,
    };
    assert!(runtime_hook_components(&json!([]), &mut effects).is_err());
    assert!(generic_hook_components(&json!({"host": {}}), &mut effects).is_err());
}

/// A gone process cwd does not matter when the hook names its workspace.
#[cfg(unix)]
#[test]
fn explicit_workspace_composes_without_host_cwd() {
    let mut checked = 0;
    for vector in vectors() {
        let inputs = &vector["inputs"];
        let workspace = inputs["runtime_workspace"].as_str().unwrap_or_default();
        let metadata = &inputs["metadata"];
        if vector["kind"] != "runtime"
            || vector["error"] == json!(true)
            || !workspace.starts_with('/')
            || !metadata["shell_execution_context_hash"].is_null()
            || !metadata["shell_execution_context_hashes"].is_null()
            || !metadata["shell_execution_effective_cwds"].is_null()
        {
            continue;
        }
        let mut detached = inputs.clone();
        detached["host"]["cwd"] = Value::Null;
        let mut counter = 0u32;
        let mut nonce = || {
            counter += 1;
            Ok(format!("{counter:032x}"))
        };
        let mut effects = Effects {
            launch: &fixture_launch,
            nonce: &mut nonce,
        };
        let components = runtime_hook_components(&detached, &mut effects)
            .unwrap_or_else(|code| panic!("{}: {code}", vector["name"]));
        assert_eq!(components.identity, vector["components"]["identity"]);
        checked += 1;
    }
    assert!(checked > 0);
}

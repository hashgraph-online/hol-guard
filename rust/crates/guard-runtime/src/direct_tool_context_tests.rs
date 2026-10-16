//! Direct-tool actions stay request-bound and reject malformed caller facts.
use guard_contracts::RequestContextRequestV1;
use serde_json::{json, Value};

fn request(kind: &str, command: Value) -> Value {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let owner = if cfg!(unix) { owner() } else { None };
    let mut body = json!({"facts": {"cwd": root, "home_dir": root, "caller_home": root, "temp_dir": root, "environment": {}, "groups": []}});
    body["facts"]["launcher"] = json!({"python_executable": root, "interpreter": root, "import_root": root, "frozen": false, "python_version": [3, 12]});
    if kind == "direct_tool" {
        body["tool"] = json!("vitest");
        body["script"] = command;
    } else {
        body["command"] = command;
    }
    json!({"schema": "guard-request-context-request.v1", "request_id": "synthetic-direct-tool", "guard_home": root, "source": "direct_command", "budget_ms": 9000, "owner_uid": owner, "action": {"kind": kind, "body": body}})
}

#[cfg(unix)]
fn owner() -> Option<u32> {
    Some(nix::unistd::geteuid().as_raw())
}
#[cfg(not(unix))]
fn owner() -> Option<u32> {
    None
}

fn evaluate(wire: Value) -> Value {
    let request: RequestContextRequestV1 = serde_json::from_value(wire).unwrap();
    let bytes = crate::request_context_op::evaluate_request_context_request(&request).unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response["request_sha256"],
        crate::request_context_op::request_digest(&request).unwrap()
    );
    assert_eq!(response["request_id"], request.request_id);
    response
}

#[test]
fn direct_tool_refusals_are_bound_without_a_context() {
    let response = evaluate(request("direct_tool", json!("echo synthetic")));
    assert_eq!(response["status"], "ok");
    assert_eq!(
        response["payload"],
        json!({"kind": "direct_tool", "accepted": false, "context": null})
    );
    let response = evaluate(request("trusted_tool", json!("missing-synthetic-command")));
    assert_eq!(
        response["payload"],
        json!({"kind": "trusted_tool", "trusted": false})
    );
}

#[test]
fn direct_tool_admission_refuses_paths_environment_and_budgets() {
    let mut wire = request("direct_tool", json!("echo synthetic"));
    wire["action"]["body"]["facts"]["cwd"] = json!("relative");
    assert_eq!(
        evaluate(wire)["code"],
        "native_request_context_direct_path_invalid"
    );
    let mut wire = request("trusted_tool", json!("node"));
    wire["action"]["body"]["facts"]["environment"]["PATH"] = json!("x".repeat(65537));
    assert_eq!(
        evaluate(wire)["code"],
        "native_request_context_direct_environment_invalid"
    );
    let mut wire = request("direct_tool", json!("echo synthetic"));
    wire["budget_ms"] = json!(0);
    assert_eq!(
        evaluate(wire)["code"],
        "native_request_context_budget_invalid"
    );
}

#[test]
fn direct_tool_contract_has_no_trust_override_or_unknown_fields() {
    for kind in ["direct_tool", "trusted_tool"] {
        let mut wire = request(kind, json!("node"));
        wire["action"]["body"]["facts"]["trusted_tree_sha256"] = json!("unreviewed");
        assert!(serde_json::from_value::<RequestContextRequestV1>(wire).is_err());
        let mut wire = request(kind, json!("node"));
        wire["action"]["body"]["trusted"] = json!(true);
        assert!(serde_json::from_value::<RequestContextRequestV1>(wire).is_err());
    }
}

#[cfg(unix)]
#[test]
fn current_python_managed_bun_shims_are_trusted_and_tampering_is_refused() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/direct-tool-python-shims.v1.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("guard-direct-bun-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let _scratch = Scratch(root.clone());
        let root_text = root.to_string_lossy();
        let bound: Value = serde_json::from_str(
            &serde_json::to_string(case)
                .unwrap()
                .replace("{ROOT}", &root_text),
        )
        .unwrap();
        let home = root.join("home/caller");
        let shim_dir = home.join(".hol-guard/package-shims/bin");
        let real_dir = root.join("real-bin");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        for path in [
            real_dir.join("bun"),
            Path::new(bound["launcher"]["interpreter"].as_str().unwrap()).to_path_buf(),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let manifest = home.join(".hol-guard/package-shims/manifest.json");
        fs::write(&manifest, r#"{"installed_managers":["bun"]}"#).unwrap();
        let shim = shim_dir.join("bun");
        fs::write(&shim, bound["wrapper"].as_str().unwrap()).unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
        let sidecar = shim_dir.join(".bun.py");
        fs::write(&sidecar, bound["source"].as_str().unwrap()).unwrap();
        let mut wire = request("trusted_tool", json!("bun"));
        let facts = &mut wire["action"]["body"]["facts"];
        facts["home_dir"] = json!(home);
        facts["caller_home"] = json!(home);
        facts["launcher"] = bound["launcher"].clone();
        facts["environment"]["PATH"] = json!(std::env::join_paths([&shim_dir, &real_dir])
            .unwrap()
            .into_string()
            .unwrap());
        assert_eq!(
            evaluate(wire.clone())["payload"]["trusted"],
            true,
            "layout {}",
            case["name"]
        );
        fs::write(&manifest, r#"{"installed_managers":[]}"#).unwrap();
        assert_eq!(evaluate(wire.clone())["payload"]["trusted"], false);
        fs::write(&manifest, r#"{"installed_managers":["bun"]}"#).unwrap();
        fs::remove_file(real_dir.join("bun")).unwrap();
        assert_eq!(evaluate(wire.clone())["payload"]["trusted"], false);
        fs::write(real_dir.join("bun"), "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(real_dir.join("bun"), fs::Permissions::from_mode(0o755)).unwrap();
        let modified = format!(
            "{}\n# unexpected modification\n",
            bound["source"].as_str().unwrap()
        );
        if bound["wrapper"] == bound["source"] {
            fs::write(shim, modified).unwrap();
        } else {
            fs::write(sidecar, modified).unwrap();
        }
        assert_eq!(evaluate(wire)["payload"]["trusted"], false);
    }
}

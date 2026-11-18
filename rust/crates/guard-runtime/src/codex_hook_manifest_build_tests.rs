use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use guard_policy_snapshot::local_authority_integrity::verify_local_authority_payload;
use serde_json::{json, Map, Value};

use super::{
    bridge_argv, bridge_argv_sha256, build, compatible_hashes, retained_generations, Signer,
};
use crate::codex_hook_bridge_trust_files::{verify_executable, verify_regular};

const KEY: [u8; 32] = [7; 32];

fn signer() -> Signer<'static> {
    Signer {
        key: &KEY,
        key_id: "k1",
        installation_id: "i1",
    }
}

fn file(path: &Path, body: &str, mode: u32) {
    fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    fs::write(path, body).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

struct Fixture {
    _root: tempfile::TempDir,
    base: PathBuf,
    spec: Map<String, Value>,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("root");
    let base = fs::canonicalize(root.path()).expect("canonical");
    let python = base.join("venv").join("python3");
    file(&python, "python", 0o755);
    let link = base.join("venv").join("python");
    std::os::unix::fs::symlink(&python, &link).expect("link");
    let mut packaged = Vec::new();
    for role in [
        "bridge",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
        "fallback_entrypoint",
    ] {
        let path = base.join("package").join(role);
        file(&path, role, 0o644);
        packaged.push(json!([role, path.to_str()]));
    }
    let spec = json!({
        "guard_home": base.join("guard").to_str(),
        "home_dir": base.to_str(),
        "runtime_guard_home": base.join("guard").to_str(),
        "workspace_dir": null,
        "config_path": base.join(".codex").join("config.toml").to_str(),
        "interpreter_path": link.to_str(),
        "package_version": "1.0.0",
        "packaged_file_paths": packaged,
        "fallback_argv": [link.to_str(), "-I", "fallback"],
        "daemon_start_argv": [link.to_str(), "-I", "start"],
        "event_bindings": [{"event": "PreToolUse", "argv": ["/r", "codex-hook-bridge", "{}"]}],
    });
    Fixture {
        _root: root,
        base,
        spec: spec.as_object().expect("spec").clone(),
    }
}

#[test]
fn the_built_manifest_is_signed_and_its_identities_verify() {
    let fixture = fixture();
    let manifest = build(&fixture.spec, None, &[], &signer()).expect("built");
    let mut unsigned = manifest.clone();
    let authentication = unsigned
        .as_object_mut()
        .and_then(|object| object.remove("authentication"))
        .expect("authentication");
    assert_eq!(authentication["algorithm"], "hmac-sha256");
    let verified = verify_local_authority_payload(
        &unsigned,
        &authentication,
        Some(&KEY),
        Some("k1"),
        "codex-managed-hook-manifest",
    );
    assert_eq!(verified.status, "valid");
    assert_eq!(manifest["installation_id"], "i1");
    assert_eq!(manifest["schema_version"], 2);
    assert_eq!(manifest["transport"]["wrapper"], Value::Null);
    let interpreter = &manifest["interpreter"];
    assert_eq!(
        interpreter["link_target"],
        fixture
            .base
            .join("venv")
            .join("python3")
            .to_str()
            .expect("utf-8")
    );
    assert_eq!(verify_executable(interpreter), Ok(()));
    for identity in manifest["packaged_files"].as_array().expect("files") {
        assert_eq!(verify_regular(identity), Ok(()));
    }
    assert_eq!(manifest["compatible_bridge_argv_sha256"], json!([]));
    assert_eq!(manifest["retained_bridge_generations"], json!([]));
}

#[test]
fn an_incomplete_package_or_a_shared_file_is_refused() {
    let fixture = fixture();
    let mut spec = fixture.spec.clone();
    let pairs = spec["packaged_file_paths"].as_array_mut().expect("pairs");
    pairs.retain(|pair| pair[0] != "windows_job");
    assert_eq!(
        build(&spec, None, &[], &signer()).err().as_deref(),
        Some("codex_hook_manifest_packaged_files_invalid")
    );
    let shared = fixture.base.join("package").join("bridge");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o666)).expect("mode");
    assert_eq!(
        build(&fixture.spec, None, &[], &signer()).err().as_deref(),
        Some("codex_hook_bridge_permissions_unsafe")
    );
    fs::remove_file(&shared).expect("remove");
    assert_eq!(
        build(&fixture.spec, None, &[], &signer()).err().as_deref(),
        Some("codex_hook_bridge_missing")
    );
}

#[test]
fn the_bridge_argv_digest_matches_the_python_encoding() {
    let argv = json!(["/r", "codex-hook-bridge", "{\"q\":\"\u{e9}\"}"]);
    assert_eq!(
        bridge_argv_sha256(argv.as_array().expect("argv")).as_deref(),
        Some("f1c672dd0b22e67c7fb35084a3558e1edcbf833a95f512caca2215c574341b32")
    );
    let wrapped = json!(["/r", "codex-hook-bridge", "/py", "-m", "x"]);
    assert_eq!(
        bridge_argv_sha256(wrapped.as_array().expect("argv")).as_deref(),
        Some("9e6245fd44c31d50db0635e9fc82965a8c03a42348fb60ea437e1e82573e03f2")
    );
}

#[test]
fn only_a_legacy_native_prefix_is_stripped() {
    let unchanged = [
        json!([]),
        json!(["/opt/runtime", "codex-hook-bridge"]),
        json!(["/opt/runtime", "codex-hook-bridge", "{}"]),
        json!(["", "codex-hook-bridge", "python3", "bridge.py"]),
        json!([null, "codex-hook-bridge", "python3", "bridge.py"]),
        json!(["/opt/runtime", "claude-hook-bridge", "python3", "bridge.py"]),
        json!(["python3", "-I", "bridge.py", "{}"]),
    ];
    for argv in &unchanged {
        let items = argv.as_array().expect("argv");
        assert_eq!(bridge_argv(items), items.as_slice(), "{argv}");
    }
    let wrapped = json!(["/opt/runtime", "codex-hook-bridge", "python3", "bridge.py"]);
    assert_eq!(
        bridge_argv(wrapped.as_array().expect("argv")),
        [json!("python3"), json!("bridge.py")]
    );
}

#[test]
fn a_rebuild_carries_the_previous_bridge_generation() {
    let fixture = fixture();
    let first = build(&fixture.spec, None, &[], &signer()).expect("first");
    let previous = first.as_object().expect("manifest");
    let hashes = compatible_hashes(Some(previous));
    let expected = bridge_argv_sha256(&[json!("/r"), json!("codex-hook-bridge"), json!("{}")]);
    assert_eq!(hashes, vec![expected.expect("digest")]);
    let retained = retained_generations(Some(previous));
    assert_eq!(retained.len(), 1);
    assert!(retained[0].get("authentication").is_none());
    assert_eq!(retained[0]["events"], previous["events"]);
    let second = build(&fixture.spec, Some(previous), &[], &signer()).expect("second");
    assert_eq!(second["compatible_bridge_argv_sha256"], json!(hashes));
    assert_eq!(
        second["retained_bridge_generations"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert!(compatible_hashes(None).is_empty());
}

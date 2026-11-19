use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::registration_failure;
use crate::codex_hook_key::{answer, read_matching};

struct Install {
    _root: tempfile::TempDir,
    guard: PathBuf,
    bridge: PathBuf,
    manifest: PathBuf,
    config: Value,
    unsigned: Value,
}

fn executable(path: &Path, body: &str) -> Value {
    fs::create_dir_all(path.parent().expect("dir")).expect("dir");
    fs::write(path, body).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mode");
    json!({
        "path": path.to_str().expect("utf-8"),
        "sha256": hex::encode(Sha256::digest(body.as_bytes())),
        "mode": 0o755,
        "size": body.len(),
        "executable_required": true,
    })
}

fn install() -> Install {
    let root = tempfile::tempdir().expect("root");
    let base = fs::canonicalize(root.path()).expect("canonical");
    let guard = base.join("guard");
    fs::create_dir_all(&guard).expect("guard");
    let home = guard.to_str().expect("utf-8");
    let key = answer("key_ensure", home).expect("op");
    let python = base.join("bin").join("python");
    let mut target = executable(&python, "python");
    target["role"] = json!("interpreter");
    let interpreter = json!({
        "role": "interpreter",
        "invocation_path": python.to_str(),
        "invocation_mode": 0o755,
        "target": target,
    });
    let bridge = base.join("package").join("hol-guard-runtime");
    let mut packaged = executable(&bridge, "runtime");
    packaged["role"] = json!("bridge");
    let target = base.join(".codex").join("config.toml");
    fs::create_dir_all(target.parent().expect("dir")).expect("dir");
    fs::write(&target, "").expect("config");
    let digest = hex::encode(Sha256::digest(target.to_str().expect("utf-8").as_bytes()));
    let manifest = guard
        .join("managed")
        .join("codex")
        .join(format!("hooks-{}.manifest.json", &digest[..24]));
    let fallback = json!([python.to_str(), "-I", "fallback"]);
    let start = json!([python.to_str(), "-I", "start"]);
    let config = json!({
        "state_path": guard.join("daemon-state.json").to_str(),
        "manifest_path": manifest.to_str(),
        "fallback_command": fallback,
        "start_command": start,
        "query": "guard-home=x",
        "hook_timeouts": {"PreToolUse": 10},
    });
    let unsigned = json!({
        "schema_version": 2,
        "harness": "codex",
        "installation_id": key["installation_id"],
        "generated_at": "2026-11-14T00:00:00Z",
        "context": {"runtime_guard_home": home},
        "config": {"target": target.to_str()},
        "interpreter": interpreter,
        "packaged_files": [packaged],
        "events": [{"argv": [bridge.to_str(), "codex-hook-bridge", config.to_string()]}],
        "fallback": {"argv": fallback, "interpreter": interpreter},
        "daemon_start": {"argv": start, "interpreter": interpreter},
    });
    let install = Install {
        _root: root,
        guard,
        bridge,
        manifest,
        config,
        unsigned,
    };
    write_signed(&install, &install.unsigned);
    install
}

fn write_signed(install: &Install, unsigned: &Value) {
    let home = install.guard.to_str().expect("utf-8");
    let key = read_matching(home, None, None).expect("key");
    let signed_at = unsigned["generated_at"].as_str().expect("time");
    let fields = sign_local_authority_payload(
        unsigned,
        key.key.as_slice(),
        &key.key_id,
        "codex-managed-hook-manifest",
        signed_at,
    )
    .expect("sign");
    let mut manifest = unsigned.clone();
    manifest["authentication"] = json!({
        "algorithm": "hmac-sha256",
        "integrity_version": fields.integrity_version,
        "payload_hash": fields.payload_hash,
        "payload_mac": fields.payload_mac,
        "integrity_key_id": fields.integrity_key_id,
        "signed_at": fields.signed_at,
    });
    fs::write(&install.manifest, manifest.to_string()).expect("manifest");
    fs::set_permissions(&install.manifest, fs::Permissions::from_mode(0o600)).expect("mode");
}

#[test]
fn the_installed_registration_authenticates() {
    let install = install();
    assert_eq!(registration_failure(&install.config.to_string()), None);
}

#[test]
fn a_missing_manifest_is_named() {
    let install = install();
    fs::remove_file(&install.manifest).expect("remove");
    assert_eq!(
        registration_failure(&install.config.to_string()).as_deref(),
        Some("codex_hook_manifest_missing")
    );
}

#[test]
fn a_rewritten_start_command_is_refused() {
    let install = install();
    let mut config = install.config.clone();
    config["start_command"] = json!(["/bin/sh", "-c", "true"]);
    assert_eq!(
        registration_failure(&config.to_string()).as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
}

#[test]
fn a_manifest_edited_after_signing_is_refused() {
    let install = install();
    let mut edited: Value =
        serde_json::from_str(&fs::read_to_string(&install.manifest).expect("manifest"))
            .expect("json");
    edited["daemon_start"]["argv"] = json!(["/bin/sh"]);
    fs::write(&install.manifest, edited.to_string()).expect("write");
    assert_eq!(
        registration_failure(&install.config.to_string()).as_deref(),
        Some("codex_hook_manifest_mac_invalid")
    );
}

#[test]
fn a_replaced_runtime_file_is_refused() {
    let install = install();
    fs::write(&install.bridge, "replaced").expect("write");
    assert_eq!(
        registration_failure(&install.config.to_string()).as_deref(),
        Some("codex_hook_bridge_hash_mismatch")
    );
}

#[test]
fn a_shared_manifest_or_one_outside_the_home_is_refused() {
    let install = install();
    fs::set_permissions(&install.manifest, fs::Permissions::from_mode(0o644)).expect("mode");
    assert_eq!(
        registration_failure(&install.config.to_string()).as_deref(),
        Some("codex_hook_manifest_permissions_unsafe")
    );
    let mut config = install.config.clone();
    config["manifest_path"] = json!(install.guard.join("hooks-x.manifest.json").to_str());
    assert_eq!(
        registration_failure(&config.to_string()).as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
}

#[test]
fn a_retained_generation_needs_its_compatibility_hash() {
    let install = install();
    let mut config = install.config.clone();
    config["query"] = json!("guard-home=older");
    let older = config.to_string();
    let mut unsigned = install.unsigned.clone();
    let mut retained = install.unsigned.clone();
    retained["events"] = json!([{"argv": [install.bridge.to_str(), "codex-hook-bridge", older]}]);
    unsigned["retained_bridge_generations"] = json!([retained]);
    write_signed(&install, &unsigned);
    assert_eq!(
        registration_failure(&older).as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
    let argv = json!([install.bridge.to_str(), "codex-hook-bridge", older]);
    let hash = hex::encode(Sha256::digest(argv.to_string().as_bytes()));
    unsigned["compatible_bridge_argv_sha256"] = json!([hash]);
    write_signed(&install, &unsigned);
    assert_eq!(registration_failure(&older), None);
}

/// The frozen bundle's layout: every recorded file, the bridge included, is
/// the bundle executable, while each event runs the native runtime copied
/// out of it under the Guard home.
fn frozen(install: &Install) -> (Value, String) {
    let mut unsigned = install.unsigned.clone();
    let bundle = unsigned["interpreter"]["target"].clone();
    let mut bridge = bundle.clone();
    bridge["role"] = json!("bridge");
    unsigned["packaged_files"] = json!([bridge]);
    let copy = install
        .guard
        .join("native-runtime")
        .join("digest")
        .join("hol-guard-runtime");
    executable(&copy, "runtime");
    let config = install.config.to_string();
    unsigned["events"] = json!([
        {"argv": [copy.to_str(), "codex-hook-bridge", config]},
        {"argv": [copy.to_str(), "codex-hook-bridge", config]},
    ]);
    (unsigned, copy.to_str().expect("utf-8").to_owned())
}

#[test]
fn a_frozen_bundle_registration_authenticates() {
    let install = install();
    let (unsigned, _) = frozen(&install);
    write_signed(&install, &unsigned);
    assert_eq!(registration_failure(&install.config.to_string()), None);
}

#[test]
fn a_frozen_bundle_still_refuses_a_rewritten_config() {
    let install = install();
    let (unsigned, _) = frozen(&install);
    write_signed(&install, &unsigned);
    let mut config = install.config.clone();
    config["query"] = json!("guard-home=elsewhere");
    assert_eq!(
        registration_failure(&config.to_string()).as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
}

#[test]
fn a_frozen_retained_generation_needs_the_hash_of_what_it_registered() {
    let install = install();
    let (current, copy) = frozen(&install);
    let mut config = install.config.clone();
    config["query"] = json!("guard-home=older");
    let older = config.to_string();
    let mut retained = current.clone();
    retained["events"] = json!([{"argv": [copy, "codex-hook-bridge", older]}]);
    let mut unsigned = current.clone();
    unsigned["retained_bridge_generations"] = json!([retained]);
    write_signed(&install, &unsigned);
    assert_eq!(
        registration_failure(&older).as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
    let argv = json!([copy, "codex-hook-bridge", older]);
    let hash = hex::encode(Sha256::digest(argv.to_string().as_bytes()));
    unsigned["compatible_bridge_argv_sha256"] = json!([hash]);
    write_signed(&install, &unsigned);
    assert_eq!(registration_failure(&older), None);
}

#[test]
fn a_package_install_still_binds_the_runtime_path() {
    let install = install();
    let mut unsigned = install.unsigned.clone();
    let moved = install.guard.join("elsewhere").join("hol-guard-runtime");
    executable(&moved, "runtime");
    let config = install.config.to_string();
    unsigned["events"] = json!([{"argv": [moved.to_str(), "codex-hook-bridge", config]}]);
    write_signed(&install, &unsigned);
    assert_eq!(
        registration_failure(&install.config.to_string()).as_deref(),
        Some("codex_hook_launch_unauthenticated")
    );
}

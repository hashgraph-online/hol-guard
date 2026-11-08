use super::*;
use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;
use std::fs;
use std::time::Duration;

struct Fixture {
    _root: tempfile::TempDir,
    manifest: std::path::PathBuf,
    key_path: std::path::PathBuf,
    argv: Vec<String>,
    config: BridgeConfig,
    unsigned: Value,
}

fn mode(path: &Path, bits: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(bits)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, bits);
}
fn identity(path: &Path, role: &str) -> Value {
    let metadata = fs::metadata(path).unwrap();
    let facts = crate::codex_hook_file_identity_op::FileFacts::of(path, &metadata);
    json!({"role": role, "path": canonical(path).unwrap(), "sha256": hex::encode(Sha256::digest(fs::read(path).unwrap())),
        "mode": facts.mode & 0o7777, "size": facts.size, "owner_uid": facts.uid})
}
impl Fixture {
    fn new() -> Self {
        Self::in_home(None)
    }
    fn in_home(home: Option<std::path::PathBuf>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = home.unwrap_or_else(|| fs::canonicalize(root.path()).unwrap());
        mode(&home, 0o700);
        let managed = home.join("managed/codex");
        fs::create_dir_all(&managed).unwrap();
        mode(&managed, 0o700);
        let target = home.join("config.toml");
        fs::write(&target, b"[hooks]\n").unwrap();
        let digest = hex::encode(Sha256::digest(canonical(&target).unwrap().as_bytes()));
        let manifest = managed.join(format!("hooks-{}.manifest.json", &digest[..24]));
        let python = home.join("python");
        fs::write(&python, b"fixture interpreter").unwrap();
        mode(&python, 0o755);
        let metadata = fs::symlink_metadata(&python).unwrap();
        let facts = crate::codex_hook_file_identity_op::FileFacts::of(&python, &metadata);
        let interpreter = json!({"role":"interpreter", "invocation_path":canonical(&python).unwrap(),
            "invocation_mode":facts.mode & 0o7777, "invocation_owner_uid":facts.uid,
            "link_target":null, "target":identity(&python,"interpreter")});
        let package = home.join("codex_plugin_scanner");
        let guard = package.join("guard");
        fs::create_dir_all(guard.join("adapters")).unwrap();
        fs::create_dir_all(guard.join("daemon")).unwrap();
        let roles = [
            ("bridge", guard.join("adapters/codex_daemon_hook_bridge.py")),
            ("bridge_runtime", guard.join("codex_hook_bridge_runtime.py")),
            ("hook_probe", guard.join("runtime_transition_hook_probe.py")),
            ("native_receipt", guard.join("native_decision_receipt.py")),
            ("daemon_entrypoint", guard.join("daemon/__init__.py")),
            ("daemon_manager", guard.join("daemon/manager.py")),
            ("fallback_entrypoint", package.join("cli.py")),
            ("launch_runtime", guard.join("codex_hook_launch_runtime.py")),
            ("runtime_trust", guard.join("codex_hook_runtime_trust.py")),
            ("windows_job", guard.join("codex_hook_windows_job.py")),
        ];
        let files: Vec<Value> = roles
            .iter()
            .map(|(role, path)| {
                fs::write(path, role).unwrap();
                mode(path, 0o644);
                identity(path, role)
            })
            .collect();
        let python_text = canonical(&python).unwrap();
        let home_text = canonical(&home).unwrap();
        let mut fallback = contract::fallback_prefix(&python_text, &home_text);
        fallback.extend(["guard", "hook", "--harness", "codex"].map(str::to_owned));
        let start = contract::start_command(&python_text, &home_text, &home_text, &home_text);
        let payload=json!({"manifest_path":manifest,"state_path":home.join("daemon-state.json"),"query":"fixture",
            "fallback_command":fallback,"start_command":start,"hook_timeouts":{"PreToolUse":10}}).to_string();
        let argv = vec![
            python_text,
            "-I".to_owned(),
            canonical(&roles[0].1).unwrap(),
            payload.clone(),
        ];
        let mut transport = serde_json::Map::new();
        for role in [
            "bridge",
            "bridge_runtime",
            "launch_runtime",
            "runtime_trust",
            "windows_job",
        ] {
            transport.insert(
                role.to_owned(),
                files.iter().find(|f| f["role"] == role).unwrap().clone(),
            );
        }
        transport.insert("wrapper".to_owned(), Value::Null);
        let unsigned = json!({"schema_version":2,"harness":"codex","installation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "generated_at":"2026-11-08T00:00:00Z","config":{"target":canonical(&target).unwrap()},
            "context":{"runtime_guard_home":home_text,"home_dir":home_text},"interpreter":interpreter,"packaged_files":files,"transport":transport,
            "fallback":{"argv":fallback,"interpreter":interpreter,"package_roles":["fallback_entrypoint"]},
            "daemon_start":{"argv":start,"interpreter":interpreter,"package_roles":["daemon_entrypoint","daemon_manager"]},
            "events":[{"argv":argv}]});
        let key_path = managed.join("hook-manifest.key");
        // 32 zero bytes, URL-safe base64 as the installed key writer emits it.
        fs::write(&key_path,json!({"schema_version":1,"installation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "key_id":"bbbbbbbbbbbbbbbbbbbbbbbb","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}).to_string()).unwrap();
        mode(&key_path, 0o600);
        let result = Self {
            _root: root,
            manifest,
            key_path,
            argv,
            config: super::super::parse_config(&payload).unwrap(),
            unsigned,
        };
        result.sign();
        result
    }
    fn sign(&self) {
        let signed = sign_local_authority_payload(
            &self.unsigned,
            &[0; 32],
            "bbbbbbbbbbbbbbbbbbbbbbbb",
            PURPOSE,
            "2026-11-08T00:00:00Z",
        )
        .unwrap();
        let mut manifest = self.unsigned.clone();
        manifest["authentication"] = json!({"algorithm":"hmac-sha256","integrity_version":signed.integrity_version,
            "payload_hash":signed.payload_hash,"payload_mac":signed.payload_mac,"integrity_key_id":signed.integrity_key_id,"signed_at":signed.signed_at});
        fs::write(&self.manifest, manifest.to_string()).unwrap();
        mode(&self.manifest, 0o600);
    }
    fn check(&self) -> bool {
        authenticate(
            &self.config,
            &self.argv,
            Instant::now() + Duration::from_secs(5),
            "PreToolUse",
        )
        .is_some()
    }
}

#[test]
fn valid_registration_authenticates_without_starting_daemon() {
    let f = Fixture::new();
    assert!(f.check());
    assert!(!Path::new(&f.config.state_path).exists());
}
#[test]
fn removed_manifest_and_removed_key_revoke_cached_native_command() {
    let f = Fixture::new();
    fs::remove_file(&f.manifest).unwrap();
    assert!(!f.check());
    assert!(!f.manifest.exists());
    assert!(!Path::new(&f.config.state_path).exists());
    f.sign();
    fs::remove_file(&f.key_path).unwrap();
    assert!(!f.check());
    assert!(!f.key_path.exists());
}
#[test]
fn tampered_manifest_config_and_file_fail_closed() {
    let f = Fixture::new();
    let mut value: Value = serde_json::from_str(&fs::read_to_string(&f.manifest).unwrap()).unwrap();
    value["events"][0]["argv"][0] = json!("tampered");
    fs::write(&f.manifest, value.to_string()).unwrap();
    assert!(!f.check());
    f.sign();
    let mut argv = f.argv.clone();
    argv[3] = argv[3].replace("fixture", "different");
    assert!(authenticate(
        &f.config,
        &argv,
        Instant::now() + Duration::from_secs(5),
        "PreToolUse"
    )
    .is_none());
    fs::write(
        f.unsigned["packaged_files"][0]["path"].as_str().unwrap(),
        b"changed",
    )
    .unwrap();
    assert!(!f.check());
}
#[test]
fn only_explicit_signed_retained_generation_is_accepted() {
    let mut f = Fixture::new();
    let old = f.unsigned.clone();
    f.unsigned["events"][0]["argv"][3] = json!("replacement");
    f.unsigned["retained_bridge_generations"] = json!([old]);
    f.sign();
    assert!(!f.check());
    f.unsigned["compatible_bridge_argv_sha256"] = json!([argv_hash(&f.argv)]);
    f.sign();
    assert!(f.check());
    f.unsigned["retained_bridge_generations"][0]["context"]["runtime_guard_home"] =
        json!("foreign");
    f.sign();
    assert!(!f.check());
}
#[test]
fn elapsed_validation_deadline_refuses_launch() {
    let f = Fixture::new();
    assert!(authenticate(&f.config, &f.argv, Instant::now(), "PreToolUse").is_none());
}

#[test]
fn config_only_native_delegation_binds_the_same_signed_registration() {
    let f = Fixture::new();
    let argv = vec![f.argv.last().unwrap().clone()];
    assert!(authenticate(
        &f.config,
        &argv,
        Instant::now() + Duration::from_secs(5),
        "PreToolUse"
    )
    .is_some());
}

#[cfg(unix)]
#[test]
fn revoked_registration_cannot_enter_restart_or_contained_fallback() {
    let mut f = Fixture::new();
    fs::remove_file(&f.manifest).unwrap();
    let marker = f._root.path().join("child-executed");
    let command = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        format!("touch '{}'", marker.display()),
    ];
    f.config.start_command = command.clone();
    f.config.fallback_command = command;
    let data =
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pwd"}}"#;
    let (route, _) = super::super::registered_route(&f.config, data, Instant::now(), &f.argv);
    let super::super::Route::Respond(text) = route else {
        panic!("revoked hook entered an execution route")
    };
    assert!(text.contains("deny"));
    assert!(!marker.exists());
    assert!(!Path::new(&f.config.state_path).exists());
    assert!(!f.manifest.exists());
}

#[test]
fn malformed_signed_compatibility_records_are_refused() {
    let mut f = Fixture::new();
    for value in [
        json!("not-a-list"),
        json!(["not-a-hash"]),
        json!(["A".repeat(64)]),
    ] {
        f.unsigned["compatible_bridge_argv_sha256"] = value;
        f.sign();
        assert!(!f.check());
    }
    f.unsigned
        .as_object_mut()
        .unwrap()
        .remove("compatible_bridge_argv_sha256");
    f.unsigned["retained_bridge_generations"] = json!({});
    f.sign();
    assert!(!f.check());
}

#[test]
fn authenticated_but_inconsistent_transport_and_launch_contracts_are_refused() {
    let mut f = Fixture::new();
    let original = f.unsigned.clone();
    f.unsigned["transport"]["bridge"] = json!({});
    f.sign();
    assert!(!f.check());
    f.unsigned = original.clone();
    f.unsigned["fallback"]["package_roles"] = json!(["bridge"]);
    f.sign();
    assert!(!f.check());
    f.unsigned = original.clone();
    f.unsigned["daemon_start"]["interpreter"] = json!({});
    f.sign();
    assert!(!f.check());
    f.unsigned = original;
    f.config.start_command[3] = "print('arbitrary child')".into();
    let mut payload: Value = serde_json::from_str(f.argv.last().unwrap()).unwrap();
    payload["start_command"] = json!(f.config.start_command);
    *f.argv.last_mut().unwrap() = payload.to_string();
    f.unsigned["daemon_start"]["argv"] = json!(f.config.start_command);
    f.unsigned["events"][0]["argv"] = json!(f.argv);
    f.sign();
    assert!(!f.check());
}

#[test]
fn config_only_delegation_remains_revoked_after_uninstall() {
    let f = Fixture::new();
    fs::remove_file(&f.manifest).unwrap();
    let argv = vec![f.argv.last().unwrap().clone()];
    assert!(authenticate(
        &f.config,
        &argv,
        Instant::now() + Duration::from_secs(5),
        "PreToolUse"
    )
    .is_none());
    assert!(!f.manifest.exists());
    assert!(!Path::new(&f.config.state_path).exists());
}

#[cfg(unix)]
#[test]
fn valid_registered_hook_reaches_authenticated_daemon() {
    use crate::claude_hook_bridge_fixture::Exchange;
    let (home, daemon) = super::super::tests::codex_home(
        "registered-native",
        vec![Exchange::Hook(
            200,
            r#"{"continue":true,"systemMessage":"registered"}"#.to_owned(),
        )],
    );
    let f = Fixture::in_home(Some(home.home.clone()));
    assert!(f.check());
    let (route, _) = super::super::registered_route(
        &f.config,
        r#"{"hook_event_name":"Stop"}"#,
        Instant::now(),
        &f.argv,
    );
    let super::super::Route::Respond(text) = route else {
        panic!("unexpected execution route")
    };
    assert!(text.contains("registered"), "{text}");
    assert_eq!(daemon.join().unwrap().len(), 1);
}

#[test]
fn desktop_delegation_can_only_reduce_the_current_events_signed_budget() {
    let f = Fixture::new();
    let original: Value = serde_json::from_str(f.argv.last().unwrap()).unwrap();
    let mut child = original.clone();
    child["hook_timeouts"]["PreToolUse"] = json!(6);
    let encoded = child.to_string();
    let config = super::super::parse_config(&encoded).unwrap();
    assert!(authenticate(
        &config,
        &[encoded],
        Instant::now() + Duration::from_secs(5),
        "PreToolUse"
    )
    .is_some());
    for change in ["larger", "query", "start", "different-event"] {
        let mut child = original.clone();
        child["hook_timeouts"]["PreToolUse"] = json!(6);
        match change {
            "larger" => child["hook_timeouts"]["PreToolUse"] = json!(11),
            "query" => child["query"] = json!("different-workspace"),
            "start" => child["start_command"][3] = json!("other bootstrap"),
            _ => child["hook_timeouts"]["Stop"] = json!(3),
        }
        let encoded = child.to_string();
        let config = super::super::parse_config(&encoded).unwrap();
        assert!(
            authenticate(
                &config,
                &[encoded],
                Instant::now() + Duration::from_secs(5),
                "PreToolUse"
            )
            .is_none(),
            "{change}"
        );
    }
}

#[test]
fn native_launcher_prefix_uses_the_python_argv_compatibility_digest() {
    let mut f = Fixture::new();
    let python_hash = argv_hash(&f.argv);
    let mut native = vec![
        std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        "codex-hook-bridge".to_owned(),
    ];
    native.extend(f.argv.clone());
    f.unsigned["events"][0]["argv"] = json!(native);
    f.sign();
    assert!(f.check());
    let old = f.unsigned.clone();
    f.unsigned["events"][0]["argv"][5] = json!("replacement");
    f.unsigned["retained_bridge_generations"] = json!([old]);
    f.unsigned["compatible_bridge_argv_sha256"] = json!([python_hash]);
    f.sign();
    assert!(f.check());
}

#[path = "codex_hook_bridge_registration_frozen_tests.rs"]
mod frozen;

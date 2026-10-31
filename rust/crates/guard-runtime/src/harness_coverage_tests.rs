use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::artifacts::{
    artifact_digest, is_same_directory, managed_manifest_paths, resolve_lenient, Evidence,
};
use super::{register, unregister, verify, Coverage, ErrorClass, REGISTRY_NAME};

struct Fixture {
    _root: tempfile::TempDir,
    state_root: PathBuf,
    home: PathBuf,
    owner: u32,
}

fn setup() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let base = resolve_lenient(root.path());
    let home = base.join("home");
    fs::create_dir_all(&home).unwrap();
    Fixture {
        state_root: base.join("state"),
        owner: owner_of(&home),
        home,
        _root: root,
    }
}

#[cfg(unix)]
fn owner_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;

    fs::metadata(path).unwrap().uid()
}

#[cfg(windows)]
fn owner_of(_path: &Path) -> u32 {
    0
}

fn install(name: &str, artifact: &Path) -> Value {
    json!({"active": true, "harness": name, "manifest": {"config_path": artifact}})
}

fn required(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn counts(fixture: &Fixture, names: &[&str]) -> Option<Coverage> {
    verify(&fixture.state_root, fixture.owner, &required(names)).coverage
}

fn coverage(
    required: usize,
    protected: usize,
    degraded: usize,
    missing: usize,
) -> Option<Coverage> {
    Some(Coverage {
        required,
        protected,
        degraded,
        missing,
    })
}

fn register_one(fixture: &Fixture, artifact: &Path) {
    register(
        &fixture.state_root,
        fixture.owner,
        &fixture.home,
        &[install("codex", artifact)],
    )
    .unwrap();
}

#[test]
fn a_registered_artifact_is_protected_until_it_changes_or_goes() {
    let fixture = setup();
    let artifact = fixture.home.join(".codex").join("config.toml");
    fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    fs::write(&artifact, "managed = true\n").unwrap();
    register_one(&fixture, &artifact);

    let initial = verify(
        &fixture.state_root,
        fixture.owner,
        &required(&["codex", "claude-code"]),
    );
    assert_eq!(
        (initial.state, initial.reason_code),
        ("degraded", "harness_coverage_missing")
    );
    assert_eq!(initial.coverage, coverage(2, 1, 0, 1));

    fs::write(&artifact, "managed = false\n").unwrap();
    assert_eq!(
        counts(&fixture, &["codex", "claude-code"]),
        coverage(2, 0, 1, 1)
    );

    fs::remove_file(&artifact).unwrap();
    assert_eq!(
        counts(&fixture, &["codex", "claude-code"]),
        coverage(2, 0, 0, 2)
    );
}

#[test]
fn nothing_required_is_healthy_without_a_registry() {
    let fixture = setup();
    let verification = verify(&fixture.state_root, fixture.owner, &[]);
    assert_eq!(
        (verification.state, verification.reason_code),
        ("healthy", "harness_coverage_not_required")
    );
    assert_eq!(verification.coverage, coverage(0, 0, 0, 0));
}

#[test]
fn an_absent_or_malformed_registry_is_unknown() {
    let fixture = setup();
    let absent = verify(&fixture.state_root, fixture.owner, &required(&["codex"]));
    assert_eq!(
        (absent.state, absent.reason_code, absent.coverage),
        ("unknown", "harness_coverage_registry_absent", None)
    );

    fs::create_dir_all(&fixture.state_root).unwrap();
    let registry = fixture.state_root.join(REGISTRY_NAME);
    for malformed in [
        "{}".to_owned(),
        "not json".to_owned(),
        json!({"schemaVersion": "hol-guard-harness-coverage-registry.v1", "users": [
            {"home": "relative", "harnesses": []}
        ]})
        .to_string(),
        json!({"schemaVersion": "hol-guard-harness-coverage-registry.v1", "users": [
            {"home": fixture.home, "harnesses": [{"name": "codex", "artifacts": [
                {"kind": "file", "path": "../escape", "sha256": "0".repeat(64)}
            ]}]}
        ]})
        .to_string(),
    ] {
        fs::write(&registry, malformed).unwrap();
        restrict(&registry);
        let tampered = verify(&fixture.state_root, fixture.owner, &required(&["codex"]));
        assert_eq!(
            (tampered.state, tampered.reason_code, tampered.coverage),
            ("unknown", "harness_coverage_probe_failed", None)
        );
    }
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(windows)]
fn restrict(_path: &Path) {}

#[cfg(unix)]
#[test]
fn a_shared_foreign_or_linked_registry_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let fixture = setup();
    fs::create_dir_all(&fixture.state_root).unwrap();
    let registry = fixture.state_root.join(REGISTRY_NAME);
    let empty = json!({"schemaVersion": "hol-guard-harness-coverage-registry.v1", "users": []});
    fs::write(&registry, empty.to_string()).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        verify(&fixture.state_root, fixture.owner, &required(&["codex"])).reason_code,
        "harness_coverage_probe_failed"
    );
    let refused = register(&fixture.state_root, fixture.owner, &fixture.home, &[]).unwrap_err();
    assert_eq!(
        (refused.class, refused.reason_code),
        (
            ErrorClass::Permission,
            "harness_coverage_registry_acl_invalid"
        )
    );

    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        verify(
            &fixture.state_root,
            fixture.owner + 1,
            &required(&["codex"])
        )
        .reason_code,
        "harness_coverage_probe_failed"
    );

    fs::remove_file(&registry).unwrap();
    let planted = fixture.home.join("attacker-registry.json");
    fs::write(&planted, empty.to_string()).unwrap();
    fs::set_permissions(&planted, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&planted, &registry).unwrap();
    assert_eq!(
        verify(&fixture.state_root, fixture.owner, &required(&["codex"])).reason_code,
        "harness_coverage_probe_failed"
    );
}

#[test]
fn every_user_is_counted_and_unregistering_keeps_the_registry() {
    let fixture = setup();
    let base = fixture.home.parent().unwrap().to_path_buf();
    for identity in ["alice", "bob"] {
        let home = base.join(identity);
        let artifact = home.join("config.json");
        fs::create_dir_all(&home).unwrap();
        fs::write(&artifact, identity).unwrap();
        register(
            &fixture.state_root,
            fixture.owner,
            &home,
            &[install("codex", &artifact)],
        )
        .unwrap();
    }
    assert_eq!(counts(&fixture, &["codex"]), coverage(2, 2, 0, 0));

    for identity in ["alice", "bob"] {
        let home = base.join(identity);
        unregister(&fixture.state_root, fixture.owner, home.to_str().unwrap()).unwrap();
    }
    let verification = verify(&fixture.state_root, fixture.owner, &required(&["codex"]));
    assert_eq!(
        (verification.state, verification.coverage),
        ("healthy", coverage(0, 0, 0, 0))
    );
    let written: Value =
        serde_json::from_slice(&fs::read(fixture.state_root.join(REGISTRY_NAME)).unwrap()).unwrap();
    assert_eq!(
        written,
        json!({"schemaVersion": "hol-guard-harness-coverage-registry.v1", "users": []})
    );
}

#[test]
fn unregistering_without_a_registry_writes_nothing() {
    let fixture = setup();
    unregister(
        &fixture.state_root,
        fixture.owner,
        fixture.home.to_str().unwrap(),
    )
    .unwrap();
    assert!(!fixture.state_root.exists());
}

#[test]
fn registration_writes_the_python_registry_bytes() {
    let fixture = setup();
    let artifact = fixture.home.join("config.json");
    fs::write(&artifact, "{}").unwrap();
    let inactive = json!({"active": 0, "harness": "cursor", "manifest": {}});
    register(
        &fixture.state_root,
        fixture.owner,
        &fixture.home,
        &[install("codex", &artifact), inactive],
    )
    .unwrap();

    let written = fs::read_to_string(fixture.state_root.join(REGISTRY_NAME)).unwrap();
    let home = fixture.home.to_str().unwrap();
    let digest = hex::encode(Sha256::digest(b"{}"));
    let expected = format!(
        "{{\"schemaVersion\":\"hol-guard-harness-coverage-registry.v1\",\"users\":[{{\"harnesses\":[{{\"artifacts\":[{{\"kind\":\"file\",\"path\":\"config.json\",\"sha256\":\"{digest}\"}}],\"name\":\"codex\"}}],\"home\":{}}}]}}\n",
        serde_json::to_string(home).unwrap()
    );
    assert_eq!(written, expected);
}

#[test]
fn registration_refuses_malformed_and_oversized_installs() {
    let fixture = setup();
    let mut nested = json!({});
    for _ in 0..18 {
        nested = json!({"nested": nested});
    }
    let refusals = [
        (
            vec![json!({"active": true, "harness": "codex", "manifest": nested})],
            "harness_coverage_manifest_invalid",
        ),
        (
            vec![json!({"active": true, "harness": "", "manifest": {}})],
            "harness_coverage_registry_invalid",
        ),
        (
            vec![
                json!({"active": true, "harness": "codex", "manifest": {}}),
                json!({"active": "yes", "harness": "codex", "manifest": {}}),
            ],
            "harness_coverage_registry_invalid",
        ),
        (
            (0..33)
                .map(|index| json!({"active": false, "harness": format!("h{index}"), "manifest": {}}))
                .collect(),
            "harness_coverage_registry_capacity_exceeded",
        ),
    ];
    for (installs, reason_code) in refusals {
        let refused =
            register(&fixture.state_root, fixture.owner, &fixture.home, &installs).unwrap_err();
        assert_eq!(
            (refused.class, refused.reason_code),
            (ErrorClass::Value, reason_code)
        );
    }
    assert!(!fixture.state_root.join(REGISTRY_NAME).exists());
}

#[test]
fn guard_state_is_present_however_large_it_grows() {
    let fixture = setup();
    let artifact = fixture.home.join("config.toml");
    fs::write(&artifact, "managed = true\n").unwrap();
    let state = fixture.home.join(".hol-guard").join("guard.db");
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    fs::write(&state, b"initial").unwrap();
    register_one(&fixture, &artifact);

    fs::write(&state, vec![0_u8; 3 * 1024 * 1024]).unwrap();
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 1, 0, 0));

    fs::remove_file(&state).unwrap();
    fs::create_dir(&state).unwrap();
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 0, 1, 0));

    fs::remove_dir(&state).unwrap();
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 0, 0, 1));
}

#[test]
fn a_directory_artifact_digests_its_tree_in_walk_order() {
    let fixture = setup();
    let extension = fixture.home.join(".guard-extension");
    fs::create_dir_all(extension.join("sub")).unwrap();
    fs::write(extension.join("a.txt"), "a").unwrap();
    fs::write(extension.join("sub").join("b.txt"), "b").unwrap();

    let file_digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let separator = std::path::MAIN_SEPARATOR;
    let entries = format!(
        "d:sub\nf:a.txt:{}\nf:sub{separator}b.txt:{}",
        file_digest(b"a"),
        file_digest(b"b")
    );
    assert_eq!(
        artifact_digest(&extension),
        Some(Evidence::Directory(file_digest(entries.as_bytes())))
    );
    assert_eq!(artifact_digest(&fixture.home.join("absent")), None);

    register_one(&fixture, &extension);
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 1, 0, 0));
    fs::write(extension.join("sub").join("b.txt"), "tampered").unwrap();
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 0, 1, 0));
}

#[test]
fn manifest_paths_stay_below_the_home() {
    let fixture = setup();
    let manifest = json!({
        "config_path": "~/.codex/config.toml",
        "nested": [{"shim_paths": ["bin/shim", "", "/etc/passwd", "~"]}],
        "hook_path": "../outside",
        "plugin_path": 7,
    });
    let paths = managed_manifest_paths(manifest.as_object().unwrap(), &fixture.home, 63).unwrap();
    assert_eq!(
        paths,
        vec![
            fixture.home.join(".codex").join("config.toml"),
            fixture.home.join("bin").join("shim"),
        ]
    );
    let limited = managed_manifest_paths(manifest.as_object().unwrap(), &fixture.home, 1).unwrap();
    assert_eq!(limited.len(), 1);
}

#[cfg(unix)]
#[test]
fn links_never_stand_in_for_a_registered_artifact() {
    use std::os::unix::fs::symlink;

    let fixture = setup();
    let outside = fixture.home.parent().unwrap().join("attacker-config");
    fs::write(&outside, "managed = true\n").unwrap();
    let artifact = fixture.home.join("config.toml");
    symlink(&outside, &artifact).unwrap();
    register_one(&fixture, &artifact);
    // A link out of the home is never registered, so the harness has nothing
    // to protect.
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 0, 1, 0));

    fs::remove_file(&artifact).unwrap();
    fs::write(&artifact, "managed = true\n").unwrap();
    register_one(&fixture, &artifact);
    fs::remove_file(&artifact).unwrap();
    let replacement = fixture.home.join("replacement.toml");
    fs::write(&replacement, "managed = true\n").unwrap();
    symlink(&replacement, &artifact).unwrap();
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 0, 0, 1));

    fs::remove_file(&artifact).unwrap();
    symlink(&outside, &artifact).unwrap();
    assert_eq!(counts(&fixture, &["codex"]), coverage(1, 0, 1, 0));
}

#[cfg(unix)]
#[test]
fn lenient_resolution_follows_links_and_keeps_the_missing_rest() {
    use std::os::unix::fs::symlink;

    let fixture = setup();
    let real = fixture.home.join("real");
    fs::create_dir(&real).unwrap();
    symlink("real", fixture.home.join("relative")).unwrap();
    symlink(&real, fixture.home.join("absolute")).unwrap();
    symlink("loop", fixture.home.join("loop")).unwrap();

    assert_eq!(
        resolve_lenient(&fixture.home.join("relative/x/y")),
        real.join("x/y")
    );
    assert_eq!(
        resolve_lenient(&fixture.home.join("absolute/../z")),
        fixture.home.join("z")
    );
    assert!(resolve_lenient(&fixture.home.join("loop")).starts_with(&fixture.home));
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_link_while_queued_is_not_followed() {
    use std::os::unix::fs::symlink;

    let fixture = setup();
    let extension = fixture.home.join(".guard-extension");
    let nested = extension.join("sub").join("deeper");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("b.txt"), "b").unwrap();
    let queued = fs::symlink_metadata(&nested).unwrap();
    assert!(is_same_directory(&nested, &queued));

    let identical = fixture.home.join("identical");
    fs::create_dir_all(&identical).unwrap();
    fs::write(identical.join("b.txt"), "b").unwrap();
    fs::remove_dir_all(&nested).unwrap();
    symlink(&identical, &nested).unwrap();
    assert!(!is_same_directory(&nested, &queued));
    assert_eq!(artifact_digest(&extension), None);
}

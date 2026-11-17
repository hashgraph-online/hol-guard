use super::*;
use crate::codex_hook_bridge::trust::argv_sha256;

fn object(value: Value) -> Object {
    value.as_object().cloned().unwrap()
}

fn message(refusal: Refusal) -> String {
    assert_eq!(refusal.0, LAUNCH_INVALID);
    refusal.1
}

#[test]
fn managed_paths_belong_to_one_guard_home() {
    let home = std::env::temp_dir().join(format!(
        "launch-trust-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let state = home.join(STATE_FILE);
    let manifest = home
        .join("managed")
        .join("codex")
        .join("hooks-abc.manifest.json");
    let (found, _) = managed_paths(&state, &manifest).unwrap();
    assert_eq!(found, canonical(&home));
    let relative = managed_paths(Path::new("daemon-state.json"), &manifest).unwrap_err();
    assert_eq!(
        message(relative),
        "managed Codex hook paths must be absolute"
    );
    let elsewhere = managed_paths(&state, &home.join("hooks-abc.manifest.json")).unwrap_err();
    assert_eq!(
        message(elsewhere),
        "managed Codex hook paths do not belong to this Guard home"
    );
    let misnamed = home.join("managed").join("codex").join("other.json");
    assert_eq!(
        message(managed_paths(&state, &misnamed).unwrap_err()),
        "managed Codex hook manifest path is invalid"
    );
}

fn generation(bridge: &str, config: &str) -> Value {
    json!({
        "installation_id": "install",
        "context": {"runtime_guard_home": "/home"},
        "packaged_files": [{"role": "bridge", "path": bridge}],
        "events": [{"argv": [bridge, BRIDGE_COMMAND, config]}],
    })
}

#[test]
fn a_retained_generation_is_selected_only_by_its_recorded_hash() {
    let config = "{}";
    let mut manifest = object(generation("/new/runtime", config));
    let old = generation("/old/runtime", config);
    manifest.insert("retained_bridge_generations".into(), json!([old]));
    // Every event registers the retained layout, not the current one.
    manifest.insert(
        "events".into(),
        json!([{"argv": ["/old/runtime", BRIDGE_COMMAND, config]}]),
    );
    let selected = selected_generation(&manifest, config).unwrap();
    assert!(
        std::ptr::eq(selected, &manifest),
        "unlisted retained argv falls back"
    );
    let hash = argv_sha256(&["/old/runtime", BRIDGE_COMMAND, config]);
    manifest.insert("compatible_bridge_argv_sha256".into(), json!([hash]));
    let selected = selected_generation(&manifest, config).unwrap();
    assert_eq!(selected.get("packaged_files"), old.get("packaged_files"));
    manifest.insert("compatible_bridge_argv_sha256".into(), json!(["XYZ"]));
    assert_eq!(
        message(selected_generation(&manifest, config).unwrap_err()),
        "managed Codex hook bridge compatibility identity is invalid"
    );
}

#[test]
fn a_registration_install_never_recorded_is_refused() {
    let manifest = object(generation("/runtime", "{}"));
    let bridge = object(json!({"path": "/runtime"}));
    assert!(registered_bridge_argv(&manifest, &bridge, "{}").is_ok());
    assert_eq!(
        message(registered_bridge_argv(&manifest, &bridge, r#"{"changed":1}"#).unwrap_err()),
        "managed Codex hook bridge config changed after authentication"
    );
    assert_eq!(
        message(registered_bridge_argv(&manifest, &bridge, "[]").unwrap_err()),
        "managed Codex hook bridge config is malformed"
    );
}

#[test]
fn a_package_must_name_exactly_the_launch_roles() {
    // Each file is checked as it is read, before the next role is counted.
    let manifest = object(json!({"packaged_files": [{"role": "bridge"}, {"role": "bridge"}]}));
    let refusal = packaged_files(&manifest, &[]).unwrap_err();
    assert_eq!(refusal.0, "codex_hook_bridge_identity_invalid");
    let manifest = object(json!({"packaged_files": [{"path": "/x"}]}));
    assert_eq!(
        message(packaged_files(&manifest, &[]).unwrap_err()),
        "managed Codex hook packaged-file roles are invalid"
    );
    let manifest = object(json!({"packaged_files": "none"}));
    assert_eq!(
        message(packaged_files(&manifest, &[]).unwrap_err()),
        "managed Codex hook packaged-file identity is invalid"
    );
}

#[test]
fn a_captured_manifest_without_events_is_refused_before_any_launch() {
    let args = object(json!({"manifest": {"interpreter": "none"}}));
    assert_eq!(
        message(captured(&args, &[]).unwrap_err()),
        "managed Codex hook interpreter identity is invalid"
    );
}

fn layout(drop: &[&str], foreign: Option<&str>) -> Vec<(&'static str, Object)> {
    let names = [
        ("bridge", "native-bridge"),
        ("daemon_entrypoint", "daemon.py"),
        ("daemon_manager", "manager.py"),
        ("fallback_entrypoint", "cli.py"),
        ("launch_runtime", "codex_hook_launch_runtime.py"),
        ("runtime_trust", "codex_hook_runtime_trust.py"),
        ("windows_job", "codex_hook_windows_job.py"),
        ("hook_probe", "runtime_transition_hook_probe.py"),
        ("native_receipt", "native_decision_receipt.py"),
    ];
    names
        .into_iter()
        .filter(|(role, _)| !drop.contains(role))
        .map(|(role, name)| {
            let path = if foreign == Some(role) {
                "/untrusted/probe.py".to_owned()
            } else {
                format!("/opt/guard/{name}")
            };
            (role, object(json!({"role": role, "path": path})))
        })
        .collect()
}

#[test]
fn observation_roles_come_all_together_or_not_at_all() {
    let trust = Path::new("/opt/guard/codex_hook_runtime_trust.py");
    let check = |drop: &[&str], foreign: Option<&str>| {
        let owned = layout(drop, foreign);
        let packaged: Packaged<'_> = owned.iter().map(|(role, id)| (*role, id)).collect();
        complete(&packaged)
            .and_then(|()| verify_observation_paths(&packaged, trust))
            .map_err(|refusal| refusal.1)
    };
    assert!(check(&[], None).is_ok(), "current layout");
    assert!(
        check(&["hook_probe", "native_receipt"], None).is_ok(),
        "legacy layout"
    );
    assert_eq!(
        check(&["native_receipt"], None).unwrap_err(),
        "managed Codex hook package identity is incomplete"
    );
    assert_eq!(
        check(&[], Some("hook_probe")).unwrap_err(),
        "managed Codex observation package path is invalid"
    );
}

#[test]
fn an_install_that_still_records_the_retired_bridge_runtime_role_is_refused() {
    // The role named a Python file the hook never runs; a manifest from before
    // it was retired fails closed with the repair wording, not a crash.
    let mut owned = layout(&[], None);
    owned.push((
        "bridge_runtime",
        object(
            json!({"role": "bridge_runtime", "path": "/opt/guard/codex_hook_bridge_runtime.py"}),
        ),
    ));
    let packaged: Packaged<'_> = owned.iter().map(|(role, id)| (*role, id)).collect();
    let refusal = complete(&packaged).unwrap_err();
    assert_eq!(refusal.0, LAUNCH_INVALID);
    assert_eq!(
        refusal.1,
        "managed Codex hook package identity is incomplete"
    );
}

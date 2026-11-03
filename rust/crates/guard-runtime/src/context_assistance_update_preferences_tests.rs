use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
fn fixture() -> tempfile::TempDir {
    let f = tempfile::tempdir().unwrap();
    fs::set_permissions(f.path(), fs::Permissions::from_mode(0o700)).unwrap();
    f
}
fn source(
    home: &Path,
    settings: Value,
    locks: Value,
) -> crate::managed_policy_load::ManagedPolicySource {
    let path = home.join("fixture-update-policy.json");
    fs::write(&path,json!({"schemaVersion":"hol-guard-mdm-policy.v1","settings":{KEY:settings},"lockedSettings":locks}).to_string()).unwrap();
    let mut s = native_source();
    s.policy_path = Some(path);
    s.write_cache = false;
    s
}
#[test]
fn passive_default_preferences_do_not_provision_installations_or_jobs() {
    let f = fixture();
    let v = read(f.path()).unwrap();
    assert_eq!(v["requested"]["mode"], "manual");
    assert_eq!(v["effective"]["allow_preview"], false);
    assert_eq!(v["capabilities"]["automatic_selection"], false);
    assert!(!f.path().join("config.toml").exists());
    assert!(!f.path().join("context-assistance").exists());
}
#[test]
fn preferences_roundtrip_preserves_serving_intent_other_settings_and_off_state() {
    let f = fixture();
    let path = f.path().join("config.toml");
    fs::write(&path,"mode='enforce'\n# keep this comment\n[context_assistance]\nenabled=false\nruntime_id='kept-slot'\n").unwrap();
    let old = crate::guard_config_load::context_assistance_config(f.path()).unwrap();
    let s = crate::context_assistance_service::Service::default();
    s.configure(old.clone()).unwrap();
    let status = s.status().unwrap();
    let v = read(f.path()).unwrap();
    let prefs = UpdatePreferences {
        mode: UpdateMode::Notify,
        pinned_build: Some("exact-build".into()),
        ..Default::default()
    };
    let answer = write(f.path(), v["revision"].as_str().unwrap(), prefs.clone()).unwrap();
    assert_eq!(answer["requested"], serde_json::to_value(prefs).unwrap());
    assert_ne!(v["revision"], answer["revision"]);
    assert!(old == crate::guard_config_load::context_assistance_config(f.path()).unwrap());
    s.configure(crate::guard_config_load::context_assistance_config(f.path()).unwrap())
        .unwrap();
    assert_eq!(s.status().unwrap(), status);
    let text = fs::read_to_string(path).unwrap();
    assert!(text.contains("# keep this comment"));
    assert!(text.contains("mode='enforce'"));
    assert!(!f.path().join("context-assistance").exists());
    s.shutdown();
}
#[test]
fn a_competing_edit_or_repeated_stop_invalidates_the_revision() {
    let f = fixture();
    let before = read(f.path()).unwrap();
    crate::guard_config_update::disable_context_assistance(f.path()).unwrap();
    let after = fs::read(f.path().join("config.toml")).unwrap();
    assert_eq!(
        write(
            f.path(),
            before["revision"].as_str().unwrap(),
            UpdatePreferences::default()
        )
        .unwrap_err(),
        error("update_preferences_conflict")
    );
    assert_eq!(fs::read(f.path().join("config.toml")).unwrap(), after);
    let fresh = read(f.path()).unwrap();
    crate::guard_config_update::disable_context_assistance(f.path()).unwrap();
    assert_eq!(
        write(
            f.path(),
            fresh["revision"].as_str().unwrap(),
            UpdatePreferences::default()
        )
        .unwrap_err(),
        error("update_preferences_conflict")
    );
}
#[test]
fn native_machine_caps_and_locks_cannot_be_replaced_by_request_preferences() {
    let f = fixture();
    let source = source(
        f.path(),
        json!({"mode":"manual","allow_preview":false,"pinned_build":"machine-build"}),
        json!([
            "context_assistance_updates.mode",
            "context_assistance_updates.pinned_build"
        ]),
    );
    let rev = revision(None);
    let notify = UpdatePreferences {
        mode: UpdateMode::Notify,
        ..Default::default()
    };
    assert_eq!(
        write_with_source(f.path(), &rev, notify, &source).unwrap_err(),
        error("update_preferences_locked")
    );
    assert!(!f.path().join("config.toml").exists());
    let requested = UpdatePreferences {
        pinned_build: Some("machine-build".into()),
        allow_preview: true,
        ..Default::default()
    };
    let v = write_with_source(f.path(), &rev, requested, &source).unwrap();
    assert_eq!(v["requested"]["allow_preview"], true);
    assert_eq!(v["effective"]["allow_preview"], false);
    assert_eq!(v["effective"]["pinned_build"], "machine-build");
}
#[test]
fn malformed_preferences_are_local_diagnostics_and_can_be_explicitly_repaired() {
    let f = fixture();
    fs::write(
        f.path().join("config.toml"),
        "[context_assistance_updates]\nallow_preview='private-invalid-value'\n",
    )
    .unwrap();
    let v = read(f.path()).unwrap();
    assert!(v["diagnostic"]
        .as_str()
        .unwrap()
        .ends_with("update_preferences_invalid"));
    assert!(selection_rules(f.path(), &native_source()).is_err());
    let v = write(
        f.path(),
        v["revision"].as_str().unwrap(),
        UpdatePreferences::default(),
    )
    .unwrap();
    assert!(v["diagnostic"].is_null());
    assert_eq!(v["effective"]["mode"], "manual");
    assert!(!f.path().join("context-assistance").exists());
}
#[test]
fn unavailable_automatic_preparation_and_retention_reduction_do_not_write() {
    let f = fixture();
    let v = read(f.path()).unwrap();
    let r = v["revision"].as_str().unwrap();
    assert_eq!(
        write(
            f.path(),
            r,
            UpdatePreferences {
                mode: UpdateMode::Prepare,
                ..Default::default()
            }
        )
        .unwrap_err(),
        error("update_preparation_policy_unavailable")
    );
    assert_eq!(
        write(
            f.path(),
            r,
            UpdatePreferences {
                retain_last_good: false,
                ..Default::default()
            }
        )
        .unwrap_err(),
        error("update_retention_reduction_unavailable")
    );
    assert!(!f.path().join("config.toml").exists());
    assert!(write(f.path(), "sha256:wrong", UpdatePreferences::default()).is_err());
}
#[test]
fn malformed_machine_restrictions_and_unavailable_policy_refuse_publication() {
    let f = fixture();
    let source = source(f.path(), json!({"enabled":true}), json!([]));
    assert!(write_with_source(
        f.path(),
        &revision(None),
        UpdatePreferences::default(),
        &source
    )
    .unwrap_err()
    .ends_with("update_preferences_invalid"));
    fs::write(
        source.policy_path.as_ref().unwrap(),
        "invalid fixture policy",
    )
    .unwrap();
    assert_eq!(
        write_with_source(
            f.path(),
            &revision(None),
            UpdatePreferences::default(),
            &source
        )
        .unwrap_err(),
        error("update_policy_unavailable")
    );
    assert!(!f.path().join("config.toml").exists());
}

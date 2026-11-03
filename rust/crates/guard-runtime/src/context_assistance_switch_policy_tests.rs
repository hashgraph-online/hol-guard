//! Candidate selection preserves local intent while native policy narrows both
//! sides. These tests use an explicit fixture-only machine policy source.
use super::*;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    policy: PathBuf,
    requested: ContextAssistanceConfig,
}
impl Fixture {
    fn new(enabled: bool, restriction: Value) -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let requested = ContextAssistanceConfig {
            enabled,
            runtime_id: "old".into(),
            ..Default::default()
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(home.join("config.toml"))
            .unwrap();
        file.write_all(
            toml::to_string(&std::collections::BTreeMap::from([(
                "context_assistance",
                &requested,
            )]))
            .unwrap()
            .as_bytes(),
        )
        .unwrap();
        let policy = home.join("fixture-machine-policy.json");
        let result = Self {
            _root: root,
            home,
            policy,
            requested,
        };
        result.restrict(restriction);
        result
    }
    fn restrict(&self, value: Value) {
        let locks = if value["limits"]["context_tokens"].is_number() {
            vec!["context_assistance.limits.context_tokens"]
        } else {
            Vec::new()
        };
        fs::write(
            &self.policy,
            json!({"schemaVersion":"hol-guard-mdm-policy.v1",
            "settings":{"context_assistance":value}, "lockedSettings":locks})
            .to_string(),
        )
        .unwrap();
    }
    fn source(&self) -> crate::managed_policy_load::ManagedPolicySource {
        let mut source = crate::managed_policy_load::ManagedPolicySource::native();
        source.policy_path = Some(self.policy.clone());
        source.write_cache = false;
        source
    }
    fn effective(&self) -> ContextAssistanceConfig {
        crate::guard_config_load::context_assistance_from_source(&self.home, &self.source())
            .unwrap()
            .effective
    }
}
#[test]
fn target_uses_current_native_caps_without_rewriting_requested_preferences() {
    let f = Fixture::new(true, json!({"limits":{"context_tokens":1024}}));
    let original = fs::read(f.home.join("config.toml")).unwrap();
    let source = f.effective();
    assert_eq!(source.limits.context_tokens, 1024);
    let settings =
        SwitchSettings::capture_with_policy(&f.home, &source, "new", &f.source()).unwrap();
    assert_eq!(settings.target().limits.context_tokens, 1024);
    assert_eq!(
        settings.target_settings().requested.limits.context_tokens,
        f.requested.limits.context_tokens
    );
    assert_eq!(settings.target_settings().requested.runtime_id, "new");
    assert_eq!(
        settings.target_settings().restriction,
        Some("managed_policy")
    );
    settings.check_with_policy(&f.source()).unwrap();
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), original);
}
#[test]
fn later_policy_restriction_invalidates_a_prepared_selection_even_with_unchanged_config_bytes() {
    let f = Fixture::new(true, json!({"limits":{"context_tokens":1024}}));
    let original = fs::read(f.home.join("config.toml")).unwrap();
    let settings =
        SwitchSettings::capture_with_policy(&f.home, &f.effective(), "new", &f.source()).unwrap();
    f.restrict(json!({"limits":{"context_tokens":512}}));
    assert!(settings.check_with_policy(&f.source()).is_err());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), original);
}
#[test]
fn managed_disable_or_unknown_runtime_selection_never_authorizes_candidate_verification() {
    for restriction in [
        json!({"enabled":false}),
        json!({"runtime_id":"machine-runtime"}),
    ] {
        let f = Fixture::new(true, restriction);
        let original = fs::read(f.home.join("config.toml")).unwrap();
        assert!(
            SwitchSettings::capture_with_policy(&f.home, &f.effective(), "new", &f.source())
                .is_err()
        );
        assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), original);
    }
}
#[test]
fn a_managed_true_does_not_enable_a_disabled_user_when_changing_local_selection() {
    let f = Fixture::new(false, json!({"enabled":true}));
    let settings =
        SwitchSettings::capture_with_policy(&f.home, &f.effective(), "new", &f.source()).unwrap();
    assert!(!settings.source().enabled);
    assert!(!settings.target().enabled);
    assert!(!settings.target_settings().requested.enabled);
}
#[test]
fn unreadable_or_invalid_policy_after_preparation_refuses_without_changing_local_intent() {
    let f = Fixture::new(true, json!({"limits":{"context_tokens":1024}}));
    let original = fs::read(f.home.join("config.toml")).unwrap();
    let settings =
        SwitchSettings::capture_with_policy(&f.home, &f.effective(), "new", &f.source()).unwrap();
    fs::write(&f.policy, "invalid private fixture policy").unwrap();
    assert!(settings.check_with_policy(&f.source()).is_err());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), original);
}

#[test]
fn restoration_rechecks_both_sides_against_native_policy_before_writing_any_settings() {
    let f = Fixture::new(true, json!({"limits":{"context_tokens":1024}}));
    let settings =
        SwitchSettings::capture_with_policy(&f.home, &f.effective(), "new", &f.source()).unwrap();
    assert!(!settings.check_restore_with_policy(&f.source()).unwrap());
    fs::write(f.home.join("config.toml"), &settings.after).unwrap();
    assert!(settings.check_restore_with_policy(&f.source()).unwrap());
    let before = fs::read(f.home.join("config.toml")).unwrap();
    for policy in [
        json!({"enabled":false}),
        json!({"limits":{"context_tokens":512}}),
    ] {
        f.restrict(policy);
        assert!(settings.check_restore_with_policy(&f.source()).is_err());
        assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    }
}

#[test]
fn later_managed_update_pin_invalidates_ready_without_rewriting_runtime_preferences() {
    let f = Fixture::new(true, json!({"limits":{"context_tokens":1024}}));
    let before = fs::read(f.home.join("config.toml")).unwrap();
    let settings =
        SwitchSettings::capture_with_policy(&f.home, &f.effective(), "new", &f.source()).unwrap();
    fs::write(
        &f.policy,
        json!({"schemaVersion":"hol-guard-mdm-policy.v1","settings":{
            "context_assistance":{"limits":{"context_tokens":1024}},
            "context_assistance_updates":{"pinned_build":"required-build"}
        }})
        .to_string(),
    )
    .unwrap();
    assert!(settings.check_with_policy(&f.source()).is_err());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    assert_eq!(f.effective(), *settings.source());
}

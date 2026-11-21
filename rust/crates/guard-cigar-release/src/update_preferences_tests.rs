use super::*;
use serde_json::json;
#[test]
fn strict_partial_preferences_keep_manual_stable_and_recovery_defaults() {
    let p = UpdatePreferences::parse(json!({"pinned_build":"same-version-final-build"})).unwrap();
    assert_eq!(p.mode, UpdateMode::Manual);
    assert!(!p.allow_preview);
    assert!(p.retain_last_good);
    assert_eq!(p.pinned_build.as_deref(), Some("same-version-final-build"));
    for bad in [
        json!(null),
        json!(true),
        json!({"allow_preview":1}),
        json!({"mode":"automatic"}),
        json!({"runtime_id":"untrusted"}),
        json!({"pinned_build":"/tmp/python"}),
        json!({"pinned_build":""}),
        json!({"retain_last_good":null}),
    ] {
        assert_eq!(
            UpdatePreferences::parse(bad),
            Err(ReleaseError::InvalidUpdatePreferences)
        );
    }
}
#[test]
fn managed_policy_cannot_expand_local_optional_work_preview_or_deletion() {
    let local = UpdatePreferences::default();
    let effective=local.restrict(&json!({"mode":"prepare","allow_preview":true,"retain_last_good":false,"pinned_build":null})).unwrap();
    assert_eq!(local, effective);
    let local = UpdatePreferences {
        mode: UpdateMode::Prepare,
        allow_preview: true,
        retain_last_good: false,
        pinned_build: Some("local-exact-build".into()),
    };
    let effective = local
        .restrict(&json!({"mode":"notify","allow_preview":false,"retain_last_good":true}))
        .unwrap();
    assert_eq!(effective.mode, UpdateMode::Notify);
    assert!(!effective.allow_preview);
    assert!(effective.retain_last_good);
    assert_eq!(effective.pinned_build, local.pinned_build);
}
#[test]
fn managed_pin_and_malformed_restrictions_cannot_be_mistaken_for_activation() {
    let p = UpdatePreferences::default()
        .restrict(&json!({"pinned_build":"required-exact-build"}))
        .unwrap();
    assert_eq!(p.mode, UpdateMode::Manual);
    assert_eq!(p.pinned_build.as_deref(), Some("required-exact-build"));
    for raw in [
        json!(null),
        json!({"allow_preview":null}),
        json!({"mode":true}),
        json!({"enabled":true}),
        json!({"pinned_build":"http://example.test"}),
    ] {
        assert!(p.restrict(&raw).is_err());
    }
    let value = serde_json::to_value(p).unwrap();
    for name in ["enabled", "runtime_id", "grant", "approval", "activate"] {
        assert!(value.get(name).is_none());
    }
}

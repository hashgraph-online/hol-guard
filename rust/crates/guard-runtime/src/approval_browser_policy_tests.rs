use std::fs;

#[test]
fn native_only_disables_automatic_browser_fallback() {
    let home = std::env::temp_dir().join(format!(
        "guard-browser-policy-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir_all(&home).unwrap();
    let mut source = crate::managed_policy_load::ManagedPolicySource::native();
    source.machine_root = Some(home.join("machine-root"));
    fs::create_dir_all(source.machine_root.as_ref().unwrap()).unwrap();
    let config = home.join("config.toml");
    for (policy, allowed) in [
        ("native-only", false),
        ("attention-aware", true),
        ("approval-center", true),
    ] {
        fs::write(&config, format!("approval_surface_policy = {policy:?}\n")).unwrap();
        assert_eq!(
            crate::guard_config_load::approval_browser_allowed_under(&home, &source).unwrap(),
            allowed
        );
    }
    fs::write(&config, "approval_surface_policy = [\n").unwrap();
    assert!(crate::guard_config_load::approval_browser_allowed_under(&home, &source).is_err());
    fs::remove_file(config).unwrap();
    assert!(crate::guard_config_load::approval_browser_allowed_under(&home, &source).unwrap());
    fs::remove_dir_all(home).unwrap();
}

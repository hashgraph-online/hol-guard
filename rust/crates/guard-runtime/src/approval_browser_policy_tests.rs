use std::fs;

#[test]
fn native_only_disables_automatic_browser_fallback() {
    let home = std::env::temp_dir().join(format!(
        "guard-browser-policy-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir_all(&home).unwrap();
    let config = home.join("config.toml");
    for (policy, allowed) in [
        ("native-only", false),
        ("attention-aware", true),
        ("approval-center", true),
    ] {
        fs::write(&config, format!("approval_surface_policy = {policy:?}\n")).unwrap();
        assert_eq!(
            crate::guard_config_load::approval_browser_allowed(&home).unwrap(),
            allowed
        );
    }
    fs::remove_file(config).unwrap();
    assert!(crate::guard_config_load::approval_browser_allowed(&home).unwrap());
    fs::remove_dir(home).unwrap();
}

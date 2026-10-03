use guard_contracts::GuardExecutionEnvironmentV1;

fn context() -> GuardExecutionEnvironmentV1 {
    GuardExecutionEnvironmentV1 {
        path: "/usr/bin".into(),
        environment_names: vec!["PATH".into()],
        environment_digest: "a".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
    }
}

#[test]
fn shared_environment_shape_accepts_wire_boundaries_and_unicode_names() {
    let mut value = context();
    assert!(value.has_valid_shape());
    value.path = "p".repeat(32 * 1024);
    value.environment_names = vec!["n".repeat(256); 512];
    assert!(value.has_valid_shape());
    value.environment_names = vec!["name\u{200d}joiner".into(), "name\u{a0}space".into()];
    assert!(value.has_valid_shape());
}

#[test]
fn shared_environment_shape_rejects_each_invalid_boundary() {
    for case in 0..8 {
        let mut value = context();
        match case {
            0 => value.path.push('\0'),
            1 => value.home = Some("p".repeat(32 * 1024 + 1)),
            2 => value.xdg_config_home = Some("bad\0path".into()),
            3 => value.environment_names = vec!["name".into(); 513],
            4 => value.environment_names = vec!["n".repeat(257)],
            5 => value.environment_names = vec!["name\ncontrol".into()],
            6 => value.environment_digest = "A".repeat(64),
            _ => {
                value.environment_digest.pop();
            }
        }
        assert!(!value.has_valid_shape(), "case {case}");
    }
    assert!(!GuardExecutionEnvironmentV1::unavailable().has_valid_shape());
}

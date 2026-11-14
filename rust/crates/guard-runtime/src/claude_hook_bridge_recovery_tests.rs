use serde_json::{json, Map, Value};

use super::*;

fn launcher(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn an_interpreter_recovers_the_guard_home_and_home_the_hook_names() {
    let root = std::env::temp_dir();
    let command = launcher_recovery(
        "/guard home/daemon-state.json",
        "guard-home=%2Fguard+home&home=%2Fuser%20home%2F",
        &launcher(
            json!({"executable": "/usr/bin/python3", "package_root": root.to_str().unwrap()}),
        ),
    )
    .unwrap();
    assert_eq!(command[..3], ["/usr/bin/python3", "-I", "-c"]);
    assert!(command[3].contains("native_daemon_manage import schedule_guard_daemon_recovery"));
    assert!(command[3].contains("Path('/guard home'),home_dir=Path('/user home')"));
    assert_eq!(command.len(), 4);
}

#[test]
fn a_frozen_guard_recovers_through_its_private_argument() {
    let command = launcher_recovery(
        "/g/daemon-state.json",
        "home=%2Fh",
        &launcher(json!({"executable": "/Applications/HOL Guard", "frozen": true})),
    )
    .unwrap();
    assert_eq!(
        command[..2],
        ["/Applications/HOL Guard", FROZEN_RECOVER_ARG]
    );
    let payload: Value = serde_json::from_str(&command[2]).unwrap();
    assert_eq!(payload, json!({"guard_home": "/g", "home_dir": "/h"}));
    assert!(command[2].starts_with(r#"{"guard_home":"#));
}

#[test]
fn a_launcher_that_names_no_recovery_program_is_refused() {
    let root = std::env::temp_dir();
    let root = root.to_str().unwrap();
    for value in [
        json!({}),
        json!({"executable": ""}),
        json!({"executable": "/py"}),
        json!({"executable": "/py", "package_root": ""}),
        json!({"executable": "/py", "frozen": true, "package_root": root}),
        json!({"executable": "/py", "frozen": "yes"}),
        json!({"executable": 1, "package_root": root}),
    ] {
        assert_eq!(
            launcher_recovery("/g/daemon-state.json", "", &launcher(value.clone())),
            None,
            "{value}"
        );
    }
}

#[test]
fn the_legacy_config_names_a_launcher_or_a_command_never_both() {
    use crate::claude_hook_bridge::parse_config;

    let config = |extra: Value| {
        let mut base = json!({
            "state_path": "/g/daemon-state.json",
            "fallback_daemon_url": "http://127.0.0.1:5474",
            "fallback_command": ["/py"],
            "query": "home=%2Fh",
        });
        base.as_object_mut().unwrap().extend(launcher(extra));
        parse_config(&base.to_string())
    };
    let frozen = json!({"executable": "/guard", "frozen": true});
    let derived = config(json!({"recovery_launcher": frozen})).unwrap();
    assert_eq!(derived.recovery_command[1], FROZEN_RECOVER_ARG);
    assert!(config(json!({"recovery_launcher": frozen, "recovery_command": ["/x"]})).is_none());
    assert!(config(json!({"recovery_launcher": {"executable": "/py"}})).is_none());
    assert!(config(json!({"recovery_launcher": "frozen"})).is_none());
    assert_eq!(
        config(json!({})).unwrap().recovery_command,
        Vec::<String>::new()
    );
}

//! The argv and config a frozen Guard writes for the native bounded hook
//! bridge: `[guard, "__guard-bounded-hook", config]` in place of an
//! interpreter and its bootstrap.

use serde_json::json;

use super::config::MANAGED_MARKER;
use super::tests::{argv, config_text};
use super::*;

#[test]
fn a_frozen_guard_argv_carries_its_config() {
    let frozen = argv(&["/opt/hol-guard", "__guard-bounded-hook", "{}"]);
    assert_eq!(config_argument(&frozen), Some("{}"));
    assert!(frozen_launch(&frozen));
    let marked = argv(&[
        "/opt/hol-guard",
        "__guard-bounded-hook",
        "{}",
        "#",
        MANAGED_MARKER,
    ]);
    assert_eq!(config_argument(&marked), Some("{}"));
    assert!(!frozen_launch(&argv(&["py", "-I", "-c", "code", "{}"])));
    let refused: [&[&str]; 4] = [
        &["/opt/hol-guard", "__guard-cursor-hook", "{}"],
        &["/opt/hol-guard", "__guard-bounded-hook"],
        &["/opt/hol-guard", "__guard-bounded-hook", "{}", "extra"],
        &[
            "/opt/hol-guard",
            "__guard-bounded-hook",
            "{}",
            "x",
            MANAGED_MARKER,
        ],
    ];
    for items in refused {
        assert_eq!(config_argument(&argv(items)), None, "{items:?}");
    }
}

#[test]
fn a_frozen_config_is_served_only_from_a_frozen_argv() {
    let frozen = config_text(&[
        ("frozen_launcher", Some(json!(true))),
        (
            "start_command",
            Some(json!([
                "/opt/hol-guard",
                "--_hol-guard-codex-daemon-recover",
                "{}"
            ])),
        ),
    ]);
    assert_eq!(
        parse_launch_config(&frozen, true).map(|config| config.start_command),
        Some(argv(&[
            "/opt/hol-guard",
            "--_hol-guard-codex-daemon-recover",
            "{}"
        ]))
    );
    assert_eq!(parse_launch_config(&frozen, false), None);
    for launcher in [Some(json!(false)), None, Some(json!("yes"))] {
        let config = config_text(&[("frozen_launcher", launcher)]);
        assert_eq!(parse_launch_config(&config, true), None, "{config}");
    }
}

#[test]
fn a_frozen_config_without_a_start_command_never_starts_python() {
    let config = config_text(&[
        ("frozen_launcher", Some(json!(true))),
        ("start_command", None),
    ]);
    let parsed = parse_launch_config(&config, true).unwrap();
    assert!(parsed.start_command.is_empty());
}

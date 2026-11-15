//! The answer for a hook whose client this bridge cannot read.

use super::*;

#[test]
fn an_unreadable_client_fails_each_hook_as_its_own_event() {
    let observer = br#"{"hook_event_name":"PostToolUse","tool_name":"Bash"}"#;
    assert_eq!(client_unreadable_stdout(observer), "{}\n");
    let pre_tool = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#;
    assert_eq!(
        client_unreadable_stdout(pre_tool),
        failure_stdout(std::str::from_utf8(pre_tool).unwrap())
    );
    for refused in [
        &br#"{"hook_event_name":"PostToolUse","event":"PreToolUse"}"#[..],
        b"not json",
        b"\xff\xfe",
    ] {
        assert_eq!(client_unreadable_stdout(refused), failure_stdout("{}"));
    }
}

#[test]
fn a_grok_config_without_a_client_names_the_home_and_timeout_it_would_hold() {
    let config = r#"{"python_executable":"/usr/bin/python3","package_root":"/pkg","guard_home":"/home/g","cli_args":["guard","hook"],"harness":"grok","timeout_seconds":30,"frozen_launcher":false}"#;
    assert_eq!(config_constants(config), Some(("/home/g".to_owned(), 30.0)));
    for refused in [
        r#"{"guard_home":"/home/g","timeout_seconds":0}"#,
        r#"{"guard_home":"/home/g","timeout_seconds":true}"#,
        r#"{"timeout_seconds":30}"#,
        "[]",
    ] {
        assert_eq!(config_constants(refused), None, "{refused}");
    }
}

#[test]
fn only_a_grok_config_takes_the_grok_route() {
    assert!(names_grok(r#"{"harness":"grok","timeout_seconds":30}"#));
    assert!(!names_grok(r#"{"harness":"kimi","timeout_seconds":30}"#));
    assert!(!names_grok("not json"));
}

#[test]
fn path_options_accept_this_platforms_absolute_paths() {
    use crate::bounded_hook_bridge_grok_script::native_absolute_on;

    for windows_absolute in [
        r"C:\Users\me\.hol-guard",
        "c:/Users/me",
        r"\\server\share\home",
    ] {
        assert!(
            native_absolute_on(true, windows_absolute),
            "{windows_absolute}"
        );
        assert!(
            !native_absolute_on(false, windows_absolute),
            "{windows_absolute}"
        );
    }
    for relative in ["C:relative", "relative", r"\rooted-no-drive", ""] {
        assert!(!native_absolute_on(true, relative), "{relative}");
    }
    assert!(native_absolute_on(false, "/home/me"));
}

#[test]
fn windows_paths_print_as_python_prints_them() {
    use crate::bounded_hook_bridge_grok_script::python_path_on;

    assert_eq!(
        python_path_on(true, "C:/Users//me/./.hol-guard/").as_deref(),
        Some(r"C:\Users\me\.hol-guard")
    );
    assert_eq!(python_path_on(true, r"d:\").as_deref(), Some(r"d:\"));
    assert_eq!(python_path_on(true, r"\\server\share"), None);
    assert_eq!(python_path_on(true, "relative"), None);
    assert_eq!(python_path_on(false, "C:/Users"), None);
}

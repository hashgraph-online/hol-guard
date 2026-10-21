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

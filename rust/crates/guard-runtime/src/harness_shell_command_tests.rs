use serde_json::{json, Value};

use super::*;

fn render(command: &[&str], windows: Value) -> String {
    let request = json!({ "op": "shell_command", "command": command, "windows": windows });
    let answer = answer(request.as_object().unwrap()).expect("shell command");
    answer["shell_command"].as_str().expect("text").to_owned()
}

#[test]
fn a_posix_line_quotes_what_the_shell_would_read_specially() {
    let command = [
        "plain-arg_1.0/path:x=y,z+@%",
        "path with spaces",
        "single'quote",
        "$HOME",
        "`touch marker`",
        "backslash\\tail",
        "Unicode-\u{96ea}-\u{e9}",
        "",
    ];
    assert_eq!(
        render(&command, json!(false)),
        "plain-arg_1.0/path:x=y,z+@% 'path with spaces' 'single'\"'\"'quote' '$HOME' \
         '`touch marker`' 'backslash\\tail' 'Unicode-\u{96ea}-\u{e9}' ''"
    );
}

#[test]
fn a_windows_line_follows_the_list2cmdline_rules() {
    let command = [
        r"C:\Program Files\HOL Guard\python.exe",
        "print(\"quoted\")",
        r"backslash\\tail",
        "trailing-backslash\\",
        "trailing space\\",
        "quote\\\"after",
        "tab\there",
        "",
        "plain",
    ];
    assert_eq!(
        render(&command, json!(true)),
        concat!(
            "\"C:\\Program Files\\HOL Guard\\python.exe\" print(\\\"quoted\\\") ",
            "backslash\\\\tail trailing-backslash\\ \"trailing space\\\\\" quote\\\\\\\"after ",
            "\"tab\there\" \"\" plain"
        )
    );
}

#[test]
fn a_null_platform_follows_the_platform_the_runtime_runs_on() {
    let expected = render(&["a b"], json!(cfg!(windows)));
    assert_eq!(render(&["a b"], Value::Null), expected);
}

#[test]
fn a_malformed_shell_command_request_is_refused() {
    for request in [
        json!({ "op": "shell_command", "command": "ls", "windows": false }),
        json!({ "op": "shell_command", "command": [1], "windows": false }),
        json!({ "op": "shell_command", "command": [], "windows": "no" }),
        json!({ "op": "shell_command", "command": [] }),
        json!({ "op": "shell_command", "command": [], "windows": false, "extra": 1 }),
    ] {
        assert_eq!(
            answer(request.as_object().unwrap()),
            Err(ERR_INVALID),
            "{request}"
        );
    }
}

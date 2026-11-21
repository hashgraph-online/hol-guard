//! Parity for the archive-binding launch test that moved off the CLI.

use crate::package_shim_invocation::command_invokes_executable;
use crate::shell_helpers::evaluate;
use serde_json::json;

#[test]
fn a_command_that_can_reach_a_second_program_is_not_a_bare_invocation() {
    for command in [
        "`id`",
        "$(id)",
        "cat file\nwhoami",
        "cat file\rwhoami",
        "'unbalanced",
        "cat ;",
        "cat file > out",
        "cat file | tee copy",
        "cat file && whoami",
        "cat file & ",
        "cat $(id)",
    ] {
        assert!(!command_invokes_executable(command, "cat"), "{command}");
    }
}

#[test]
fn another_executable_is_not_the_one_that_was_asked_about() {
    assert!(!command_invokes_executable("ls -la", "cat"));
    assert!(!command_invokes_executable("", "cat"));
    assert!(!command_invokes_executable("   ", "cat"));
    // A match on a later word is not a match on the launch.
    assert!(!command_invokes_executable("env cat archive.tar", "cat"));
}

#[test]
fn a_plain_launch_of_the_named_executable_is_one() {
    assert!(command_invokes_executable("cat ./archive.tar", "cat"));
    assert!(command_invokes_executable("unzip -l bundle.zip", "unzip"));
    // The shim is named by path, which is how the caller reaches this rule.
    assert!(command_invokes_executable(
        "/home/user/.guard/shims/npm install left-pad",
        "/home/user/.guard/shims/npm"
    ));
    // Quoting is the lexer's business, not an operator.
    assert!(command_invokes_executable("cat 'my archive.tar'", "cat"));
}

#[test]
fn the_helper_action_answers_a_boolean_and_refuses_an_unknown_field() {
    assert_eq!(
        evaluate(
            "invokes_executable",
            &json!({"command": "cat ./archive.tar", "executable": "cat"})
        ),
        Ok(json!(true))
    );
    assert_eq!(
        evaluate(
            "invokes_executable",
            &json!({"command": "cat file | tee copy", "executable": "cat"})
        ),
        Ok(json!(false))
    );
    assert_eq!(
        evaluate("invokes_executable", &json!({"command": "cat archive.tar"})),
        Err("shell_helpers_invalid")
    );
    assert_eq!(
        evaluate(
            "invokes_executable",
            &json!({"command": "cat archive.tar", "executable": "cat", "cwd": "/tmp"})
        ),
        Err("shell_helpers_invalid")
    );
}

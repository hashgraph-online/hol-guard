use super::echoes_ssn;
// Regression coverage for printf escape decoding and shell-boundary handling.

#[test]
fn a_bare_print_of_an_ssn_is_reviewed() {
    for command in [
        "echo 123-45-6789",
        "echo 'Customer SSN is 123-45-6789.'",
        "echo 123-45-6789.",
        "echo 'SSN (123-45-6789)'",
        "echo \"SSN (123-45-6789)\"",
        "echo 000-12-3456 123-45-6789",
        "echo 123-45-67\"89\"",
        "echo 123-45-6789 # | ignored by the shell",
        "echo '123-45-6789' # a shell comment",
        "echo '# 123-45-6789'",
        "printf '%s\\n' 123-45-67\"89\"",
        "printf '%s\\n' 'case (123-45-6789)'",
        "echo \"SSN: 123-45-6789\"",
        "printf '%s\\n' 123-45-6789",
        "printf 'SSN:\\n123-45-6789\\n'",
        "echo 'customer 078-05-1120 on file'",
    ] {
        assert!(echoes_ssn(command), "{command} must be reviewed");
    }
}

#[test]
fn printf_escapes_are_decoded_before_ssn_boundary_check() {
    // Bash printf expands these format escapes. The literal echo command
    // does not expand them, so it must retain its existing benign verdict.
    for command in [
        r"printf 'SSN:\n123-45-6789\n'",
        r"printf '123\05545\0556789'",
        r"printf '123\x2d45\x2d6789'",
        r"printf '\a123-45-6789'",
        r"printf '\b123-45-6789'",
        r"printf '\f123-45-6789'",
        r"printf '\v123-45-6789'",
        r"printf '\e123-45-6789'",
    ] {
        assert!(echoes_ssn(command), "{command} prints an SSN and must be reviewed");
    }
    for command in [
        r"echo '123\05545\0556789'",
        r"echo '123\x2d45\x2d6789'",
        r"printf '123\05545\0550000'",
        r"printf '123\x2d45\x2d0000'",
        r"printf '\0123-45-6789'",
        r"echo '\a123-45-6789'",
    ] {
        assert!(!echoes_ssn(command), "{command} does not print an issuable SSN");
    }
}

#[test]
fn other_numbers_and_shapes_pass() {
    for command in [
        "echo 000-12-3456",
        "echo 666-12-3456",
        "echo 912-34-5678",
        "echo 123-00-4567",
        "echo 123-45-0000",
        "echo 555-123-4567",
        "echo 2024-11-17",
        "echo 1123-45-6789",
        "echo 123-45-67890",
        "echo '123-45-6789'0",
        "echo v123-45-6789",
        "echo build/123-45-6789",
        "echo 1.123-45-6789",
        "echo 123-45-6789 | ./redact",
        "echo \"$(printf 123-45-6789)\"",
        "echo 'SSN (000-12-3456)'",
        "echo 123-45-6789 > sample.txt",
        "echo $(cat id) 123-45-6789",
        "echo ok; echo 123-45-6789",
        "grep 123-45-6789 tests/fixtures.json",
        "cat notes-123-45-6789.txt",
        "echo hello",
    ] {
        assert!(!echoes_ssn(command), "{command} must pass");
    }
}

#[test]
fn an_enabled_permission_cannot_settle_a_printed_ssn() {
    let model = |command: &str| {
        crate::parse_command(
            &serde_json::from_value(serde_json::json!({"command": command})).unwrap(),
        )
        .unwrap()
    };
    assert!(crate::pretool::fixed_command_floor(&model(
        "echo 123-45-6789"
    )));
    assert!(!crate::pretool::fixed_command_floor(&model(
        "echo 555-123-4567"
    )));
}

#[test]
fn the_hook_reviews_a_printed_ssn_and_a_lone_home_dotpath_search() {
    let run = |command: &str| {
        crate::pretool::evaluate_pre_tool_envelope(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "cwd": "/tmp",
                "tool_input": {"command": command}
            }),
        )
    };
    for command in [
        "echo 123-45-6789",
        "grep ~/.secrets/key.txt",
        "rg ~/.secrets/key.txt",
    ] {
        assert_ne!(run(command).minimum_action, "allow", "{command}");
    }
    for command in [
        "echo 555-123-4567",
        "ps aux | grep ~/.ssh/id_rsa",
        "grep -c TODO README.md",
    ] {
        assert_eq!(run(command).minimum_action, "allow", "{command}");
    }
}

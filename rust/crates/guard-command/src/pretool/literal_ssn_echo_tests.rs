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
        r"printf '123\u002d45\u002d6789'",
        r"printf '123\U0000002d45\U0000002d6789'",
        r"printf '%b\n' '123\u002d45\u002d6789'",
        r"printf '%b\n' '123\U0000002d45\U0000002d6789'",
        r"printf '\a123-45-6789'",
        r"printf '\b123-45-6789'",
        r"printf '\f123-45-6789'",
        r"printf '\v123-45-6789'",
        r"printf '\e123-45-6789'",
        // %b expands escapes in its operand the way the format string does.
        r"printf '%b\n' '123\x2d45\x2d6789'",
        r"printf -- '123\05545\0556789'",
        r"printf -- '%b\n' '123\x2d45\x2d6789'",
    ] {
        assert!(
            echoes_ssn(command),
            "{command} prints an SSN and must be reviewed"
        );
    }
    for command in [
        r"echo '123\05545\0556789'",
        r"echo '123\x2d45\x2d6789'",
        // printf processes escapes in the format string, not in a normal
        // %s argument. Reviewing these would be a new false positive.
        r"printf '%s\n' '123\05545\0556789'",
        r"printf '%s\n' '123\x2d45\x2d6789'",
        r"printf '%s\n' '123\u002d45\u002d6789'",
        r"printf '%s\n' '123\U0000002d45\U0000002d6789'",
        r"printf -- '%s\n' '123\05545\0556789'",
        r"printf -- '123\05545\0550000'",
        r"printf '123\05545\0550000'",
        r"printf '123\x2d45\x2d0000'",
        r"printf '\0123-45-6789'",
        r"echo '\a123-45-6789'",
    ] {
        assert!(
            !echoes_ssn(command),
            "{command} does not print an issuable SSN"
        );
    }
}

#[test]
fn printf_substitutions_and_percent_b_octal_keep_the_ssn_review_floor() {
    for command in [
        r"printf '%s-%s-%s\n' 123 45 6789",
        r"printf -- '%s-%s-%s\n' 123 45 6789",
        r"printf 'SSN: %s\n' 123-45-6789",
        r"printf '%b\n' '123\005545\00556789'",
        r"printf -- '%b\n' '123\005545\00556789'",
        r"printf '%s\n' '123-45-6789\x30'",
    ] {
        assert!(
            echoes_ssn(command),
            "{command} prints an issuable SSN and must be reviewed"
        );
    }
    for command in [
        r"printf '%s\n' '123\x2d45\x2d6789'",
        r"printf '%s\n' '123\u002d45\u002d6789'",
        r"printf '%s\n' '123\U0000002d45\U0000002d6789'",
        r"printf '%s\n' '123\05545\0556789'",
        r"printf 'literal %%s\n' '123-45-6789'",
        r"printf '%b\n' '123\005545\00550000'",
    ] {
        assert!(
            !echoes_ssn(command),
            "{command} does not print an issuable SSN"
        );
    }
}

#[test]
fn printf_width_numeric_conversions_and_raw_escapes_preserve_the_floor() {
    for command in [
        r"printf '%03d-%02d-%04d' 123 45 6789",
        r"printf '%3s-%s-%s' 123 45 6789",
        r"printf '%u-%u-%u' 123 45 6789",
        r"printf '%s-%d-%s' 123 055 6789",
        r"printf '\045%s ' 123-45-6789",
        r"printf '\x25%s ' 123-45-6789",
    ] {
        assert!(echoes_ssn(command), "{command} prints an SSN");
    }
    for command in [
        r"printf '%8.5s\n' 123-45-6789",
        r"printf '%03d-%02d-%04d' 000 45 6789",
        r"printf 'literal %%s\n' 123-45-6789",
    ] {
        assert!(!echoes_ssn(command), "{command} does not print an SSN");
    }
}

#[test]
fn printf_dynamic_width_modifiers_and_radix_cannot_hide_an_ssn() {
    for command in [
        r"printf '%*d-45-6789' 5 123",
        r"printf '%.*d-45-6789' 3 123",
        r"printf '%ld-45-6789' 123",
        r"printf '%lld-45-6789' 123",
        r"printf '%x-45-6789' 291",
        r"printf '%X-45-6789' 291",
        r"printf '%o-45-6789' 83",
        r"printf '%x-45-6789' 0x123",
    ] {
        assert!(echoes_ssn(command), "{command} prints an SSN");
    }
    for command in [
        r"printf '%*d-45-6789' 5 000",
        r"printf '%#x-45-6789' 291",
        r"printf '%*d-45-6789' -5 123",
    ] {
        assert!(
            !echoes_ssn(command),
            "{command} does not print an isolated SSN"
        );
    }
}

#[test]
fn percent_b_stop_does_not_review_a_later_never_printed_ssn() {
    // Bash %b stops the whole printf at \c. These commands print only the
    // harmless prefix, even though a later operand resembles a synthetic SSN.
    for command in [
        r"printf '%b%s\n' 'build ok\c' '123-45-6789'",
        r"printf '%b/%s' 'safe\c' '123-45-6789'",
        r"printf -- '%b%s' 'ordinary\c' '123-45-6789'",
    ] {
        assert!(!echoes_ssn(command), "{command} stops before the SSN");
    }

    // An SSN printed before the stop remains protected. Escaping the
    // backslash means the c is literal and later operands are printed.
    for command in [
        r"printf '%b%s' '123-45-6789\c' 'unused'",
        r"printf '%b%s' 'safe\\c ' '123-45-6789'",
        r"printf 'literal\c %s\n' '123-45-6789'",
    ] {
        assert!(echoes_ssn(command), "{command} really prints an SSN");
    }
}

#[test]
fn percent_b_stop_keeps_bash_width_and_precision_semantics() {
    // The prefix from a stopped %b still gets padded to field width.
    // Without that space the synthetic SSN looks attached to x, and a
    // real emitted SSN could incorrectly escape Guard review.
    for command in [
        r"printf 'x%12b' '123-45-6789\c'",
        r"printf 'x%12b%s' '123-45-6789\c' unused",
    ] {
        assert!(echoes_ssn(command), "{command} prints a padded SSN");
    }
    // Precision truncates the stopped prefix: the full number never prints.
    for command in [
        r"printf '%.3b' '123-45-6789\c'",
        r"printf 'x%.3b' '123-45-6789\c'",
    ] {
        assert!(!echoes_ssn(command), "{command} prints no SSN");
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

#[test]
fn printf_render_budget_fails_closed_on_repeated_formats() {
    // The command remains below the input-size bound, but a repeated format
    // would otherwise allocate more than 64 KiB of reconstructed output.
    let literal = "x".repeat(16_000);
    let at_safe_size = format!("printf '{}%s' a b c", literal);
    assert!(
        !echoes_ssn(&at_safe_size),
        "bounded ordinary output below the budget is still allowed"
    );

    let beyond_budget = format!("printf '{}%s' a b c d e", literal);
    assert!(
        echoes_ssn(&beyond_budget),
        "an oversized reconstruction must review instead of allocating"
    );

    // A sensitive value before the output cap remains a non-allow.
    let early_ssn = format!("printf '123-45-6789 {}%s' a b c d e", literal);
    assert!(echoes_ssn(&early_ssn));
}

//! Regression for option-shaped Git pathspec operands.
//!
//! After `--`, a token like `--private-key=*.tsx` is a filename
//! pattern, not a long option. Treating the suffix alone as a filter
//! can discard the sensitive filename prefix before the fixed floor runs.

use super::fixed_command_floor;

fn model(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&serde_json::from_value(serde_json::json!({"command": command})).unwrap())
        .unwrap()
}

#[test]
fn option_shaped_pathspecs_after_delimiter_keep_secret_floor() {
    for command in [
        "git diff --name-only -- '--private-key=*.tsx'",
        "git log --name-only -- '--private-key=*.tsx'",
        "git diff -- '--include=*.tsx'",
        "git diff -m -- '--include=*.tsx'",
        "git diff-tree -m --name-only HEAD -- '--include=*.tsx'",
        "git diff-index -m --name-only HEAD -- '--include=*.tsx'",
        "git diff-files -m --name-only -- '--include=*.tsx'",
        "git whatchanged -m --name-only -1 -- '--include=*.tsx'",
        "git -C . diff -m -- '--include=*.tsx'",
        "git log -m -- '--include=*.tsx'",
        "git show -m -- '--include=*.tsx'",
        "git checkout -m -- '--include=*.tsx'",
        "git restore -m -- '--include=*.tsx'",
        "git diff -- '--api-key=*.ts'",
    ] {
        assert!(fixed_command_floor(&model(command)), "{command}");
    }
}

#[test]
fn actual_option_filters_still_have_their_original_distinction() {
    for command in [
        "grep -rn needle src --include=*.tsx -l",
        "rg needle src --glob=*.rs",
        "grep -e -- --include=*.tsx",
        "rg -e -- --glob=*.rs",
    ] {
        assert!(!fixed_command_floor(&model(command)), "{command}");
    }
    for command in [
        "grep -rn needle src --include=.env* -l",
        "rg needle src --glob=.env*",
    ] {
        assert!(fixed_command_floor(&model(command)), "{command}");
    }
}

#[test]
fn grep_and_rg_pattern_file_values_do_not_hide_a_delimiter() {
    // -f/--file consumes the next word. A following -e is then a filename,
    // not an option, and a subsequent -- really does start positional mode.
    for command in [
        "grep -f -e -- '--include=*.tsx'",
        "grep --file -e -- '--private-key=*.tsx'",
        "rg -f -e -- '--include=*.tsx'",
        "rg --file -e -- '--private-key=*.tsx'",
        "grep -f patterns -- '--api-key=*.ts'",
        "rg --file patterns -- '--private-key=*.tsx'",
    ] {
        assert!(fixed_command_floor(&model(command)), "{command}");
    }

    // When -e or -f takes -- as its value, the following token is still
    // a genuine option; its filter value alone must face the secret floor.
    for command in [
        "grep -e -- --include=*.tsx",
        "rg --regexp -- --glob=*.rs",
        "grep -f -- --include=*.tsx",
        "rg --file -- --glob=*.rs",
    ] {
        assert!(!fixed_command_floor(&model(command)), "{command}");
    }
}

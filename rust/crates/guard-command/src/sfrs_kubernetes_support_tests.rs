//! The credential-location carve-out for names-only `jsonpath` templates.

use super::sfrs_kubernetes_support::without_names_only_jsonpath_templates;

const NAMES_ONLY: &str = concat!(
    "kubectl -n alpha-namespace get deployment alpha-frontend -o ",
    r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'"#
);
const WITH_VALUES: &str = concat!(
    "kubectl -n alpha-namespace get deployment alpha-frontend -o ",
    r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"="}{.value}{"\n"}{end}'"#
);

#[test]
fn a_names_only_template_loses_the_selector_that_looks_like_a_dotenv_path() {
    let stripped = without_names_only_jsonpath_templates(NAMES_ONLY);
    assert!(!stripped.contains(".env"), "{stripped}");
    assert!(stripped.starts_with("kubectl -n alpha-namespace get deployment"));
    assert!(stripped.contains("jsonpath="), "{stripped}");
}

#[test]
fn a_template_that_renders_a_value_keeps_its_text() {
    assert_eq!(
        without_names_only_jsonpath_templates(WITH_VALUES),
        WITH_VALUES
    );
}

#[test]
fn an_unquoted_template_stops_at_the_blank_inside_its_loop() {
    // A `{range …}` loop always carries a blank, so an unquoted one is not a
    // single argument and keeps its text.
    let command = "kubectl get pods -o jsonpath={range .items[*]}{.metadata.name}{end} --watch";
    assert_eq!(without_names_only_jsonpath_templates(command), command);
}

#[test]
fn text_that_is_not_a_template_argument_is_left_alone() {
    for command in [
        "grep jsonpath ~/.env",
        "cat ~/.env && kubectl get pods -o 'jsonpath={range .items[*]}{.metadata.name}{end}'",
    ] {
        assert!(
            without_names_only_jsonpath_templates(command).contains("~/.env"),
            "{command}"
        );
    }
}

/// A second template in the same command is read at its own offset.
///
/// The offset of `jsonpath` was taken from the remainder still being walked
/// and then used to index the whole command, so from the second occurrence on
/// the screen read the wrong preceding character: a quoted template was split
/// at the blank inside its loop and kept its selector.
#[test]
fn a_second_names_only_template_in_the_same_command_loses_its_selector_too() {
    let command = concat!(
        "kubectl -n alpha-namespace get pods -o ",
        r#"'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}'"#,
        " && kubectl -n alpha-namespace get deployment alpha-frontend -o ",
        r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'"#
    );
    let stripped = without_names_only_jsonpath_templates(command);
    assert!(!stripped.contains(".env"), "{stripped}");
    assert!(!stripped.contains(".items"), "{stripped}");
    assert_eq!(stripped.matches("jsonpath=").count(), 2, "{stripped}");
}

/// Text before a template may be multibyte without panicking.
///
/// Indexing the whole command with an offset into the remainder could land
/// inside a multibyte character. This runs on the pre-tool path, so the panic
/// would break the decision for the command rather than fail it closed.
#[test]
fn multibyte_text_before_two_templates_does_not_panic() {
    let command = concat!(
        "echo 'é' && kubectl get pods -o ",
        r#"'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}'"#,
        " && kubectl get deployment alpha-frontend -o ",
        r#"'jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'"#
    );
    let stripped = without_names_only_jsonpath_templates(command);
    assert!(!stripped.contains(".env"), "{stripped}");
}

/// The shell may quote the value instead of the whole argument.
///
/// `-o jsonpath='{range …}'` is as valid as `-o 'jsonpath={range …}'`. The
/// screen resolved only the outer spelling, so the inner one stopped at the
/// blank after `range` and kept the selector that looks like a dotenv path.
#[test]
fn a_template_quoted_after_the_equals_sign_loses_its_selector() {
    for command in [
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o jsonpath=",
            r#"'{range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}'"#
        ),
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o jsonpath=",
            r#""{range .spec.template.spec.containers[*].env[*]}{.name}{'\n'}{end}""#
        ),
    ] {
        let stripped = without_names_only_jsonpath_templates(command);
        assert!(!stripped.contains(".env"), "{stripped}");
        assert!(stripped.contains("jsonpath="), "{stripped}");
    }
}

/// A value-rendering template keeps its text however it is quoted.
#[test]
fn a_template_quoted_after_the_equals_sign_that_renders_a_value_is_left_alone() {
    let command = concat!(
        "kubectl -n alpha-namespace get deployment alpha-frontend -o jsonpath=",
        r#"'{range .spec.template.spec.containers[*].env[*]}{.name}{"="}{.value}{end}'"#
    );
    assert_eq!(without_names_only_jsonpath_templates(command), command);
}

/// The shell joins adjacent quoted strings into one word.
///
/// `jsonpath='{range …}{.name}{end}''{..value}'` is a single template that
/// prints every value. Reading only as far as the first closing quote found a
/// names-only template, dropped that half from the credential screen and left
/// `{..value}`, which names no credential location of its own, so the command
/// reached the kubectl read screen with nothing left to object to.
#[test]
fn a_template_built_from_adjacent_quoted_strings_keeps_its_screen() {
    for command in [
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o jsonpath=",
            r#"'{range .spec.template.spec.containers[*].env[*]}{.name}{end}''{..value}'"#
        ),
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o 'jsonpath=",
            r#"{range .spec.template.spec.containers[*].env[*]}{.name}{end}'"#,
            r#"'{..value}'"#
        ),
        concat!(
            "kubectl -n alpha-namespace get deployment alpha-frontend -o jsonpath=",
            r#"'{range .spec.template.spec.containers[*].env[*]}{.name}{end}'{..value}"#
        ),
    ] {
        let stripped = without_names_only_jsonpath_templates(command);
        assert!(stripped.contains(".env"), "{stripped}");
    }
}

/// Joining the pieces must not swallow what follows the argument.
#[test]
fn a_names_only_template_still_ends_at_the_blank_after_it() {
    let command = concat!(
        "kubectl -n alpha-namespace get deployment alpha-frontend -o jsonpath=",
        r#"'{range .spec.template.spec.containers[*].env[*]}{.name}{end}' --watch"#
    );
    let stripped = without_names_only_jsonpath_templates(command);
    assert!(!stripped.contains(".env"), "{stripped}");
    assert!(stripped.ends_with(" --watch"), "{stripped}");
}

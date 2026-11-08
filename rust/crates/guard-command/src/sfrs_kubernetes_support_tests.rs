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

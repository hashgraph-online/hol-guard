//! Screens for `kubectl get -o jsonpath` templates that render names alone.

use super::sfrs_kubernetes_commands::kubernetes_read_only_inventory_args;

fn inventory(arguments: &[&str]) -> bool {
    let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
    kubernetes_read_only_inventory_args("kubectl", &arguments)
}

#[test]
fn a_range_template_emitting_only_names_reads_an_inventory() {
    assert!(inventory(&[
        "-n",
        "alpha-namespace",
        "get",
        "deployment",
        "alpha-frontend",
        "-o",
        r#"jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"\n"}{end}"#,
    ]));
    assert!(inventory(&[
        "get",
        "pods",
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}{end}",
    ]));
}

#[test]
fn a_range_template_that_emits_a_value_is_refused() {
    assert!(!inventory(&[
        "get",
        "deployment",
        "alpha-frontend",
        "-o",
        r#"jsonpath={range .spec.template.spec.containers[*].env[*]}{.name}{"="}{.value}{"\n"}{end}"#,
    ]));
    assert!(!inventory(&[
        "get",
        "deployment",
        "alpha-frontend",
        "-o",
        "jsonpath={range .spec.template.spec.containers[*].env[*]}{.value}{end}",
    ]));
}

#[test]
fn a_loop_whose_separator_could_expand_is_refused() {
    assert!(!inventory(&[
        "get",
        "pods",
        "-o",
        r#"jsonpath={range .items[*]}{.name}{"$(id)"}{end}"#,
    ]));
    assert!(!inventory(&[
        "get",
        "pods",
        "-o",
        "jsonpath={range .items[*]}{.name} raw {end}",
    ]));
}

#[test]
fn a_loop_that_never_closes_or_emits_nothing_is_refused() {
    assert!(!inventory(&[
        "get",
        "pods",
        "-o",
        "jsonpath={range .items[*]}{.name}",
    ]));
    assert!(!inventory(&[
        "get",
        "pods",
        "-o",
        "jsonpath={range .items[*]}{end}"
    ]));
    assert!(!inventory(&[
        "get",
        "pods",
        "-o",
        "jsonpath={range .items[*] | sh}{.name}{end}",
    ]));
}

use super::usage_only;

fn words(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

#[test]
fn a_usage_page_for_a_builtin_command_is_admitted() {
    for line in [
        "--help",
        "-h",
        "help",
        "help install",
        "help repo add",
        "install --help",
        "upgrade --help",
        "uninstall -h",
        "repo add --help",
        "plugin install --help",
        "template --help",
        "version --help",
    ] {
        assert!(usage_only(&words(line)), "helm {line}");
    }
}

#[test]
fn a_plugin_an_operand_or_a_selected_cluster_stays_reviewed() {
    for line in [
        "diff --help",
        "secrets --help",
        "install",
        "install mychart ./chart",
        "install --help mychart",
        "install --kubeconfig /tmp/agent.yaml --help",
        "install -n team --help",
        "help install upgrade rollback",
        "--help install",
    ] {
        assert!(!usage_only(&words(line)), "helm {line}");
    }
}

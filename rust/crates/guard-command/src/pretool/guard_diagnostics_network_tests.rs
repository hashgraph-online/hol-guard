//! `network` shapes [`super::super::safe_hol_guard_arguments`] admits and refuses.

use super::super::safe_hol_guard_arguments;

fn arguments(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn network_reads_the_saved_rules_without_fetching_them() {
    for command in [
        "network",
        "network --json",
        "network status",
        "network status --json",
        "network --json status",
        "network check https://ads-api.x.com/12/accounts",
        "network check --json https://example.com/path?q=1",
        "network check example.com",
        "execute-bound-bash --help",
        "ack-bound-bash --help",
        "execute-contained-test --help",
    ] {
        assert!(safe_hol_guard_arguments(&arguments(command)), "{command}");
    }
    for command in [
        "network sync",
        "network sync --json",
        "network check",
        "network check --url https://example.com",
        "network check -x",
        "network check https://a.example https://b.example",
        "network check https://example.com --home /tmp",
        "network check https://example.com --guard-home /tmp",
        "network status --workspace /tmp",
        "network --home /tmp status",
        "network status --json --json",
        "network status extra",
        "execute-bound-bash --harness omp --request-file x --request-sha256 y --operation-id z",
        "ack-bound-bash --harness omp --operation-id z --tool-call-id t --exit-code 0",
    ] {
        assert!(!safe_hol_guard_arguments(&arguments(command)), "{command}");
    }
}

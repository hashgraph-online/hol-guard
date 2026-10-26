use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn evaluate(harness: &str, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        None,
        None,
    );
    (result.decision, result.minimum_action)
}

#[test]
fn doctl_metadata_and_list_get_reads_are_explicitly_benign() {
    for harness in ["omp", "zcode"] {
        for command in [
            "doctl version",
            "doctl --help",
            "doctl compute droplet delete --help",
            "doctl account get",
            "doctl apps list",
            "doctl kubernetes cluster list",
            "doctl registry get",
            "doctl registry repository list-tags web",
            "doctl registry repository list-manifests web --format Digest,UpdatedAt,Tags --no-header",
            "doctl compute droplet list --output json",
            "doctl -o json projects list",
        ] {
            let (decision, minimum_action) = evaluate(harness, command);
            assert_eq!(decision, "allow", "{harness}: {command}");
            assert_eq!(minimum_action, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn doctl_effects_secrets_and_unbound_launches_stay_reviewed() {
    for harness in ["omp", "zcode"] {
        for command in [
            "doctl compute droplet delete web --force",
            "doctl kubernetes cluster delete prod",
            "doctl registry garbage-collection start",
            "doctl auth token",
            "doctl auth init",
            "doctl registry login",
            "doctl registry docker-config",
            "doctl kubernetes cluster kubeconfig show prod",
            "doctl kubernetes cluster kubeconfig save prod",
            "doctl databases list",
            "doctl apps list --access-token dop_v1_example",
            "doctl -t dop_v1_example apps list",
            "doctl apps list --api-url https://example.invalid",
            "doctl apps list --trace",
            "doctl apps list --show",
            "DIGITALOCEAN_ACCESS_TOKEN=dop_v1_example doctl apps list",
            "./doctl apps list",
        ] {
            let (decision, _) = evaluate(harness, command);
            assert_ne!(decision, "allow", "{harness}: {command}");
        }
    }
}

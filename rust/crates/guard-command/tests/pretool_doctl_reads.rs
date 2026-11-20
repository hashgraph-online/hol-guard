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
            "doctl databases list --format ID,Name,Engine,Status,Region",
            "doctl databases list --format ID,Name,Engine,Status,Region --no-header 2>&1 | head -20",
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
            "doctl databases list --format ID,URI",
            "doctl databases list --format ID,Name --output json",
            "doctl databases user list --format Name,Password",
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

/// The same commands with the packaged command extensions compiled in and no
/// control of the user's own. `command.cloud.digitalocean.credential-exposure`
/// reviews the whole `databases` group, so a native read proof alone leaves a
/// cluster listing under review; only `doctl_reads::settle` lifts it.
fn decide_with_extensions(
    harness: &str,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        Some(controls),
        None,
        None,
        None,
    )
}

#[test]
fn a_cluster_listing_of_named_inventory_columns_runs_with_the_extensions_loaded() {
    let controls = crate::git_helper_fixture::github_controls("default");
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in [
            "doctl databases list --format ID,Name,Engine,Status,Region",
            "doctl databases list --format ID,Name,Engine,Status,Region --no-header 2>&1 | head -20",
            "doctl d ls --format=ID,Name,Region --no-header",
        ] {
            let result = decide_with_extensions(harness, command, &controls);
            assert_eq!(
                result.decision, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
            assert_eq!(
                result.reason_code, "native_exact_safe_doctl_cluster_listing",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn the_rest_of_the_database_group_stays_reviewed_with_the_extensions_loaded() {
    let controls = crate::git_helper_fixture::github_controls("default");
    for harness in ["omp", "zcode", "codex", "claude-code"] {
        for command in [
            "doctl databases list",
            "doctl databases list --format ID,URI",
            "doctl databases list --format ID,Name --output json",
            "doctl databases user list --format Name,Password",
            "doctl databases connection mydb",
            "doctl auth token",
            "doctl compute droplet delete web --force",
        ] {
            let result = decide_with_extensions(harness, command, &controls);
            assert_ne!(
                result.decision, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
    }
}

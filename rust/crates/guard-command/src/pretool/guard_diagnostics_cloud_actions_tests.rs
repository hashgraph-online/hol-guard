//! Cloud actions shapes [`super::super::safe_hol_guard_arguments`] admits and refuses.

use super::super::safe_hol_guard_arguments;

fn arguments(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn cloud_actions_admits_only_the_local_reads() {
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    for command in [
        "cloud-actions --help".to_owned(),
        "cloud-actions status --help".to_owned(),
        "cloud-actions ai-tools configure --help".to_owned(),
        "help cloud-actions".to_owned(),
        "cloud-actions status --offline".to_owned(),
        "cloud-actions status --offline --json".to_owned(),
        "cloud-actions status --json --offline".to_owned(),
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID} --dry-run"),
        format!("cloud-actions ai-tools configure cursor --dry-run --cloud-workspace {ID}"),
        format!(
            "cloud-actions ai-tools configure claude-code --cloud-workspace {ID} --dry-run --json"
        ),
    ] {
        assert!(safe_hol_guard_arguments(&arguments(&command)), "{command}");
    }

    for command in [
        // Asking Guard Cloud whether the saved sign-in still works.
        "cloud-actions status".to_owned(),
        "cloud-actions status --json".to_owned(),
        format!("cloud-actions status --offline --cloud-workspace {ID}"),
        "cloud-actions status --offline --profile work".to_owned(),
        "cloud-actions status --offline --guard-home /tmp/g".to_owned(),
        "cloud-actions status --offline --json --json".to_owned(),
        // Changing saved sign-ins, settings or files.
        format!("cloud-actions login --cloud-workspace {ID}"),
        "cloud-actions logout".to_owned(),
        format!("cloud-actions workspace select {ID}"),
        "cloud-actions doctor".to_owned(),
        "cloud-actions doctor --bundle /tmp/b.json".to_owned(),
        "cloud-actions accounts".to_owned(),
        "cloud-actions ai-tools restore codex".to_owned(),
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID} --apply"),
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID} --dry-run --apply"),
        // A preview of someone else's settings or another address.
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID} --dry-run --home /tmp/evil"),
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID} --dry-run --guard-home /tmp/g"),
        format!(
            "cloud-actions ai-tools configure codex --cloud-workspace {ID} --dry-run --cloud-url https://example.test"
        ),
        // Shapes the parser would refuse or read differently.
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID}"),
        "cloud-actions ai-tools configure codex --cloud-workspace ws_1 --dry-run".to_owned(),
        "cloud-actions ai-tools configure codex --cloud-workspace ./project --dry-run".to_owned(),
        format!("cloud-actions ai-tools configure --apply --cloud-workspace {ID} --dry-run"),
        format!("cloud-actions ai-tools configure Codex --cloud-workspace {ID} --dry-run"),
        format!("cloud-actions ai-tools configure codex --cloud-workspace {ID} --dry-run extra"),
    ] {
        assert!(!safe_hol_guard_arguments(&arguments(&command)), "{command}");
    }
}

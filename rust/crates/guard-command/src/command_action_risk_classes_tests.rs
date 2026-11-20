//! The action-class risk table against the extensions that publish the labels.
//!
//! These pins came over from the Python extension tests when the table itself
//! was retired from Python. Each one names an extension's action class and the
//! risk classes a match on it carries, so a label renamed in
//! `contributions/command-sources/` cannot silently lose its risks.

use super::command_action_risk_classes::risk_classes_for_command_action;
use serde_json::Value;
use std::collections::BTreeSet;

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("class list is an array")
        .iter()
        .map(|class| class.as_str().expect("class is a string").to_owned())
        .collect()
}

#[test]
fn the_shell_and_github_actions_carry_their_risk_classes() {
    assert_eq!(
        risk_classes_for_command_action("destructive shell command"),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("GitHub PR body shell substitution"),
        &["execution"]
    );
    assert_eq!(
        risk_classes_for_command_action("GitHub remote mutation command"),
        &["destructive_shell", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Unverified GitHub command capability"),
        &["destructive_shell", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("GitHub local configuration write"),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("Guard approval self-authorization command"),
        &["policy_bypass"]
    );
    // The shell secret-read label the dispatcher produces for a script that
    // reads a credential file. The artifact a discovery build makes for it
    // carries no evaluated risk classes of its own, so this table entry is the
    // only thing that puts `local_secret_read` on the resident's answer.
    assert_eq!(
        risk_classes_for_command_action("local secret read shell command"),
        &["local_secret_read"]
    );
    // Order matters: the resident reports these in table order, and the
    // artifact a discovery build makes for this label publishes none of them.
    assert_eq!(
        risk_classes_for_command_action("credential exfiltration shell command"),
        &[
            "data_flow_exfiltration",
            "credential_exfiltration",
            "network_egress"
        ]
    );
}

#[test]
fn the_remote_execution_actions_carry_their_risk_classes() {
    assert_eq!(
        risk_classes_for_command_action("SSH configured execution command"),
        &["execution", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Rsync remote shell command"),
        &["execution", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("essh group execution command"),
        &["execution", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("essh cache removal command"),
        &["destructive_shell"]
    );
}

#[test]
fn the_third_party_tool_actions_carry_their_risk_classes() {
    assert_eq!(
        risk_classes_for_command_action("Noodle request execution command"),
        &["execution", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Probe request execution command"),
        &["execution", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Probe workspace mutation command"),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("Probe destructive command"),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("Ollama model publication command"),
        &["network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Ollama model removal command"),
        &["destructive_shell"]
    );
    assert_eq!(
        risk_classes_for_command_action("Blitcp remote destination command"),
        &["network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Blitcp privilege escalation command"),
        &["execution"]
    );
    assert_eq!(
        risk_classes_for_command_action("Blitcp self-update command"),
        &["execution", "network_egress"]
    );
    assert_eq!(
        risk_classes_for_command_action("Skill Sunset configuration audit command"),
        &["local_secret_read"]
    );
    assert_eq!(
        risk_classes_for_command_action("tui-runner forced reconfiguration command"),
        &["destructive_shell"]
    );
}

/// The table may stay narrower than the extension that owns a label, but it
/// must never add a risk the extension does not publish: the extension's own
/// `risk_classes` are what a reader sees when deciding whether to enable it.
#[test]
fn no_action_class_carries_a_risk_its_extension_does_not_publish() {
    let catalog: Value =
        serde_json::from_slice(guard_command_catalog_data::CATALOG_JSON).expect("catalog JSON");
    let extensions = catalog["catalog"].as_array().expect("catalog array");
    assert!(!extensions.is_empty());
    let mut checked = 0usize;
    for extension in extensions {
        let published = strings(&extension["risk_classes"]);
        for action_class in extension["action_classes"]
            .as_array()
            .expect("action_classes array")
        {
            let label = action_class.as_str().expect("action class is a string");
            checked += 1;
            for risk in risk_classes_for_command_action(label) {
                assert!(
                    published.contains(*risk),
                    "{} carries {risk}, which {} does not publish",
                    label,
                    extension["extension_id"]
                );
            }
        }
    }
    assert!(checked > 0);
}
/// The labels pinned above that a packaged core extension publishes, with the
/// extension that owns each one. A label Guard's own dispatcher produces, and
/// a label an opt-in pack publishes, are left out: neither reaches
/// `CATALOG_JSON`, which carries only `contracts/extensions/core-defaults.v1.json`.
const PUBLISHED_ACTION_CLASS_PINS: &[(&str, &str)] = &[
    ("command.shell-mutations", "destructive shell command"),
    (
        "command.shell-mutations",
        "GitHub PR body shell substitution",
    ),
    (
        "command.data-protection",
        "credential exfiltration shell command",
    ),
    (
        "command.guard-self-protection",
        "Guard approval self-authorization command",
    ),
    ("command.github", "GitHub remote mutation command"),
    ("command.github", "Unverified GitHub command capability"),
    ("command.github", "GitHub local configuration write"),
    ("command.remote.ssh", "SSH configured execution command"),
    ("command.remote.rsync", "Rsync remote shell command"),
];

/// Renaming a label in `contributions/command-sources/` without renaming it
/// here leaves the table answering for a label nothing produces any more,
/// while the pins above keep passing against the stale entry. Require each
/// pinned label to still appear under the extension that publishes it.
#[test]
fn every_pinned_action_class_is_published_by_its_extension() {
    let catalog: Value =
        serde_json::from_slice(guard_command_catalog_data::CATALOG_JSON).expect("catalog JSON");
    let extensions = catalog["catalog"].as_array().expect("catalog array");
    for (extension_id, label) in PUBLISHED_ACTION_CLASS_PINS {
        let extension = extensions
            .iter()
            .find(|entry| entry["extension_id"].as_str() == Some(*extension_id))
            .unwrap_or_else(|| panic!("{extension_id} is missing from the catalog"));
        let published: BTreeSet<String> = strings(&extension["action_classes"])
            .iter()
            .map(|class| class.trim().to_lowercase())
            .collect();
        assert!(
            published.contains(&label.trim().to_lowercase()),
            "{extension_id} no longer publishes {label}"
        );
        assert!(
            !risk_classes_for_command_action(label).is_empty(),
            "{label} carries no risk classes"
        );
    }
}

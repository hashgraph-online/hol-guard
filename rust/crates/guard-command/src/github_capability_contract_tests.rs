//! Parity tests for `github_capability_contract` against the Python oracle
//! `_CONTRACTS` / `_CAPABILITY_FLOOR` dump.

use crate::effect_decision::GuardAction;
use crate::github_capability_contract::{github_capability_contract, GitHubCommandCapability};

fn cap(s: &str) -> GitHubCommandCapability {
    GitHubCommandCapability::ALL
        .into_iter()
        .find(|c| c.as_str() == s)
        .unwrap()
}

#[test]
#[allow(clippy::type_complexity)]
fn contract_table_matches_python_oracle() {
    // [capability, permission_id, action_floor, workflow_authorizable,
    //  action_class, rule_id, risk_classes, risk_tier] — dumped from
    //  github_capability_contract._CONTRACTS.
    let oracle: Vec<(
        &str,
        &str,
        &str,
        bool,
        Option<&str>,
        Option<&str>,
        Vec<&str>,
        &str,
    )> = vec![
        (
            "read_local",
            "command.github.permission.read-local",
            "allow",
            false,
            None,
            None,
            vec![],
            "low",
        ),
        (
            "read_remote",
            "command.github.permission.read-remote",
            "allow",
            false,
            None,
            None,
            vec![],
            "low",
        ),
        (
            "propose_remote",
            "command.github.permission.propose-remote",
            "allow",
            false,
            None,
            None,
            vec![],
            "low",
        ),
        (
            "routine_merge_remote",
            "command.github.permission.routine-merge-remote",
            "allow",
            false,
            Some("GitHub routine pull-request merge command"),
            Some("command.github.routine-merge"),
            vec!["destructive_shell", "network_egress"],
            "low",
        ),
        (
            "routine_review_thread_remote",
            "command.github.permission.routine-review-thread-remote",
            "allow",
            false,
            None,
            None,
            vec![],
            "low",
        ),
        (
            "routine_workflow_remote",
            "command.github.permission.routine-workflow-remote",
            "require-reapproval",
            false,
            Some("GitHub workflow rerun"),
            Some("command.github.workflow-mutation"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "write_local",
            "command.github.permission.write-local",
            "review",
            false,
            Some("GitHub local configuration write"),
            Some("command.github.local-write"),
            vec!["destructive_shell"],
            "high",
        ),
        (
            "maintain_remote",
            "command.github.permission.maintain-remote",
            "review",
            true,
            Some("GitHub bounded maintenance command"),
            Some("command.github.maintenance"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "content_remote",
            "command.github.permission.content-remote",
            "review",
            false,
            Some("GitHub content mutation command"),
            Some("command.github.content"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "merge_remote",
            "command.github.permission.merge-remote",
            "require-reapproval",
            false,
            Some("GitHub merge command"),
            Some("command.github.merge"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "admin_merge_remote",
            "command.github.permission.merge-admin",
            "require-reapproval",
            false,
            Some("GitHub administrator pull-request merge command"),
            Some("command.github.admin-merge"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "publish_remote",
            "command.github.permission.publish-remote",
            "require-reapproval",
            false,
            Some("GitHub release publication command"),
            Some("command.github.publish"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "workflow_remote",
            "command.github.permission.workflow-remote",
            "require-reapproval",
            false,
            Some("GitHub workflow mutation command"),
            Some("command.github.workflow"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "force_remote",
            "command.github.permission.force-remote",
            "block",
            false,
            Some("GitHub force mutation command"),
            Some("command.github.force"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "delete_remote",
            "command.github.permission.delete-remote",
            "require-reapproval",
            false,
            Some("GitHub delete command"),
            Some("command.github.delete"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "secret_remote",
            "command.github.permission.secret-remote",
            "block",
            false,
            Some("GitHub secret mutation command"),
            Some("command.github.secret"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "access_remote",
            "command.github.permission.access-remote",
            "require-reapproval",
            false,
            Some("GitHub access mutation command"),
            Some("command.github.access"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "mutate_remote",
            "command.github.permission.mutate-remote",
            "require-reapproval",
            false,
            Some("GitHub remote mutation command"),
            Some("command.github.mutation"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
        (
            "unknown",
            "command.github.permission.unknown",
            "require-reapproval",
            false,
            Some("Unverified GitHub command capability"),
            Some("command.github.unknown"),
            vec!["destructive_shell", "network_egress"],
            "high",
        ),
    ];
    assert_eq!(oracle.len(), GitHubCommandCapability::ALL.len());
    for (name, pid, floor, wa, ac, rid, risks, tier) in oracle {
        let c = github_capability_contract(cap(name));
        assert_eq!(c.permission_id, pid, "{name} permission_id");
        assert_eq!(c.action_floor.as_str(), floor, "{name} floor");
        assert_eq!(c.workflow_authorizable, wa, "{name} workflow_authorizable");
        assert_eq!(c.action_class, ac, "{name} action_class");
        assert_eq!(c.rule_id.as_deref(), rid, "{name} rule_id");
        assert_eq!(c.risk_classes, risks.as_slice(), "{name} risk_classes");
        assert_eq!(c.risk_tier, tier, "{name} risk_tier");
    }
}

#[test]
fn assessment_action_floor_is_max() {
    // Block (secret_remote) dominates require-reapproval -> floor block.
    let a = crate::github_capability_contract::github_assessment(
        &[
            GitHubCommandCapability::SecretRemote,
            GitHubCommandCapability::ReadRemote,
        ],
        "r",
        "d",
    );
    assert_eq!(a.action_floor(), GuardAction::Block);
    assert_eq!(a.capability, GitHubCommandCapability::SecretRemote);
    assert!(!a.workflow_authorizable());
}

#[test]
fn github_assessment_canonicalizes_and_picks_strongest() {
    let a = crate::github_capability_contract::github_assessment(
        &[
            GitHubCommandCapability::Unknown,
            GitHubCommandCapability::ReadRemote,
            GitHubCommandCapability::Unknown,
        ],
        "r",
        "d",
    );
    // canonical dedup+sort by rank: read_remote(1) < unknown(18)
    assert_eq!(
        a.capabilities,
        vec![
            GitHubCommandCapability::ReadRemote,
            GitHubCommandCapability::Unknown
        ]
    );
    assert_eq!(a.capability, GitHubCommandCapability::Unknown);
}

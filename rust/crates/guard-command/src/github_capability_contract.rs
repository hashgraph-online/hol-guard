//! Rust port of `runtime/github_capability_contract.py`.

use crate::effect_decision::GuardAction;

/// `GitHubCommandCapability` literal domain (:15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitHubCommandCapability {
    ReadLocal,
    ReadRemote,
    ProposeRemote,
    RoutineMergeRemote,
    RoutineReviewThreadRemote,
    RoutineWorkflowRemote,
    WriteLocal,
    MaintainRemote,
    ContentRemote,
    MergeRemote,
    AdminMergeRemote,
    PublishRemote,
    WorkflowRemote,
    ForceRemote,
    DeleteRemote,
    SecretRemote,
    AccessRemote,
    MutateRemote,
    Unknown,
}

impl GitHubCommandCapability {
    pub const ALL: [Self; 19] = [
        Self::ReadLocal,
        Self::ReadRemote,
        Self::ProposeRemote,
        Self::RoutineMergeRemote,
        Self::RoutineReviewThreadRemote,
        Self::RoutineWorkflowRemote,
        Self::WriteLocal,
        Self::MaintainRemote,
        Self::ContentRemote,
        Self::MergeRemote,
        Self::AdminMergeRemote,
        Self::PublishRemote,
        Self::WorkflowRemote,
        Self::ForceRemote,
        Self::DeleteRemote,
        Self::SecretRemote,
        Self::AccessRemote,
        Self::MutateRemote,
        Self::Unknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadLocal => "read_local",
            Self::ReadRemote => "read_remote",
            Self::ProposeRemote => "propose_remote",
            Self::RoutineMergeRemote => "routine_merge_remote",
            Self::RoutineReviewThreadRemote => "routine_review_thread_remote",
            Self::RoutineWorkflowRemote => "routine_workflow_remote",
            Self::WriteLocal => "write_local",
            Self::MaintainRemote => "maintain_remote",
            Self::ContentRemote => "content_remote",
            Self::MergeRemote => "merge_remote",
            Self::AdminMergeRemote => "admin_merge_remote",
            Self::PublishRemote => "publish_remote",
            Self::WorkflowRemote => "workflow_remote",
            Self::ForceRemote => "force_remote",
            Self::DeleteRemote => "delete_remote",
            Self::SecretRemote => "secret_remote",
            Self::AccessRemote => "access_remote",
            Self::MutateRemote => "mutate_remote",
            Self::Unknown => "unknown",
        }
    }

    /// `_CAPABILITY_RANK` — index in `_CAPABILITY_ORDER`.
    const fn rank(self) -> u8 {
        match self {
            Self::ReadLocal => 0,
            Self::ReadRemote => 1,
            Self::ProposeRemote => 2,
            Self::RoutineMergeRemote => 3,
            Self::RoutineReviewThreadRemote => 4,
            Self::RoutineWorkflowRemote => 5,
            Self::WriteLocal => 6,
            Self::MaintainRemote => 7,
            Self::ContentRemote => 8,
            Self::MergeRemote => 9,
            Self::AdminMergeRemote => 10,
            Self::PublishRemote => 11,
            Self::WorkflowRemote => 12,
            Self::ForceRemote => 13,
            Self::DeleteRemote => 14,
            Self::SecretRemote => 15,
            Self::AccessRemote => 16,
            Self::MutateRemote => 17,
            Self::Unknown => 18,
        }
    }
}

/// `GitHubCapabilityContract` (:42). `title`/`description`/`safer_alternatives`/
/// `example_command`/`family`/`risk_tier`/`risk_classes` are permission-catalog
/// metadata (off the evaluate_command path); the contract carries the fields
/// consumed by classification/floor logic.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct GitHubCapabilityContract {
    pub capability: GitHubCommandCapability,
    pub permission_id: &'static str,
    pub action_floor: GuardAction,
    pub workflow_authorizable: bool,
    pub action_class: Option<&'static str>,
    pub rule_id: Option<&'static str>,
    pub local: bool,
    pub family: Option<&'static str>,
}

const REMOTE_MUTATION_RISKS: &[&str] = &["destructive_shell", "network_egress"];
const LOCAL_WRITE_RISKS: &[&str] = &["destructive_shell"];

/// `_CAPABILITY_FLOOR` (:80).
const fn capability_floor(capability: GitHubCommandCapability) -> GuardAction {
    match capability {
        GitHubCommandCapability::ReadLocal
        | GitHubCommandCapability::ReadRemote
        | GitHubCommandCapability::ProposeRemote
        | GitHubCommandCapability::RoutineMergeRemote
        | GitHubCommandCapability::RoutineReviewThreadRemote => GuardAction::Allow,
        GitHubCommandCapability::RoutineWorkflowRemote => GuardAction::RequireReapproval,
        GitHubCommandCapability::WriteLocal
        | GitHubCommandCapability::MaintainRemote
        | GitHubCommandCapability::ContentRemote => GuardAction::Review,
        GitHubCommandCapability::MergeRemote
        | GitHubCommandCapability::AdminMergeRemote
        | GitHubCommandCapability::PublishRemote
        | GitHubCommandCapability::WorkflowRemote
        | GitHubCommandCapability::DeleteRemote
        | GitHubCommandCapability::AccessRemote
        | GitHubCommandCapability::MutateRemote
        | GitHubCommandCapability::Unknown => GuardAction::RequireReapproval,
        GitHubCommandCapability::ForceRemote | GitHubCommandCapability::SecretRemote => {
            GuardAction::Block
        }
    }
}

/// `_contract` (:105) — builds one contract entry. `prompt_free`/`local` select
/// description/risk metadata which we elide (off the evaluate path) but keep
/// the field selections that drive floors/permissions.
#[allow(clippy::too_many_arguments)]
const fn contract(
    capability: GitHubCommandCapability,
    permission_suffix: &'static str,
    action_class: Option<&'static str>,
    rule_suffix: Option<&'static str>,
    _title: &'static str,
    local: bool,
    _example_command: &'static str,
    family: Option<&'static str>,
) -> GitHubCapabilityContract {
    GitHubCapabilityContract {
        capability,
        permission_id: permission_suffix, // prefixed at lookup
        action_floor: capability_floor(capability),
        workflow_authorizable: matches!(capability, GitHubCommandCapability::MaintainRemote),
        action_class,
        rule_id: rule_suffix,
        local,
        family,
    }
}

// `_CONTRACTS` (:158). `permission_id`/`rule_id` are stored as suffixes here and
// expanded with the `command.github.permission.` / `command.github.` prefixes at
// the accessor to keep the table const. Values verified against the Python
// oracle `_CONTRACTS` dump.
use GitHubCommandCapability as C;
static CONTRACTS: &[GitHubCapabilityContract] = &[
    contract(
        C::ReadLocal,
        "read-local",
        None,
        None,
        "local GitHub state",
        false,
        "gh auth status",
        None,
    ),
    contract(
        C::ReadRemote,
        "read-remote",
        None,
        None,
        "remote GitHub state",
        false,
        "gh pr view 123",
        None,
    ),
    contract(
        C::ProposeRemote,
        "propose-remote",
        None,
        None,
        "pull-request proposal",
        false,
        "gh pr create --title \"Fix login\" --body \"Summary\"",
        None,
    ),
    contract(
        C::RoutineMergeRemote,
        "routine-merge-remote",
        Some("GitHub routine pull-request merge command"),
        Some("routine-merge"),
        "routine squash pull-request merge",
        false,
        "gh pr merge 123 --squash",
        Some("gh-pr-merge"),
    ),
    contract(
        C::RoutineReviewThreadRemote,
        "routine-review-thread-remote",
        None,
        None,
        "routine review-thread resolution",
        false,
        "gh api graphql -F query='mutation { resolveReviewThread...}'",
        None,
    ),
    contract(
        C::RoutineWorkflowRemote,
        "routine-workflow-remote",
        Some("GitHub workflow rerun"),
        Some("workflow-mutation"),
        "routine failed-run retry",
        false,
        "gh run rerun 123 --failed",
        None,
    ),
    contract(
        C::WriteLocal,
        "write-local",
        Some("GitHub local configuration write"),
        Some("local-write"),
        "local repository configuration",
        true,
        "gh auth login",
        None,
    ),
    contract(
        C::MaintainRemote,
        "maintain-remote",
        Some("GitHub bounded maintenance command"),
        Some("maintenance"),
        "remote maintenance",
        false,
        "gh pr ready 123",
        None,
    ),
    contract(
        C::ContentRemote,
        "content-remote",
        Some("GitHub content mutation command"),
        Some("content"),
        "remote content",
        false,
        "gh pr create --title \"Fix\" --body \"Body\"",
        None,
    ),
    contract(
        C::MergeRemote,
        "merge-remote",
        Some("GitHub merge command"),
        Some("merge"),
        "remote merge",
        false,
        "gh pr merge 123 --merge",
        Some("gh-pr-merge"),
    ),
    contract(
        C::AdminMergeRemote,
        "merge-admin",
        Some("GitHub administrator pull-request merge command"),
        Some("admin-merge"),
        "administrator merge",
        false,
        "gh pr merge 123 --admin",
        Some("gh-pr-merge"),
    ),
    contract(
        C::PublishRemote,
        "publish-remote",
        Some("GitHub release publication command"),
        Some("publish"),
        "remote release publication",
        false,
        "gh release create v1.2.3",
        None,
    ),
    contract(
        C::WorkflowRemote,
        "workflow-remote",
        Some("GitHub workflow mutation command"),
        Some("workflow"),
        "remote workflow control",
        false,
        "gh run rerun 123",
        None,
    ),
    contract(
        C::ForceRemote,
        "force-remote",
        Some("GitHub force mutation command"),
        Some("force"),
        "remote force operation",
        false,
        "gh pr merge 123 --force",
        None,
    ),
    contract(
        C::DeleteRemote,
        "delete-remote",
        Some("GitHub delete command"),
        Some("delete"),
        "remote deletion",
        false,
        "gh repo delete owner/repo",
        None,
    ),
    contract(
        C::SecretRemote,
        "secret-remote",
        Some("GitHub secret mutation command"),
        Some("secret"),
        "remote secret access",
        false,
        "gh secret list",
        None,
    ),
    contract(
        C::AccessRemote,
        "access-remote",
        Some("GitHub access mutation command"),
        Some("access"),
        "remote access grant",
        false,
        "gh ssh-key add key.pub",
        None,
    ),
    contract(
        C::MutateRemote,
        "mutate-remote",
        Some("GitHub remote mutation command"),
        Some("mutation"),
        "remote mutation",
        false,
        "gh issue close 123",
        None,
    ),
    contract(
        C::Unknown,
        "unknown",
        Some("Unverified GitHub command capability"),
        Some("unknown"),
        "unknown",
        false,
        "gh",
        None,
    ),
];

fn contract_entry(capability: GitHubCommandCapability) -> &'static GitHubCapabilityContract {
    // `_CONTRACTS` is keyed by capability; order matches `_CAPABILITY_ORDER`.
    &CONTRACTS[capability.rank() as usize]
}

/// `github_capability_contract` (:352) — the contract with `permission_id`/`rule_id`
/// expanded to their full `command.github.permission.`/`command.github.` form.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedGitHubCapabilityContract {
    pub capability: GitHubCommandCapability,
    pub permission_id: String,
    pub action_floor: GuardAction,
    pub workflow_authorizable: bool,
    pub action_class: Option<&'static str>,
    pub rule_id: Option<String>,
    pub risk_classes: &'static [&'static str],
    pub risk_tier: &'static str,
}

pub fn github_capability_contract(
    capability: GitHubCommandCapability,
) -> ResolvedGitHubCapabilityContract {
    let c = contract_entry(capability);
    let prompt_free = c.action_floor == GuardAction::Allow;
    let local = c.local;
    ResolvedGitHubCapabilityContract {
        capability: c.capability,
        permission_id: format!("command.github.permission.{}", c.permission_id),
        action_floor: c.action_floor,
        workflow_authorizable: c.workflow_authorizable,
        action_class: c.action_class,
        rule_id: c.rule_id.map(|s| format!("command.github.{s}")),
        risk_tier: if prompt_free { "low" } else { "high" },
        risk_classes: if c.rule_id.is_none() {
            &[]
        } else if local {
            LOCAL_WRITE_RISKS
        } else {
            REMOTE_MUTATION_RISKS
        },
    }
}

/// `GitHubCommandAssessment` (:316). `capabilities` is canonicalized to sorted
/// unique order; `capability` is the strongest.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GitHubCommandAssessment {
    pub capability: GitHubCommandCapability,
    pub reason_code: String,
    pub detail: String,
    pub capabilities: Vec<GitHubCommandCapability>,
}

impl GitHubCommandAssessment {
    /// `action_floor` property (:339): max contract floor by severity.
    pub fn action_floor(&self) -> GuardAction {
        self.capabilities
            .iter()
            .map(|c| github_capability_contract(*c).action_floor)
            .max_by_key(|a| a.severity())
            .unwrap_or(GuardAction::Allow)
    }

    /// `workflow_authorizable` property (:346).
    pub fn workflow_authorizable(&self) -> bool {
        !self.capabilities.is_empty()
            && self
                .capabilities
                .iter()
                .all(|c| github_capability_contract(*c).workflow_authorizable)
    }
}

/// `strongest_github_capability` (:360).
pub fn strongest_github_capability(
    capabilities: &[GitHubCommandCapability],
) -> GitHubCommandCapability {
    capabilities
        .iter()
        .copied()
        .max_by_key(|c| c.rank())
        .expect("at least one GitHub capability is required")
}

/// `github_assessment` (:366) — canonicalize, dedup-sort by rank, pick strongest.
pub fn github_assessment(
    capabilities: &[GitHubCommandCapability],
    reason_code: &str,
    detail: &str,
) -> GitHubCommandAssessment {
    let mut canonical: Vec<GitHubCommandCapability> = capabilities.to_vec();
    canonical.sort_by_key(|c| c.rank());
    canonical.dedup();
    let strongest = strongest_github_capability(&canonical);
    GitHubCommandAssessment {
        capability: strongest,
        reason_code: reason_code.to_owned(),
        detail: detail.to_owned(),
        capabilities: canonical,
    }
}

/// `github_cli_invocation_is_help` (:381).
pub fn github_cli_invocation_is_help(normalized: &[String]) -> bool {
    (matches!(
        normalized.first().map(String::as_str),
        Some("--help") | Some("-h")
    )) || normalized == ["auth", "switch", "--help"]
}

/// `combine_github_assessments` (:387).
#[allow(dead_code)]
pub fn combine_github_assessments(
    assessments: &[GitHubCommandAssessment],
) -> Option<GitHubCommandAssessment> {
    if assessments.is_empty() {
        return None;
    }
    let mut capabilities: Vec<GitHubCommandCapability> = assessments
        .iter()
        .flat_map(|a| a.capabilities.iter().copied())
        .collect();
    capabilities.sort_by_key(|c| c.rank());
    capabilities.dedup();
    let strongest = assessments
        .iter()
        .map(|a| a.capability)
        .max_by_key(|c| c.rank())
        .unwrap();
    Some(GitHubCommandAssessment {
        capability: strongest,
        reason_code: assessments
            .iter()
            .map(|a| a.reason_code.clone())
            .collect::<Vec<_>>()
            .join(";"),
        detail: assessments
            .iter()
            .map(|a| a.detail.clone())
            .collect::<Vec<_>>()
            .join(";"),
        capabilities,
    })
}

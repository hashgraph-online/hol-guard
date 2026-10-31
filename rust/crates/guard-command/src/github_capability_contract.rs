//! Rust port of `runtime/github_capability_contract.py`.

use crate::effect_decision::GuardAction;

/// `GitHubCommandCapability` literal domain (:15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitHubCommandCapability {
    ReadLocal,
    ReadRemote,
    ProposeRemote,
    CreatePrivateRemote,
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
    pub const ALL: [Self; 20] = [
        Self::ReadLocal,
        Self::ReadRemote,
        Self::ProposeRemote,
        Self::CreatePrivateRemote,
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
            Self::CreatePrivateRemote => "create_private_remote",
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
            Self::CreatePrivateRemote => 3,
            Self::RoutineMergeRemote => 4,
            Self::RoutineReviewThreadRemote => 5,
            Self::RoutineWorkflowRemote => 6,
            Self::WriteLocal => 7,
            Self::MaintainRemote => 8,
            Self::ContentRemote => 9,
            Self::MergeRemote => 10,
            Self::AdminMergeRemote => 11,
            Self::PublishRemote => 12,
            Self::WorkflowRemote => 13,
            Self::ForceRemote => 14,
            Self::DeleteRemote => 15,
            Self::SecretRemote => 16,
            Self::AccessRemote => 17,
            Self::MutateRemote => 18,
            Self::Unknown => 19,
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
        | GitHubCommandCapability::CreatePrivateRemote
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
        C::CreatePrivateRemote,
        "create-private-remote",
        None,
        None,
        "new private repository",
        false,
        "gh repo create todo-app --private --source=.",
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
///
/// A trailing `--help` prints the subcommand's help and runs nothing, so
/// `gh repo delete owner/name --help` is as local as `gh --help`. It is only
/// help when the token before it is a plain word: after a written option the
/// `--help` is that option's value, and `gh issue create --title --help` opens
/// an issue. `-h` carries no such reading past the first token, where the CLI
/// reads it as `--hostname`. It is also only help when gh is the one reading
/// the flag: see `trailing_help_prints_gh_help`.
pub fn github_cli_invocation_is_help(normalized: &[String]) -> bool {
    if matches!(
        normalized.first().map(String::as_str),
        Some("--help") | Some("-h")
    ) {
        return true;
    }
    match normalized.split_last() {
        Some((last, before)) if last == "--help" => {
            before.last().is_some_and(|token| !token.starts_with('-'))
                && trailing_help_prints_gh_help(before)
        }
        _ => false,
    }
}

/// The commands the GitHub CLI itself owns, each with the subcommands it owns.
///
/// gh registers aliases, installed extensions and `gh extension exec` with
/// flag parsing disabled, and forwards every argument — `--help` included — to
/// the alias's shell command or to the extension binary, which runs instead of
/// printing help. A name gh does not own is one of those, so the trailing
/// `--help` reading is only safe for the names listed here. A built-in missing
/// from the list reads as it did before the trailing-help reading existed.
///
/// An alias can also sit under a group: `gh alias set --shell "issue mine" …`
/// is accepted, and `gh issue mine --help` then runs the alias with `--help`
/// as its argument. gh refuses to register a name it already owns, so listing
/// a group's own subcommands is what keeps a nested alias out. A group whose
/// list is empty owns no subcommands, and gh refuses an alias beneath it too,
/// so a word there is an argument to the command itself. A few of these
/// subcommands are groups in their own right, and those are listed in
/// `GITHUB_BUILTIN_NESTED_GROUPS` so an alias cannot hide one level deeper.
const GITHUB_BUILTIN_COMMANDS: &[(&str, &[&str])] = &[
    ("accessibility", &[]),
    ("alias", &["delete", "import", "list", "set"]),
    ("api", &[]),
    ("attestation", &["download", "trusted-root", "verify"]),
    (
        "auth",
        &[
            "login",
            "logout",
            "refresh",
            "setup-git",
            "status",
            "switch",
            "token",
        ],
    ),
    ("browse", &[]),
    ("cache", &["delete", "list"]),
    (
        "codespace",
        &[
            "code", "cp", "create", "delete", "edit", "jupyter", "list", "logs", "ports",
            "rebuild", "ssh", "stop", "view",
        ],
    ),
    ("completion", &[]),
    ("config", &["clear-cache", "get", "list", "set"]),
    (
        "extension",
        &[
            "browse", "create", "exec", "install", "list", "remove", "search", "upgrade",
        ],
    ),
    (
        "gist",
        &[
            "clone", "create", "delete", "edit", "list", "rename", "view",
        ],
    ),
    ("gpg-key", &["add", "delete", "list"]),
    ("help", &[]),
    (
        "issue",
        &[
            "close", "comment", "create", "delete", "develop", "edit", "list", "lock", "pin",
            "reopen", "status", "transfer", "unlock", "unpin", "view",
        ],
    ),
    ("label", &["clone", "create", "delete", "edit", "list"]),
    ("org", &["list"]),
    (
        "pr",
        &[
            "checkout",
            "checks",
            "close",
            "comment",
            "create",
            "diff",
            "edit",
            "list",
            "lock",
            "merge",
            "ready",
            "reopen",
            "revert",
            "review",
            "status",
            "unlock",
            "update-branch",
            "view",
        ],
    ),
    (
        "project",
        &[
            "close",
            "copy",
            "create",
            "delete",
            "edit",
            "field-create",
            "field-delete",
            "field-list",
            "item-add",
            "item-archive",
            "item-create",
            "item-delete",
            "item-edit",
            "item-list",
            "link",
            "list",
            "mark-template",
            "unlink",
            "view",
        ],
    ),
    (
        "release",
        &[
            "create",
            "delete",
            "delete-asset",
            "download",
            "edit",
            "list",
            "upload",
            "verify",
            "verify-asset",
            "view",
        ],
    ),
    (
        "repo",
        &[
            "archive",
            "autolink",
            "clone",
            "create",
            "delete",
            "deploy-key",
            "edit",
            "fork",
            "gitignore",
            "license",
            "list",
            "read-dir",
            "read-file",
            "rename",
            "set-default",
            "sync",
            "unarchive",
            "view",
        ],
    ),
    ("ruleset", &["check", "list", "view"]),
    (
        "run",
        &[
            "cancel", "delete", "download", "list", "rerun", "view", "watch",
        ],
    ),
    ("search", &["code", "commits", "issues", "prs", "repos"]),
    ("secret", &["delete", "list", "set"]),
    ("ssh-key", &["add", "delete", "list"]),
    ("status", &[]),
    ("variable", &["delete", "get", "list", "set"]),
    ("version", &[]),
    ("workflow", &["disable", "enable", "list", "run", "view"]),
];

/// The built-in subcommands that own subcommands themselves.
///
/// gh registers an alias wherever its parent group is, so a name under one of
/// these is a name a user can take: `gh alias set --shell "repo deploy-key zap"`
/// is accepted and `gh repo deploy-key zap --help` then runs it. Reading the
/// trailing `--help` has to walk down to the group that really owns the last
/// name, not stop at the first one.
const GITHUB_BUILTIN_NESTED_GROUPS: &[(&str, &str, &[&str])] = &[
    ("codespace", "ports", &["forward", "visibility"]),
    ("repo", "autolink", &["create", "delete", "list", "view"]),
    ("repo", "deploy-key", &["add", "delete", "list"]),
    ("repo", "gitignore", &["list", "view"]),
    ("repo", "license", &["list", "view"]),
];

/// The options gh reads a value from wherever they are written. Cobra takes
/// these and their values out of the way before it matches a subcommand, so
/// they say nothing about where the subcommand ends up.
const GITHUB_OPTIONS_THAT_TAKE_A_VALUE: &[&str] = &["-R", "--repo", "--hostname"];

/// Whether a trailing `--help` is read by gh rather than by something gh runs.
fn trailing_help_prints_gh_help(before: &[String]) -> bool {
    // After `--`, gh stops parsing flags, so `gh release create v1 -- notes.md
    // --help` uploads a file named `--help` and publishes the release.
    if before.iter().any(|token| token == "--") {
        return false;
    }
    // Cobra matches a name byte for byte unless `EnableCaseInsensitive` is set,
    // and gh leaves it alone, so `ISSUE` is not the built-in `issue`: it is a
    // name gh looks up among the user's aliases, and an alias can run anything.
    // Reading its `--help` as gh's own would hand that alias a local reading.
    let Some(top) = before.first().map(String::as_str) else {
        return false;
    };
    let Some((_, subcommands)) = GITHUB_BUILTIN_COMMANDS
        .iter()
        .find(|(name, _)| *name == top)
    else {
        return false;
    };
    // `gh extension exec <name> …` forwards everything after the name to the
    // extension binary.
    if top == "extension" && before.get(1).is_some_and(|t| t == "exec") {
        return false;
    }
    // Cobra matches a subcommand against the words that are left once it has
    // taken the options out of the way, so a written option in front of a name
    // does not keep gh from expanding an alias there: `gh issue -R o/r mine`
    // still runs the `issue mine` alias. Walk the names the way gh does, and
    // read the trailing `--help` only when gh owns every one of them.
    let mut parent = top;
    let mut owned = subcommands;
    let mut index = 1;
    while index < before.len() {
        let token = &before[index];
        if token.starts_with('-') {
            // A value written onto the option carries its own, so the next word
            // is still a name. A bare option whose arity gh does not publish
            // here could take the next word or leave it, and the name an alias
            // would be registered under is exactly that word, so the reading is
            // given up rather than guessed.
            if token.contains('=') || (token.starts_with("-R") && token.as_str() != "-R") {
                index += 1;
                continue;
            }
            if GITHUB_OPTIONS_THAT_TAKE_A_VALUE.contains(&token.as_str()) {
                index += 2;
                continue;
            }
            return false;
        }
        if owned.is_empty() {
            // The command owns no names, so this word is an argument to it and
            // gh is still the one reading the flag.
            return true;
        }
        if !owned.contains(&token.as_str()) {
            return false;
        }
        let Some((_, group_name, deeper)) = GITHUB_BUILTIN_NESTED_GROUPS
            .iter()
            .find(|(group, sub, _)| *group == parent && *sub == token.as_str())
        else {
            // A command that owns no further names reads the rest as its own
            // arguments, `gh repo delete owner/name --help` included.
            return true;
        };
        parent = group_name;
        owned = deeper;
        index += 1;
    }
    true
}

/// `combine_github_assessments` (:387).
#[allow(dead_code)]
pub fn combine_github_assessments(
    assessments: &[GitHubCommandAssessment],
) -> Option<GitHubCommandAssessment> {
    match assessments {
        [] => None,
        [single] => Some(single.clone()),
        _ => {
            let capabilities: Vec<GitHubCommandCapability> = assessments
                .iter()
                .flat_map(|a| a.capabilities.iter().copied())
                .collect();
            Some(github_assessment(
                &capabilities,
                "github.shell.combined-capabilities",
                "The shell composition contains multiple GitHub capabilities.",
            ))
        }
    }
}

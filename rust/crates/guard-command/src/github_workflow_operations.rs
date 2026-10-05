//! Rust port of `runtime/github_workflow_operations.py` — the strict
//! operation record + `parse_github_workflow_operation` entrypoint.
//!
//! `GitHubWorkflowOperation` construction validates the digest against
//! `_operation_digest(...)`; tampered wire rows are rejected the same way
//! `__post_init__` rejects them in Python.

use guard_contracts::canonical_framed_payload;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use crate::github_capability_contract::GitHubCommandCapability;
use crate::github_command_capabilities::classify_github_cli;
use crate::CanonicalCommandV1;

/// `GitHubWorkflowOperationKind` — the ten authorization-eligible operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubWorkflowOperationKind {
    ResolveReviewThread,
    UnresolveReviewThread,
    LockIssue,
    UnlockIssue,
    PinIssue,
    UnpinIssue,
    LockPr,
    UnlockPr,
    MarkPrReady,
    MarkPrDraft,
}

impl GitHubWorkflowOperationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolveReviewThread => "resolve-review-thread",
            Self::UnresolveReviewThread => "unresolve-review-thread",
            Self::LockIssue => "lock-issue",
            Self::UnlockIssue => "unlock-issue",
            Self::PinIssue => "pin-issue",
            Self::UnpinIssue => "unpin-issue",
            Self::LockPr => "lock-pr",
            Self::UnlockPr => "unlock-pr",
            Self::MarkPrReady => "mark-pr-ready",
            Self::MarkPrDraft => "mark-pr-draft",
        }
    }

    /// Inverse of `as_str` for persisted `operation_kind` values.
    pub fn from_kind_str(value: &str) -> Option<Self> {
        Some(match value {
            "resolve-review-thread" => Self::ResolveReviewThread,
            "unresolve-review-thread" => Self::UnresolveReviewThread,
            "lock-issue" => Self::LockIssue,
            "unlock-issue" => Self::UnlockIssue,
            "pin-issue" => Self::PinIssue,
            "unpin-issue" => Self::UnpinIssue,
            "lock-pr" => Self::LockPr,
            "unlock-pr" => Self::UnlockPr,
            "mark-pr-ready" => Self::MarkPrReady,
            "mark-pr-draft" => Self::MarkPrDraft,
            _ => return None,
        })
    }
}

/// `GitHubWorkflowOperation` — the six binding fields plus the derived digest.
/// `resource_type`/`resource_id`/`repository`/`operation_digest` all satisfy
/// `__post_init__`'s invariants.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GitHubWorkflowOperation {
    pub kind: GitHubWorkflowOperationKind,
    pub resource_type: String,
    pub resource_id: String,
    pub repository: String,
    pub command_identity: String,
    pub operation_digest: String,
}

impl GitHubWorkflowOperation {
    /// `__post_init__` — resource-type match, `_RESOURCE_ID` match, normalized
    /// repository round-trip, and the `compare_digest` digest gate.
    pub fn try_new(
        kind: GitHubWorkflowOperationKind,
        resource_type: String,
        resource_id: String,
        repository: String,
        command_identity: String,
        operation_digest: String,
    ) -> Result<Self, &'static str> {
        if resource_type != resource_type_for(kind) {
            return Err("GitHub workflow operation resource type mismatch");
        }
        if !resource_id_re().is_match(&resource_id) {
            return Err("GitHub workflow operation resource is invalid");
        }
        if normalized_repository(&repository).as_deref() != Some(repository.as_str()) {
            return Err("GitHub workflow operation repository is invalid");
        }
        let expected = compute_operation_digest(
            &command_identity,
            kind,
            &repository,
            &resource_id,
            &resource_type,
        );
        if !hmac_compare_digest(&operation_digest, &expected) {
            return Err("GitHub workflow operation digest mismatch");
        }
        Ok(Self {
            kind,
            resource_type,
            resource_id,
            repository,
            command_identity,
            operation_digest,
        })
    }
}

/// `parse_github_workflow_operation` (:78) — exact single-segment commands only.
pub fn parse_github_workflow_operation(
    command: &CanonicalCommandV1,
    repository: Option<&str>,
    expected_executable: &str,
) -> Option<GitHubWorkflowOperation> {
    // `CanonicalCommandV1`/`CanonicalCommand` drop `redirects` and
    // `embedded_commands` (the wire omits them; `security_identity` covers
    // their span). A command that produced any redirect/embedded segment cannot
    // collapse to exactly one `exact` segment anyway, so the remaining gate is
    // `confidence=="exact" && segments.len()==1`.
    if command.confidence != "exact"
        || command.segments.len() != 1
        || !command.wrapper_chain.is_empty()
        || command.normalized_text.trim_end().ends_with('&')
    {
        return None;
    }
    let segment = &command.segments[0];
    let executable = segment.executable.as_deref().unwrap_or("");
    if executable != expected_executable
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
    {
        return None;
    }
    let normalized_repository = normalized_repository(repository?);
    let operation = graphql_operation(&segment.arguments, normalized_repository.as_deref())
        .or_else(|| cli_operation(&segment.arguments, normalized_repository.as_deref()))?;
    let (kind, resource_type, resource_id, repo) = operation;
    let assessment = classify_github_cli(&segment.arguments);
    if assessment.capabilities != [GitHubCommandCapability::MaintainRemote]
        || !assessment.workflow_authorizable()
    {
        return None;
    }
    let digest = compute_operation_digest(
        &command.security_identity,
        kind,
        &repo,
        &resource_id,
        &resource_type,
    );
    GitHubWorkflowOperation::try_new(
        kind,
        resource_type,
        resource_id,
        repo,
        command.security_identity.clone(),
        digest,
    )
    .ok()
}

// ─── internals (ports of module-private helpers) ─────────────────────────────

fn resource_type_for(kind: GitHubWorkflowOperationKind) -> &'static str {
    match kind {
        GitHubWorkflowOperationKind::ResolveReviewThread
        | GitHubWorkflowOperationKind::UnresolveReviewThread => "github-review-thread",
        GitHubWorkflowOperationKind::LockIssue
        | GitHubWorkflowOperationKind::UnlockIssue
        | GitHubWorkflowOperationKind::PinIssue
        | GitHubWorkflowOperationKind::UnpinIssue => "github-issue",
        GitHubWorkflowOperationKind::LockPr
        | GitHubWorkflowOperationKind::UnlockPr
        | GitHubWorkflowOperationKind::MarkPrReady
        | GitHubWorkflowOperationKind::MarkPrDraft => "github-pr",
    }
}

fn graphql_operations() -> &'static HashMap<&'static str, GitHubWorkflowOperationKind> {
    static MAP: OnceLock<HashMap<&'static str, GitHubWorkflowOperationKind>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            (
                "resolveReviewThread",
                GitHubWorkflowOperationKind::ResolveReviewThread,
            ),
            (
                "unresolveReviewThread",
                GitHubWorkflowOperationKind::UnresolveReviewThread,
            ),
        ])
    })
}

fn resource_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$").unwrap())
}

fn repository_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").unwrap())
}

fn graphql_root_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[,{]\s*([A-Za-z][A-Za-z0-9]*)\s*\(").unwrap())
}

fn graphql_thread_definition_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bmutation(?:\s+[A-Za-z][A-Za-z0-9]*)?\s*\(\s*\$threadId\s*:\s*ID!\s*\)")
            .unwrap()
    })
}

fn graphql_thread_input_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\binput\s*:\s*\{\s*threadId\s*:\s*\$threadId\s*\}").unwrap())
}

#[allow(clippy::invalid_regex)]
fn graphql_operation(
    arguments: &[String],
    repository: Option<&str>,
) -> Option<(GitHubWorkflowOperationKind, String, String, String)> {
    if arguments.get(..2) != Some(&["api".to_string(), "graphql".to_string()][..]) {
        return None;
    }
    let repository = repository?;
    let fields = field_values(&arguments[2..]);
    let query = fields.get("query")?;
    let thread_id = fields.get("threadId")?;
    if fields.len() != 2 || !resource_id_re().is_match(thread_id) {
        return None;
    }
    let mutation_count = regex_count(r"\bmutation\b", query);
    let thread_def = query
        .find('{')
        .map(|i| graphql_thread_definition_re().is_match(query[..i].trim()))
        .unwrap_or(false);
    if mutation_count != 1
        || !thread_def
        || graphql_thread_input_re().find_iter(query).count() != 1
        || query.matches("$threadId").count() != 2
        || Regex::new(r"\$(?!threadId\b)").unwrap().is_match(query)
        || ["$(`", "${", "`", "\"", "#"]
            .iter()
            .any(|m| query.contains(m))
    {
        return None;
    }
    let matches: Vec<&str> = graphql_operations()
        .keys()
        .copied()
        .filter(|name| {
            Regex::new(&format!(r"\b{}\s*\(", regex::escape(name)))
                .unwrap()
                .is_match(query)
        })
        .collect();
    let roots: Vec<String> = graphql_root_re()
        .captures_iter(query)
        .map(|c| c[1].to_string())
        .collect();
    if matches.len() != 1 || roots != vec![matches[0].to_string()] {
        return None;
    }
    let kind = graphql_operations()[matches[0]];
    Some((
        kind,
        "github-review-thread".to_string(),
        thread_id.clone(),
        repository.to_string(),
    ))
}

fn cli_operation(
    arguments: &[String],
    expected_repository: Option<&str>,
) -> Option<(GitHubWorkflowOperationKind, String, String, String)> {
    if arguments.len() < 5 || (arguments[0] != "issue" && arguments[0] != "pr") {
        return None;
    }
    let group = arguments[0].as_str();
    let action = arguments[1].as_str();
    let resource_id = &arguments[2];
    if (group, action) == ("pr", "ready") {
        return pr_ready_operation(arguments, expected_repository);
    }
    let kind = match (group, action) {
        ("issue", "lock") => GitHubWorkflowOperationKind::LockIssue,
        ("issue", "unlock") => GitHubWorkflowOperationKind::UnlockIssue,
        ("issue", "pin") => GitHubWorkflowOperationKind::PinIssue,
        ("issue", "unpin") => GitHubWorkflowOperationKind::UnpinIssue,
        ("pr", "lock") => GitHubWorkflowOperationKind::LockPr,
        ("pr", "unlock") => GitHubWorkflowOperationKind::UnlockPr,
        _ => return None,
    };
    if !resource_id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let tail = &arguments[3..];
    if tail.len() != 2 || (tail[0] != "--repo" && tail[0] != "-R") {
        return None;
    }
    let repository = normalized_repository(&tail[1])?;
    if expected_repository.is_some() && expected_repository != Some(repository.as_str()) {
        return None;
    }
    Some((
        kind,
        format!("github-{group}"),
        resource_id.clone(),
        repository,
    ))
}

fn pr_ready_operation(
    arguments: &[String],
    expected_repository: Option<&str>,
) -> Option<(GitHubWorkflowOperationKind, String, String, String)> {
    if !(arguments.len() == 5 || arguments.len() == 6)
        || arguments.get(..2) != Some(&["pr".to_string(), "ready".to_string()][..])
        || !arguments[2].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let pull_number = arguments[2].clone();
    let ready_args = &arguments[3..arguments.len() - 2];
    if arguments[arguments.len() - 2] != "--repo" && arguments[arguments.len() - 2] != "-R" {
        return None;
    }
    let repository = normalized_repository(&arguments[arguments.len() - 1])?;
    if expected_repository.is_some() && expected_repository != Some(repository.as_str()) {
        return None;
    }
    if ready_args.is_empty() {
        return Some((
            GitHubWorkflowOperationKind::MarkPrReady,
            "github-pr".to_string(),
            pull_number,
            repository,
        ));
    }
    if ready_args == ["--undo"] {
        return Some((
            GitHubWorkflowOperationKind::MarkPrDraft,
            "github-pr".to_string(),
            pull_number,
            repository,
        ));
    }
    None
}

fn field_values(arguments: &[String]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        if (flag != "-f" && flag != "--raw-field") || index + 1 >= arguments.len() {
            return BTreeMap::new();
        }
        let field = &arguments[index + 1];
        let Some((key, value)) = field.split_once('=') else {
            return BTreeMap::new();
        };
        if key.is_empty() || values.contains_key(key) || value.is_empty() {
            return BTreeMap::new();
        }
        values.insert(key.to_string(), value.to_string());
        index += 2;
    }
    values
}

fn normalized_repository(repository: &str) -> Option<String> {
    let normalized = repository.trim().to_ascii_lowercase();
    if repository_re().is_match(&normalized) {
        Some(normalized)
    } else {
        None
    }
}

fn compute_operation_digest(
    command_identity: &str,
    kind: GitHubWorkflowOperationKind,
    repository: &str,
    resource_id: &str,
    resource_type: &str,
) -> String {
    let payload = serde_json::json!({
        "command_identity": command_identity,
        "kind": kind.as_str(),
        "repository": repository,
        "resource_id": resource_id,
        "resource_type": resource_type,
    });
    let framed =
        canonical_framed_payload("github-workflow-operation", &payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&framed);
    hex_lower(&hasher.finalize())
}

fn regex_count(pattern: &str, haystack: &str) -> usize {
    Regex::new(pattern).unwrap().find_iter(haystack).count()
}

fn hmac_compare_digest(a: &str, b: &str) -> bool {
    let (x, y) = (a.as_bytes(), b.as_bytes());
    if x.len() != y.len() {
        return false;
    }
    x.iter()
        .zip(y.iter())
        .fold(0u8, |acc, (p, q)| acc | (p ^ q))
        == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

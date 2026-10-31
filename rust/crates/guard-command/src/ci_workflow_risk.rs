//! Risky settings in a GitHub Actions workflow file.
//!
//! These rules read a workflow's text only: they never run a job, resolve an
//! action or fetch a reusable workflow. They match line by line, the way
//! GitHub's own keys are written, and skip whole-line comments, so a trigger
//! or permission someone commented out is not reported.
//!
//! A workflow that runs on `pull_request_target` or `workflow_run` holds
//! repository secrets and a write token. Checking out the pull request's head
//! there lets a contributor's code run with them. A `write-all` token lets
//! any compromised step push, publish or approve. An action referenced by tag
//! or branch can change under the workflow when its owner moves that ref.

use std::sync::LazyLock;

use regex::Regex;

#[cfg(test)]
#[path = "ci_workflow_risk_tests.rs"]
mod tests;

/// One rule's fixed wording. Nothing in it quotes the workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiWorkflowRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub false_positive_hint: Option<&'static str>,
}

pub const UNTRUSTED_CHECKOUT: CiWorkflowRule = CiWorkflowRule {
    id: "ci.workflow.untrusted-checkout",
    category: "execution",
    severity: "high",
    confidence: "likely",
    title: "Privileged workflow checks out pull request code",
    reason: "A workflow that runs on pull_request_target or workflow_run, with repository secrets and a write token, checks out the pull request's own code, so a contributor's change can run with those privileges.",
    false_positive_hint: Some(
        "Safe only when the checked-out code is read as data and never built, installed or run.",
    ),
};

pub const WRITE_ALL_PERMISSIONS: CiWorkflowRule = CiWorkflowRule {
    id: "ci.workflow.write-all-permissions",
    category: "privilege",
    severity: "medium",
    confidence: "strong",
    title: "Workflow token has write access to everything",
    reason: "The workflow grants its GitHub token write-all permissions, so any compromised step can push code, publish releases or change repository settings.",
    false_positive_hint: None,
};

pub const UNPINNED_ACTION: CiWorkflowRule = CiWorkflowRule {
    id: "ci.workflow.unpinned-action",
    category: "supply_chain",
    severity: "medium",
    confidence: "strong",
    title: "Workflow uses an action that is not pinned to a commit",
    reason: "The workflow references an action or reusable workflow by tag or branch instead of a full commit SHA, so its owner can change the code the workflow runs.",
    false_positive_hint: None,
};

static USES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*(?:-\s*)?uses:\s*["']?([^\s#"']+)"#).expect("valid uses pattern")
});
static WRITE_ALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\s*["']?permissions["']?\s*:\s*["']?write-all\b"#)
        .expect("valid permissions pattern")
});
/// An action step's `with:` key. Keys indented under it are the action's
/// inputs, not the workflow's or job's own settings.
static WITH_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\s*(?:-\s*)?)["']?with["']?\s*:\s*(?:#.*)?$"#).expect("valid with pattern")
});
/// The trigger in any of its forms (`workflow_run:`, `on: workflow_run`,
/// `on: [workflow_run]`), but not the `github.event.workflow_run` context.
static PRIVILEGED_TRIGGER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^.\w])(?:pull_request_target|workflow_run)\b")
        .expect("valid trigger pattern")
});
static CHECKOUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bactions/checkout\b|\bgit\s+checkout\b|\bgh\s+pr\s+checkout\b")
        .expect("valid checkout pattern")
});
/// `gh pr checkout` always fetches the pull request's own code.
static GH_PR_CHECKOUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh\s+pr\s+checkout\b").expect("valid gh checkout pattern"));
/// Expressions that name the pull request's own code rather than the base
/// branch the privileged workflow was started from.
static UNTRUSTED_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"github\.event\.pull_request\.(?:head\.(?:sha|ref)|merge_commit_sha)\b|github\.event\.workflow_run\.head_(?:sha|branch)\b|github\.head_ref\b|\bGITHUB_HEAD_REF\b|refs/pull/",
    )
    .expect("valid untrusted ref pattern")
});
/// Lines that choose the code a checkout fetches: a checkout step's `ref` or
/// `repository` input, or a `git checkout` or `git fetch` command. An
/// untrusted ref anywhere else, such as a concurrency group or a log line,
/// does not put pull request code in the workspace.
static CHECKOUT_TARGET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:-\s*)?(?:ref|repository):|\bgit\s+(?:checkout|fetch)\b")
        .expect("valid checkout target pattern")
});
static COMMIT_SHA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{40}$").expect("valid sha pattern"));

/// The rules a workflow's `text` matches, in rule order and each at most once.
pub fn detect_ci_workflow_risk(text: &str) -> Vec<CiWorkflowRule> {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    let any = |pattern: &Regex| lines.iter().any(|line| pattern.is_match(line));
    let checks_out_head = lines.iter().any(|line| {
        GH_PR_CHECKOUT.is_match(line)
            || (CHECKOUT_TARGET.is_match(line) && UNTRUSTED_REF.is_match(line))
    });
    let write_all = outside_action_inputs(&lines).any(|line| WRITE_ALL.is_match(line));
    let untrusted_checkout = any(&PRIVILEGED_TRIGGER) && any(&CHECKOUT) && checks_out_head;
    let unpinned = lines
        .iter()
        .filter_map(|line| USES.captures(line))
        .any(|captures| is_unpinned(&captures[1]));
    [
        (untrusted_checkout, UNTRUSTED_CHECKOUT),
        (write_all, WRITE_ALL_PERMISSIONS),
        (unpinned, UNPINNED_ACTION),
    ]
    .into_iter()
    .filter_map(|(found, rule)| found.then_some(rule))
    .collect()
}

/// The lines that are not an action's `with:` inputs.
fn outside_action_inputs<'a>(lines: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
    let mut inputs_indent: Option<usize> = None;
    lines.iter().copied().filter(move |line| {
        let indent = line.len() - line.trim_start().len();
        if inputs_indent.is_some_and(|key| indent > key) || line.trim().is_empty() {
            return inputs_indent.is_none();
        }
        inputs_indent = WITH_BLOCK.captures(line).map(|captures| captures[1].len());
        true
    })
}

/// A remote action or reusable workflow not pinned to a full commit SHA. A
/// local path runs code from the same checkout, and a container image is out
/// of this rule's scope.
fn is_unpinned(reference: &str) -> bool {
    if reference.starts_with("./") || reference.starts_with("docker://") {
        return false;
    }
    match reference.rsplit_once('@') {
        Some((_, git_ref)) => !COMMIT_SHA.is_match(git_ref),
        None => true,
    }
}

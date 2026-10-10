//! Native port of the GitHub CLI capability dispatcher and sub-classifiers.
//!
//! Python ground truth (verbatim-faithful):
//! - `runtime/github_command_capabilities.py` (`classify_github_cli` + helpers).
//! - `runtime/github_auth_capabilities.py` (`classify_github_auth`).
//! - `runtime/github_routine_merge.py` (`classify_pr_merge`,
//!   `is_routine_squash_merge`, `boolean_option_state`,
//!   `boolean_option_token_state`).
//! - `runtime/github_rest_capabilities.py` (`classify_github_api`,
//!   `_mutation_capabilities`, `_parse_api_arguments`, `_classify_graphql`,
//!   `_field_value_is_external`, `_value_is_dynamic`, `_api_parse_failure`).
//! - `runtime/github_graphql_capabilities.py` (`classify_graphql_document`,
//!   `is_routine_review_thread_resolution`).
//!
//! `command_compatibility/github*.rs` is a DIFFERENT contract (capabilities ->
//! catalog owners, `None` = unsupported, no GraphQL); this module returns the
//! evaluate-path `GitHubCommandAssessment` with exact `reason_code`/`detail`.

use regex::Regex;
use std::sync::OnceLock;

use crate::github_capability_contract::{
    github_assessment, github_cli_invocation_is_help, GitHubCommandAssessment,
    GitHubCommandCapability as Cap,
};

/// Shorthand for a single-capability assessment (Python `_assessment` helper
/// wraps a bare string into a 1-tuple before `github_assessment`).
fn assessment(cap: Cap, reason_code: &str, detail: &str) -> GitHubCommandAssessment {
    github_assessment(&[cap], reason_code, detail)
}

// ---------------------------------------------------------------------------
// Constant tables (github_command_capabilities.py:18-99)
// ---------------------------------------------------------------------------

fn lookup<'a>(table: &'a [(&'a str, &'a [&'a str])], key: &str) -> Option<&'a [&'a str]> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

static READ_ONLY_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("issue", &["list", "status", "view"]),
    ("pr", &["checks", "diff", "list", "status", "view"]),
    ("release", &["list", "view"]),
    ("repo", &["list", "view"]),
    ("run", &["list", "view", "watch"]),
    ("workflow", &["list", "view"]),
];

static CONTENT_SUBCOMMANDS: &[(&str, &[&str])] = &[
    (
        "issue",
        &[
            "close", "comment", "create", "develop", "edit", "reopen", "transfer",
        ],
    ),
    (
        "pr",
        &["close", "comment", "create", "edit", "reopen", "review"],
    ),
    ("repo", &["create", "fork", "rename", "sync"]),
];

static MAINTENANCE_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("issue", &["lock", "pin", "unlock", "unpin"]),
    ("pr", &["lock", "ready", "unlock"]),
];

static WORKFLOW_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("run", &["cancel", "rerun"]),
    ("workflow", &["disable", "enable", "run"]),
];

const PUBLISH_SUBCOMMANDS: &[&str] = &["create", "edit", "upload"];
const DELETE_GROUPS: &[&str] = &[
    "cache",
    "codespace",
    "issue",
    "label",
    "pr",
    "release",
    "repo",
    "run",
    "variable",
];
const SECRET_GROUPS: &[&str] = &["secret"];
const ACCESS_GROUPS: &[&str] = &["gpg-key", "ssh-key"];
const OTHER_MUTATING_GROUPS: &[&str] = &["cache", "codespace", "label", "variable"];
const READ_ONLY_TOP_LEVEL: &[&str] = &["search", "status"];
const LOCAL_TOP_LEVEL: &[&str] = &["completion", "help", "version"];

const GROUP_OPTIONS_WITH_VALUES: &[&str] = &["-R", "--repo"];
const GROUP_BOOLEAN_OPTIONS: &[&str] = &["--help"];
const GLOBAL_OPTIONS_WITH_VALUES: &[&str] = &["--hostname", "--repo", "-R"];

fn repository_component_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z0-9_.-]+\z").unwrap())
}

/// `(group, subcommand, boolean-flags)` — `_READ_SHORT_BOOLEAN_FLAGS`.
static READ_SHORT_BOOLEAN_FLAGS: &[(&str, &str, &str)] = &[
    ("issue", "list", "w"),
    ("issue", "view", "cw"),
    ("pr", "checks", "w"),
    ("pr", "diff", "w"),
    ("pr", "list", "dw"),
    ("pr", "status", "c"),
    ("pr", "view", "cw"),
    ("release", "view", "w"),
    ("repo", "view", "w"),
    ("run", "list", "a"),
    ("run", "view", "vw"),
    ("workflow", "list", "a"),
    ("workflow", "view", "wy"),
];

/// `(group, subcommand, value-flags)` — `_READ_SHORT_VALUE_FLAGS`.
static READ_SHORT_VALUE_FLAGS: &[(&str, &str, &str)] = &[
    ("issue", "list", "ALSalms"),
    ("pr", "checks", "i"),
    ("pr", "diff", "e"),
    ("pr", "list", "ABHLSals"),
    ("release", "list", "LO"),
    ("repo", "list", "Ll"),
    ("repo", "view", "b"),
    ("run", "list", "Lbcesuw"),
    ("run", "view", "aj"),
    ("run", "watch", "i"),
    ("workflow", "list", "L"),
    ("workflow", "view", "r"),
];

const INHERITED_READ_SHORT_VALUE_FLAGS: &str = "qt";

fn short_flags(
    table: &[(&'static str, &'static str, &'static str)],
    g: &str,
    s: &str,
) -> &'static str {
    table
        .iter()
        .find(|(a, b, _)| *a == g && *b == s)
        .map(|(_, _, f)| *f)
        .unwrap_or("")
}

// ---------------------------------------------------------------------------
// classify_github_cli (:102-285)
// ---------------------------------------------------------------------------

pub fn classify_github_cli(args: &[String]) -> GitHubCommandAssessment {
    let normalized: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let original: Vec<String> = normalized.clone();
    if normalized.is_empty() {
        return assessment(
            Cap::Unknown,
            "github.command.missing",
            "The GitHub CLI subcommand is missing.",
        );
    }
    if alternate_hostname_requested(&original) {
        return assessment(
            Cap::Unknown,
            "github.command.alternate-host",
            "An alternate GitHub host requires explicit review.",
        );
    }
    if unsafe_repository_selector_requested(&original) {
        return assessment(
            Cap::Unknown,
            "github.command.untrusted-repository-selector",
            "An alternate, dynamic, or malformed GitHub repository selector requires explicit review.",
        );
    }
    let normalized = strip_global_options(&normalized);
    if normalized.is_empty() {
        return assessment(
            Cap::Unknown,
            "github.command.missing",
            "The GitHub CLI subcommand is missing after global options.",
        );
    }
    let top_level = normalized[0].to_lowercase();
    if top_level == "--version" || top_level == "-v" {
        return assessment(
            Cap::ReadLocal,
            "github.command.local-metadata",
            "The command reads local CLI metadata.",
        );
    }
    if github_cli_invocation_is_help(&normalized) {
        return assessment(
            Cap::ReadLocal,
            "github.command.local-help",
            "The command displays local CLI help.",
        );
    }
    if top_level == "api" {
        return classify_github_api(&normalized[1..]);
    }
    if LOCAL_TOP_LEVEL.contains(&top_level.as_str()) {
        return assessment(
            Cap::ReadLocal,
            "github.command.local-metadata",
            "The command reads local CLI metadata.",
        );
    }
    if let Some(auth) = classify_github_auth(&normalized) {
        return auth;
    }
    if READ_ONLY_TOP_LEVEL.contains(&top_level.as_str()) {
        return assessment(
            Cap::ReadRemote,
            "github.command.proven-read",
            "The command is a known read-only GitHub operation.",
        );
    }
    if SECRET_GROUPS.contains(&top_level.as_str()) {
        return assessment(
            Cap::SecretRemote,
            "github.command.secret-mutation",
            "The command changes GitHub secrets.",
        );
    }
    if ACCESS_GROUPS.contains(&top_level.as_str()) {
        let subcommand = group_subcommand(&normalized[1..]);
        if subcommand.as_deref() == Some("help") {
            return assessment(
                Cap::ReadLocal,
                "github.command.local-help",
                "The command displays local CLI help.",
            );
        }
        if subcommand.as_deref() == Some("list") {
            return assessment(
                Cap::ReadRemote,
                "github.command.proven-access-read",
                "The command reads public-key metadata from GitHub.",
            );
        }
        let access_capabilities: Vec<Cap> = if subcommand.as_deref() == Some("delete") {
            vec![Cap::DeleteRemote, Cap::AccessRemote]
        } else {
            vec![Cap::AccessRemote]
        };
        return github_assessment(
            &access_capabilities,
            "github.command.access-mutation",
            "The command changes GitHub access credentials.",
        );
    }
    if OTHER_MUTATING_GROUPS.contains(&top_level.as_str()) {
        let subcommand = group_subcommand(&normalized[1..]);
        if subcommand.as_deref() == Some("delete") {
            return assessment(
                Cap::DeleteRemote,
                "github.command.delete-mutation",
                "The command deletes GitHub-hosted state.",
            );
        }
        let capability = if top_level == "label" {
            Cap::ContentRemote
        } else if top_level == "variable" {
            Cap::WorkflowRemote
        } else {
            Cap::MutateRemote
        };
        return assessment(
            capability,
            "github.command.remote-mutation",
            "The command changes GitHub-hosted state.",
        );
    }
    if lookup(READ_ONLY_SUBCOMMANDS, &top_level).is_none() {
        return assessment(
            Cap::Unknown,
            "github.command.extension-or-alias",
            "The GitHub CLI command may be an extension or alias and cannot be classified statically.",
        );
    }
    let subcommand = match group_subcommand(&normalized[1..]) {
        Some(s) => s,
        None => {
            return assessment(
                Cap::Unknown,
                "github.command.unresolved-subcommand",
                "The GitHub CLI subcommand could not be resolved statically.",
            );
        }
    };
    if subcommand == "help" {
        return assessment(
            Cap::ReadLocal,
            "github.command.local-help",
            "The command displays local CLI help.",
        );
    }
    if lookup(READ_ONLY_SUBCOMMANDS, &top_level)
        .unwrap()
        .contains(&subcommand.as_str())
    {
        return assessment(
            Cap::ReadRemote,
            "github.command.proven-read",
            "The command is a known read-only GitHub operation.",
        );
    }
    let tail: Vec<String> = normalized[2.min(normalized.len())..].to_vec();
    if subcommand == "delete" && DELETE_GROUPS.contains(&top_level.as_str()) {
        return assessment(
            Cap::DeleteRemote,
            "github.command.delete-mutation",
            "The command deletes GitHub-hosted state.",
        );
    }
    if top_level == "pr" && subcommand == "merge" {
        return classify_pr_merge(&tail);
    }
    if top_level == "release" && PUBLISH_SUBCOMMANDS.contains(&subcommand.as_str()) {
        return assessment(
            Cap::PublishRemote,
            "github.command.release-publication",
            "The command publishes or changes a GitHub release artifact.",
        );
    }
    if lookup(WORKFLOW_SUBCOMMANDS, &top_level)
        .map(|t| t.contains(&subcommand.as_str()))
        .unwrap_or(false)
    {
        if top_level == "run"
            && subcommand == "rerun"
            && is_routine_failed_run_rerun(&original, &tail)
        {
            return assessment(
                Cap::RoutineWorkflowRemote,
                "github.command.routine-failed-run-rerun",
                "The command retries only failed jobs from one numeric GitHub Actions run.",
            );
        }
        return assessment(
            Cap::WorkflowRemote,
            "github.command.workflow-mutation",
            "The command starts or changes a GitHub workflow.",
        );
    }
    if top_level == "repo" && subcommand == "edit" {
        return assessment(
            Cap::AccessRemote,
            "github.command.repository-access-mutation",
            "Repository settings can change access or protection boundaries.",
        );
    }
    if top_level == "repo" && subcommand == "set-default" {
        return assessment(
            Cap::WriteLocal,
            "github.command.local-default-write",
            "The command changes local GitHub CLI repository configuration.",
        );
    }
    if top_level == "repo" && subcommand == "sync" && has_option(&tail, "--force") {
        return assessment(
            Cap::ForceRemote,
            "github.command.force-mutation",
            "The command forcefully changes remote repository state.",
        );
    }
    if top_level == "pr" && subcommand == "create" && pr_create_has_static_inline_content(&tail) {
        return assessment(
            Cap::ProposeRemote,
            "github.command.pr-proposal",
            "The command creates a pull-request proposal without merging or changing repository controls.",
        );
    }
    if lookup(MAINTENANCE_SUBCOMMANDS, &top_level)
        .map(|t| t.contains(&subcommand.as_str()))
        .unwrap_or(false)
    {
        if has_dynamic_value(&original) {
            return assessment(
                Cap::Unknown,
                "github.command.dynamic-maintenance-target",
                "The maintenance target cannot be resolved statically.",
            );
        }
        return assessment(
            Cap::MaintainRemote,
            "github.command.bounded-maintenance",
            "The command performs a statically bounded maintenance operation.",
        );
    }
    if lookup(CONTENT_SUBCOMMANDS, &top_level)
        .map(|t| t.contains(&subcommand.as_str()))
        .unwrap_or(false)
    {
        return assessment(
            Cap::ContentRemote,
            "github.command.content-mutation",
            "The command changes GitHub-hosted content.",
        );
    }
    assessment(
        Cap::Unknown,
        "github.command.unrecognized-subcommand",
        "The GitHub CLI subcommand is not in the reviewed read-only set.",
    )
}

// ---------------------------------------------------------------------------
// Option helpers (:288-435)
// ---------------------------------------------------------------------------

/// `_has_option` (:288).
pub fn has_option(args: &[String], option: &str) -> bool {
    args.iter()
        .any(|token| token == option || token.starts_with(&format!("{option}=")))
}

fn has_short_option(args: &[String], option: &str) -> bool {
    args.iter()
        .any(|token| token == option || (token.starts_with(option) && token.len() > option.len()))
}

fn has_short_boolean_option(args: &[String], option: &str) -> bool {
    const LONG_VALUE_OPTIONS: &[&str] = &[
        "--assignee",
        "--base",
        "--body",
        "--body-file",
        "--head",
        "--label",
        "--milestone",
        "--project",
        "--recover",
        "--repo",
        "--reviewer",
        "--template",
        "--title",
    ];
    const SHORT_VALUE_OPTIONS: &[char] =
        &['a', 'B', 'b', 'F', 'H', 'l', 'm', 'p', 'r', 'R', 'T', 't'];
    let option_name = option.trim_start_matches('-');
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        let is_short_value_option = token.len() == 2
            && token.starts_with('-')
            && token
                .chars()
                .nth(1)
                .map(|c| SHORT_VALUE_OPTIONS.contains(&c))
                .unwrap_or(false);
        if LONG_VALUE_OPTIONS.contains(&token.as_str()) || is_short_value_option {
            index += 2;
            continue;
        }
        if LONG_VALUE_OPTIONS
            .iter()
            .any(|vo| token.starts_with(&format!("{vo}=")))
        {
            index += 1;
            continue;
        }
        if token == option {
            return true;
        }
        if !token.starts_with('-') || token.starts_with("--") || token.len() < 3 {
            index += 1;
            continue;
        }
        let cluster = &token[1..];
        let first = cluster.chars().next().unwrap_or('\0');
        if !SHORT_VALUE_OPTIONS.contains(&first) && cluster.contains(option_name) {
            return true;
        }
        index += 1;
    }
    false
}

fn has_explicit_option_value(args: &[String], long_option: &str, short_option: &str) -> bool {
    args.iter().enumerate().any(|(index, token)| {
        if token == long_option || token == short_option {
            return index + 1 < args.len() && !args[index + 1].is_empty();
        }
        if let Some(rest) = token.strip_prefix(&format!("{long_option}=")) {
            return !rest.is_empty();
        }
        token.starts_with(short_option) && token.len() > short_option.len()
    })
}

/// `_has_dynamic_value` (:436).
fn has_dynamic_value(args: &[String]) -> bool {
    args.iter()
        .any(|token| token.contains('$') || token.contains('`') || token.starts_with('@'))
}

/// `_pr_create_has_static_inline_content` (:296).
fn pr_create_has_static_inline_content(args: &[String]) -> bool {
    const CONTENT_DERIVED: &[&str] = &[
        "--body-file",
        "--template",
        "--fill",
        "--fill-first",
        "--fill-verbose",
        "--recover",
        "--web",
        "--editor",
        "--dry-run",
    ];
    if CONTENT_DERIVED.iter().any(|o| has_option(args, o)) {
        return false;
    }
    if ["-F", "-T"].iter().any(|o| has_short_option(args, o)) {
        return false;
    }
    if ["-e", "-f", "-w"]
        .iter()
        .any(|o| has_short_boolean_option(args, o))
    {
        return false;
    }
    has_explicit_option_value(args, "--title", "-t")
        && has_explicit_option_value(args, "--body", "-b")
}

/// `static_markdown_pr_body_file_operand` (:321).
#[allow(dead_code)]
pub fn static_markdown_pr_body_file_operand(args: &[String]) -> Option<String> {
    const INCOMPATIBLE: &[&str] = &[
        "--body",
        "--template",
        "--fill",
        "--fill-first",
        "--fill-verbose",
        "--recover",
        "--web",
        "--editor",
        "--dry-run",
    ];
    if INCOMPATIBLE.iter().any(|o| has_option(args, o)) {
        return None;
    }
    if ["-T", "-b"].iter().any(|o| has_short_option(args, o)) {
        return None;
    }
    if ["-e", "-f", "-w"]
        .iter()
        .any(|o| has_short_boolean_option(args, o))
    {
        return None;
    }
    if !has_explicit_option_value(args, "--title", "-t") {
        return None;
    }
    let mut body_files: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--body-file" || token == "-F" {
            if index + 1 >= args.len() {
                return None;
            }
            body_files.push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--body-file=") {
            body_files.push(v.to_string());
        } else if token.starts_with("-F") && token.len() > 2 {
            body_files.push(token[2..].to_string());
        }
        index += 1;
    }
    if body_files.len() != 1 {
        return None;
    }
    let body_file = &body_files[0];
    const MARKERS: &[char] = &[
        '$', '`', '*', '?', '[', ']', '{', '}', '(', ')', '<', '>', '^', '#',
    ];
    if body_file.is_empty()
        || body_file == "-"
        || body_file.starts_with('=')
        || body_file.starts_with("~//")
        || body_file.chars().any(|c| MARKERS.contains(&c))
        || (body_file.contains('~') && !body_file.starts_with("~/"))
    {
        return None;
    }
    let lower = body_file.to_lowercase();
    if !lower.ends_with(".md") && !lower.ends_with(".markdown") {
        return None;
    }
    Some(body_file.clone())
}

// ---------------------------------------------------------------------------
// `_is_routine_failed_run_rerun` (:439)
// ---------------------------------------------------------------------------

fn is_routine_failed_run_rerun(original: &[String], args: &[String]) -> bool {
    if !original.iter().any(|t| {
        t == "--repo"
            || t == "-R"
            || t.starts_with("--repo=")
            || t.starts_with("-R=")
            || (t.starts_with("-R") && t.len() > 2)
    }) {
        return false;
    }
    let mut run_id: Option<String> = None;
    let mut failed = false;
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--failed" {
            if failed {
                return false;
            }
            failed = true;
        } else if token == "--repo" || token == "-R" {
            if index + 1 >= args.len() {
                return false;
            }
            index += 1;
        } else if token.starts_with("--repo=")
            || token.starts_with("-R=")
            || (token.starts_with("-R") && token.len() > 2)
        {
            // repo selector consumed inline
        } else if run_id.is_none() && is_positive_numeric(token) {
            run_id = Some(token.clone());
        } else {
            return false;
        }
        index += 1;
    }
    run_id.is_some() && failed
}

fn is_positive_numeric(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| c.is_ascii_digit())
        && token.len() <= 20
        && token.parse::<u64>().map(|v| v > 0).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Hostname / repo selector (:469-529)
// ---------------------------------------------------------------------------

fn alternate_hostname_requested(args: &[String]) -> bool {
    let mut hostnames: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if index > 0 && token.starts_with("-h") && token != "--help" {
            hostnames.push(if token == "-h" {
                args.get(index + 1).cloned().unwrap_or_default()
            } else {
                token[2..].to_string()
            });
        }
        if let Some(v) = token.strip_prefix("--hostname=") {
            hostnames.push(v.to_string());
        }
        if token == "--hostname" {
            hostnames.push(args.get(index + 1).cloned().unwrap_or_default());
        }
        index += 1;
    }
    hostnames.iter().any(|h| h.to_lowercase() != "github.com") || {
        let mut u = hostnames.clone();
        u.sort();
        u.dedup();
        u.len() > 1
    }
}

fn unsafe_repository_selector_requested(args: &[String]) -> bool {
    let mut selectors: Vec<String> = Vec::new();
    let mut malformed_cluster = false;
    let command_args = strip_global_options(args);
    let (g, s) = if command_args.len() >= 2 {
        (command_args[0].as_str(), command_args[1].as_str())
    } else {
        ("", "")
    };
    let boolean_flags = short_flags(READ_SHORT_BOOLEAN_FLAGS, g, s);
    let mut value_flags = String::from(short_flags(READ_SHORT_VALUE_FLAGS, g, s));
    value_flags.push_str(INHERITED_READ_SHORT_VALUE_FLAGS);
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if let Some(sel) = token.strip_prefix("--repo=") {
            selectors.push(sel.to_string());
        } else if token == "--repo" || token == "-R" {
            selectors.push(args.get(index + 1).cloned().unwrap_or_default());
            index += 1;
        } else if token.len() > 2
            && token.starts_with('-')
            && token
                .chars()
                .nth(1)
                .map(|c| value_flags.contains(c))
                .unwrap_or(false)
        {
            // value flag absorbs selector
        } else if token.starts_with('-') && !token.starts_with("--") && token[1..].contains('R') {
            let cluster = &token[1..];
            let mut it = cluster.splitn(2, 'R');
            let prefix = it.next().unwrap_or("");
            let attached = it.next().unwrap_or("");
            if prefix.chars().any(|f| value_flags.contains(f)) {
                // value flag before R absorbs
            } else if prefix.is_empty() || prefix.chars().all(|f| boolean_flags.contains(f)) {
                if !attached.is_empty() {
                    selectors.push(attached.to_string());
                } else {
                    selectors.push(args.get(index + 1).cloned().unwrap_or_default());
                    index += 1;
                }
            } else {
                malformed_cluster = true;
            }
        }
        index += 1;
    }
    malformed_cluster
        || selectors.len() > 1
        || selectors.iter().any(|s| !repository_selector_is_safe(s))
}

fn repository_selector_is_safe(selector: &str) -> bool {
    if selector.contains('$')
        || selector.contains('`')
        || selector.contains("$(")
        || selector.contains("${")
    {
        return false;
    }
    let mut parts: Vec<&str> = selector.split('/').collect();
    if parts.len() == 3 {
        if parts[0].to_lowercase() != "github.com" {
            return false;
        }
        parts = parts[1..].to_vec();
    }
    parts.len() == 2 && parts.iter().all(|p| repository_component_re().is_match(p))
}

fn strip_global_options(args: &[String]) -> Vec<String> {
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token.starts_with("-R") && token != "-R" {
            index += 1;
            continue;
        }
        let (name, sep) = match token.find('=') {
            Some(p) => (&token[..p], true),
            None => (token.as_str(), false),
        };
        if !GLOBAL_OPTIONS_WITH_VALUES.contains(&name) {
            break;
        }
        if sep {
            index += 1;
            continue;
        }
        if index + 1 >= args.len() {
            return Vec::new();
        }
        index += 2;
    }
    args[index..].to_vec()
}

fn group_subcommand(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        let (name, sep) = match token.find('=') {
            Some(p) => (&token[..p], true),
            None => (token.as_str(), false),
        };
        if token == "--" {
            index += 1;
            break;
        }
        if GROUP_OPTIONS_WITH_VALUES.contains(&name) {
            if sep {
                index += 1;
                continue;
            }
            if index + 1 >= args.len() {
                return None;
            }
            index += 2;
            continue;
        }
        if GROUP_BOOLEAN_OPTIONS.contains(&token.as_str()) {
            return Some("help".to_string());
        }
        if token.starts_with('-') {
            return None;
        }
        return Some(token.to_lowercase());
    }
    args.get(index).map(|t| t.to_lowercase())
}

// ---------------------------------------------------------------------------
// github_routine_merge.py
// ---------------------------------------------------------------------------

/// `boolean_option_token_state` (:22). States: "absent"/"true"/"false"/"invalid".
const BOOLEAN_OPTION_TRUE_VALUES: &[&str] = &["1", "t", "T", "TRUE", "true", "True"];
const BOOLEAN_OPTION_FALSE_VALUES: &[&str] = &["0", "f", "F", "FALSE", "false", "False"];

fn boolean_option_token_state(argument: &str, option: &str) -> &'static str {
    if argument == option {
        return "true";
    }
    let prefix = format!("{option}=");
    if !argument.starts_with(&prefix) {
        return "absent";
    }
    let value = &argument[prefix.len()..];
    if BOOLEAN_OPTION_TRUE_VALUES.contains(&value) {
        return "true";
    }
    if BOOLEAN_OPTION_FALSE_VALUES.contains(&value) {
        return "false";
    }
    "invalid"
}

/// `boolean_option_state` (:38): last well-formed value; early "invalid".
fn boolean_option_state(args: &[String], option: &str) -> &'static str {
    let mut state = "absent";
    for token in args {
        if token == "--" {
            break;
        }
        let token_state = boolean_option_token_state(token, option);
        if token_state == "absent" {
            continue;
        }
        if token_state == "invalid" {
            return "invalid";
        }
        state = token_state;
    }
    state
}

const MAX_PR_DIGITS: usize = 20;
const MAX_REPO_LEN: usize = 255;

fn static_repository_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A(?:[A-Za-z0-9.-]+/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z").unwrap()
    })
}

/// `_is_positive_pull_request` (:54). `isascii()` + `isdigit()` ⇒ ASCII digits only.
fn is_positive_pull_request(value: &str) -> bool {
    value.is_ascii()
        && !value.is_empty()
        && value.chars().all(|c| c.is_ascii_digit())
        && value.len() <= MAX_PR_DIGITS
        && value.parse::<u64>().map(|v| v > 0).unwrap_or(false)
}

/// `_is_static_repository` (:58).
fn is_static_repository(value: &str) -> bool {
    value.len() <= MAX_REPO_LEN && static_repository_re().is_match(value)
}

/// `is_routine_squash_merge` (:62).
pub fn is_routine_squash_merge(args: &[String]) -> bool {
    let mut pull_request: Option<String> = None;
    let mut repository: Option<String> = None;
    let mut squash = false;
    let mut delete_branch = false;
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        let delete_state = boolean_option_token_state(argument, "--delete-branch");
        if argument == "--squash" {
            if squash {
                return false;
            }
            squash = true;
        } else if delete_state != "absent" {
            if delete_state == "invalid" || delete_branch {
                return false;
            }
            delete_branch = true;
        } else if argument == "--repo" || argument == "-R" {
            if repository.is_some() || index + 1 >= args.len() {
                return false;
            }
            index += 1;
            repository = Some(args[index].clone());
            if !is_static_repository(&args[index]) {
                return false;
            }
        } else if argument.starts_with("--repo=") || argument.starts_with("-R=") {
            if repository.is_some() {
                return false;
            }
            let v = argument
                .split_once('=')
                .map(|x| x.1)
                .unwrap_or("")
                .to_string();
            repository = Some(v.clone());
            if !is_static_repository(&v) {
                return false;
            }
        } else if pull_request.is_none() && is_positive_pull_request(argument) {
            pull_request = Some(argument.clone());
        } else {
            return false;
        }
        index += 1;
    }
    pull_request.is_some() && squash
}

const ROUTINE_SQUASH_MERGE_DETAIL: &str =
    "The command performs a numeric, non-privileged squash merge and may clean up its merged head branch.";

/// `classify_pr_merge` (github_routine_merge.py:102).
fn classify_pr_merge(tail: &[String]) -> GitHubCommandAssessment {
    if is_routine_squash_merge(tail) {
        return assessment(
            Cap::RoutineMergeRemote,
            "github.command.pr-routine-squash-merge",
            ROUTINE_SQUASH_MERGE_DETAIL,
        );
    }
    let admin_state = boolean_option_state(tail, "--admin");
    let delete_state = boolean_option_state(tail, "--delete-branch");
    if admin_state == "invalid" {
        return assessment(
            Cap::Unknown,
            "github.command.invalid-admin-option",
            "The administrator merge option has an invalid Boolean value.",
        );
    }
    if delete_state == "invalid" {
        return assessment(
            Cap::Unknown,
            "github.command.invalid-delete-branch-option",
            "The delete-branch option has an invalid Boolean value.",
        );
    }
    let admin_merge = admin_state == "true";
    let merge_capability = if admin_merge {
        Cap::AdminMergeRemote
    } else {
        Cap::MergeRemote
    };
    let mut capabilities = vec![merge_capability];
    if delete_state == "true" {
        capabilities.push(Cap::DeleteRemote);
    }
    github_assessment(
        &capabilities,
        if admin_merge {
            "github.command.pr-admin-merge"
        } else {
            "github.command.pr-merge"
        },
        if admin_merge {
            "The command uses administrator privileges to merge a pull request."
        } else {
            "The command merges a pull request and may also delete its branch."
        },
    )
}

// ---------------------------------------------------------------------------
// github_auth_capabilities.py (:1-41)
// ---------------------------------------------------------------------------

pub fn classify_github_auth(normalized: &[String]) -> Option<GitHubCommandAssessment> {
    if normalized.len() < 2 || normalized[0].to_lowercase() != "auth" {
        return None;
    }
    let sub = normalized[1].to_lowercase();
    let tail = &normalized[2.min(normalized.len())..];
    if sub == "token"
        || (sub == "status" && (has_option(tail, "--show-token") || has_option(tail, "-t")))
    {
        return Some(assessment(
            Cap::SecretRemote,
            "github.command.auth-token-read",
            "The command reads a GitHub authentication token.",
        ));
    }
    if sub == "status" {
        return Some(assessment(
            Cap::ReadRemote,
            "github.command.local-auth-read",
            "The command reads local CLI auth state.",
        ));
    }
    if ["login", "logout", "switch", "refresh", "setup-git"].contains(&sub.as_str()) {
        return Some(assessment(
            Cap::WriteLocal,
            "github.command.local-auth-write",
            "The command changes local GitHub CLI authentication.",
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// github_rest_capabilities.py
// ---------------------------------------------------------------------------

const API_OPTIONS_WITH_VALUES: &[&str] = &[
    "--cache",
    "--field",
    "--header",
    "--hostname",
    "--input",
    "--jq",
    "--method",
    "--preview",
    "--raw-field",
    "--template",
    "-F",
    "-H",
    "-X",
    "-f",
    "-h",
    "-p",
];
const API_BOOLEAN_OPTIONS: &[&str] = &[
    "--include",
    "--paginate",
    "--silent",
    "--slurp",
    "--verbose",
    "-i",
];
const API_VALUE_PREFIXES: &[&str] = &["-f", "-F", "-H", "-X", "-h", "-p"];

fn method_override_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)x-http-method-override\s*:").unwrap())
}
fn safe_accept_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\Aaccept\s*:\s*application/vnd\.github(?:\+[a-z0-9.+-]+|\.[a-z0-9.+-]+)\z")
            .unwrap()
    })
}
fn safe_api_version_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\Ax-github-api-version\s*:\s*[0-9]{4}-[0-9]{2}-[0-9]{2}\z").unwrap()
    })
}
fn static_endpoint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A[A-Za-z0-9_./{}:+,@=?&-]+\z").unwrap())
}
fn pr_head_oid_endpoint_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\Arepos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commits/\$\(gh pr view [1-9][0-9]* --json headRefOid --jq \.headRefOid\)/check-runs(?:\?[A-Za-z0-9_.=&-]+)?\z").unwrap()
    })
}
fn bare_variable_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").unwrap())
}

#[derive(Default)]
struct ApiArgs {
    endpoint: Option<String>,
    method: Option<String>,
    fields: Vec<(String, String)>,
    headers: Vec<String>,
    has_input: bool,
    has_dynamic_option_value: bool,
}

/// `_api_parse_failure` (:382).
fn api_parse_failure() -> GitHubCommandAssessment {
    assessment(
        Cap::Unknown,
        "github.api.unrecognized-arguments",
        "The GitHub API arguments cannot be classified statically.",
    )
}

/// `_value_is_dynamic` (:376).
fn value_is_dynamic(value: &str, allow_bare_variables: bool) -> bool {
    for marker in ["$(", "`", "${", "$'", "$\""] {
        if value.contains(marker) {
            return true;
        }
    }
    allow_bare_variables && bare_variable_re().is_match(value)
}

/// `_field_value_is_external` (:368).
fn field_value_is_external(value: &str, allow_graphql_variables: bool) -> bool {
    let stripped = value.trim();
    stripped.starts_with('@') || value_is_dynamic(stripped, !allow_graphql_variables)
}

/// `_parse_api_arguments` (:214-282).
fn parse_api_arguments(args: &[String]) -> Result<ApiArgs, GitHubCommandAssessment> {
    let mut endpoint: Option<String> = None;
    let mut method: Option<String> = None;
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut headers: Vec<String> = Vec::new();
    let mut has_input = false;
    let mut has_dynamic_option_value = false;
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--" {
            index += 1;
            if index >= args.len() || endpoint.is_some() {
                return Err(api_parse_failure());
            }
            endpoint = Some(args[index].clone());
            index += 1;
            if index != args.len() {
                return Err(api_parse_failure());
            }
            break;
        }
        let (mut option_name, mut separator, mut attached_value) = match token.find('=') {
            Some(p) => (token[..p].to_string(), true, token[p + 1..].to_string()),
            None => (token.clone(), false, String::new()),
        };
        if !separator && token.len() > 2 && API_VALUE_PREFIXES.contains(&&token[..2]) {
            option_name = token[..2].to_string();
            separator = true;
            attached_value = token[2..].to_string();
        }
        if API_BOOLEAN_OPTIONS.contains(&option_name.as_str()) {
            if separator {
                return Err(api_parse_failure());
            }
            index += 1;
            continue;
        }
        if API_OPTIONS_WITH_VALUES.contains(&option_name.as_str()) {
            let (value, consumed) = if separator {
                (attached_value.clone(), 1usize)
            } else if index + 1 < args.len() {
                (args[index + 1].clone(), 2usize)
            } else {
                return Err(api_parse_failure());
            };
            if option_name == "-X" || option_name == "--method" {
                method = Some(value.clone());
                has_dynamic_option_value =
                    has_dynamic_option_value || value_is_dynamic(&value, true);
            } else if option_name == "-f"
                || option_name == "-F"
                || option_name == "--field"
                || option_name == "--raw-field"
            {
                let (name, field_sep, field_value) = match value.find('=') {
                    Some(p) => (value[..p].to_string(), true, value[p + 1..].to_string()),
                    None => (value.clone(), false, String::new()),
                };
                if !field_sep || name.is_empty() {
                    return Err(api_parse_failure());
                }
                fields.push((name, field_value));
            } else if option_name == "-H" || option_name == "--header" {
                headers.push(value.clone());
                has_dynamic_option_value =
                    has_dynamic_option_value || value_is_dynamic(&value, true);
            } else if option_name == "--input" {
                has_input = true;
            } else if value_is_dynamic(&value, true) {
                has_dynamic_option_value = true;
            }
            index += consumed;
            continue;
        }
        if token.starts_with('-') || endpoint.is_some() {
            return Err(api_parse_failure());
        }
        endpoint = Some(token.clone());
        index += 1;
    }
    if endpoint.is_none() {
        return Err(api_parse_failure());
    }
    Ok(ApiArgs {
        endpoint,
        method,
        fields,
        headers,
        has_input,
        has_dynamic_option_value,
    })
}

fn segments_of(endpoint: &str) -> Vec<String> {
    endpoint
        .split('?')
        .next()
        .unwrap_or("")
        .trim_matches('/')
        .to_lowercase()
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn contains_segment(segments: &[String], s: &str) -> bool {
    segments.iter().any(|x| x == s)
}

fn last_segment_is(segments: &[String], s: &str) -> bool {
    segments.last().map(|x| x.as_str()) == Some(s)
}

/// `_is_merge_endpoint` (:157).
fn is_merge_endpoint(segments: &[String]) -> bool {
    contains_segment(segments, "merges")
        || (contains_segment(segments, "pulls") && last_segment_is(segments, "merge"))
}

/// `_is_workflow_endpoint` (:161).
fn is_workflow_endpoint(segments: &[String]) -> bool {
    if let Some(ci) = segments.iter().position(|s| s == "contents") {
        let end = (ci + 3).min(segments.len());
        if segments[ci + 1..end] == [".github", "workflows"] {
            return true;
        }
    }
    if contains_segment(segments, "actions") || contains_segment(segments, "workflows") {
        return segments.iter().any(|s| {
            [
                "cancel",
                "disable",
                "dispatches",
                "enable",
                "rerun",
                "rerun-failed-jobs",
            ]
            .contains(&s.as_str())
        });
    }
    segments.len() >= 4 && segments[0] == "repos" && segments[3] == "dispatches"
}

/// `_is_publish_endpoint` (:174).
fn is_publish_endpoint(segments: &[String]) -> bool {
    contains_segment(segments, "releases") || contains_segment(segments, "release-assets")
}

/// `_is_runner_token_endpoint` (:178).
fn is_runner_token_endpoint(segments: &[String]) -> bool {
    contains_segment(segments, "runners")
        && (last_segment_is(segments, "registration-token")
            || last_segment_is(segments, "remove-token"))
}

/// `_is_access_endpoint` (:182).
fn is_access_endpoint(segments: &[String]) -> bool {
    [
        "collaborators",
        "memberships",
        "permissions",
        "protection",
        "rulesets",
    ]
    .iter()
    .any(|m| contains_segment(segments, m))
        || segments
            .iter()
            .any(|s| ["deployments", "hooks", "keys", "transfer"].contains(&s.as_str()))
}

/// `_is_repository_endpoint` (:189).
fn is_repository_endpoint(segments: &[String]) -> bool {
    segments.len() == 3 && segments[0] == "repos"
}

/// `_is_force_request` (:193).
fn is_force_request(segments: &[String], fields: &[(String, String)]) -> bool {
    contains_segment(segments, "refs")
        && fields.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("force") && value.eq_ignore_ascii_case("true")
        })
}

/// `_is_content_endpoint` (:197).
fn is_content_endpoint(segments: &[String]) -> bool {
    if let Some(ci) = segments.iter().position(|s| s == "contents") {
        let end = (ci + 3).min(segments.len());
        return segments[ci + 1..end] != [".github", "workflows"];
    }
    [
        "comments",
        "discussions",
        "gists",
        "issues",
        "labels",
        "milestones",
        "pulls",
    ]
    .iter()
    .any(|m| contains_segment(segments, m))
}

/// `_is_issue_lock_endpoint` (:204).
fn is_issue_lock_endpoint(segments: &[String]) -> bool {
    segments.len() == 6
        && segments[0] == "repos"
        && segments[3] == "issues"
        && segments[5] == "lock"
}

/// `_mutation_capabilities` (:124).
fn mutation_capabilities(parsed: &ApiArgs, method: &str) -> Vec<Cap> {
    let segments = segments_of(parsed.endpoint.as_deref().unwrap_or(""));
    let mut capabilities: Vec<Cap> = Vec::new();
    let issue_lock_endpoint = is_issue_lock_endpoint(&segments);
    let maintenance_endpoint = issue_lock_endpoint && (method == "PUT" || method == "DELETE");
    if method == "DELETE" && !maintenance_endpoint {
        capabilities.push(Cap::DeleteRemote);
    }
    if is_merge_endpoint(&segments) {
        capabilities.push(Cap::MergeRemote);
    }
    if is_workflow_endpoint(&segments) {
        capabilities.push(Cap::WorkflowRemote);
    }
    if is_publish_endpoint(&segments) {
        capabilities.push(Cap::PublishRemote);
    }
    if segments.iter().any(|s| s == "secrets") || is_runner_token_endpoint(&segments) {
        capabilities.push(Cap::SecretRemote);
    }
    if is_access_endpoint(&segments) || (method == "PATCH" && is_repository_endpoint(&segments)) {
        capabilities.push(Cap::AccessRemote);
    }
    if is_force_request(&segments, &parsed.fields) {
        capabilities.push(Cap::ForceRemote);
    }
    if is_content_endpoint(&segments) && !is_merge_endpoint(&segments) && !issue_lock_endpoint {
        capabilities.push(Cap::ContentRemote);
    }
    if maintenance_endpoint {
        capabilities.push(Cap::MaintainRemote);
    }
    if capabilities.is_empty() {
        capabilities.push(Cap::MutateRemote);
    }
    capabilities
}

/// `_mutation_reason` (:208) — reason is derived from the uncanonicalized tuple.
fn mutation_reason(capabilities: &[Cap]) -> String {
    if capabilities.len() != 1 {
        return "github.api.mixed-mutation".to_string();
    }
    format!(
        "github.api.{}",
        capabilities[0]
            .as_str()
            .replace("_remote", "")
            .replace('_', "-")
    )
}

/// `classify_github_api` (:60-121).
pub fn classify_github_api(args: &[String]) -> GitHubCommandAssessment {
    let parsed = match parse_api_arguments(args) {
        Ok(p) => p,
        Err(a) => return a,
    };
    let endpoint = parsed.endpoint.as_deref().unwrap_or("");
    if (!static_endpoint_re().is_match(endpoint) && !pr_head_oid_endpoint_re().is_match(endpoint))
        || endpoint.starts_with('-')
    {
        return assessment(
            Cap::Unknown,
            "github.api.dynamic-endpoint",
            "The GitHub API endpoint cannot be resolved statically.",
        );
    }
    if parsed.has_input {
        return assessment(
            Cap::Unknown,
            "github.api.input-body",
            "A GitHub API body loaded from a file or standard input cannot be classified statically.",
        );
    }
    if parsed.has_dynamic_option_value {
        return assessment(
            Cap::Unknown,
            "github.api.dynamic-option-value",
            "A GitHub API option value cannot be resolved statically.",
        );
    }
    if parsed
        .headers
        .iter()
        .any(|h| method_override_header_re().is_match(h))
    {
        return assessment(
            Cap::Unknown,
            "github.api.method-override",
            "An HTTP method-override header prevents reliable API capability classification.",
        );
    }
    if parsed
        .headers
        .iter()
        .any(|h| !safe_accept_header_re().is_match(h) && !safe_api_version_header_re().is_match(h))
    {
        return assessment(
            Cap::Unknown,
            "github.api.untrusted-header",
            "Only static GitHub Accept media-type headers qualify for prompt-free API reads.",
        );
    }
    let method = parsed.method.as_deref().map(|m| m.to_uppercase());
    if endpoint.eq_ignore_ascii_case("graphql") {
        return classify_graphql(&parsed, method.as_deref(), args);
    }
    if parsed
        .fields
        .iter()
        .any(|(_n, v)| field_value_is_external(v, false))
    {
        return assessment(
            Cap::Unknown,
            "github.api.external-field-value",
            "A GitHub API field loaded from external data cannot be classified statically.",
        );
    }
    let method = method.unwrap_or_else(|| {
        if parsed.fields.is_empty() {
            "GET".to_string()
        } else {
            "POST".to_string()
        }
    });
    if method == "GET" || method == "HEAD" {
        return assessment(
            Cap::ReadRemote,
            "github.api.proven-get",
            "The GitHub API request is a statically proven read.",
        );
    }
    let capabilities = mutation_capabilities(&parsed, &method);
    github_assessment(
        &capabilities,
        &mutation_reason(&capabilities),
        "The GitHub API request performs a statically classified remote mutation.",
    )
}

/// `_classify_graphql` (:285).
fn classify_graphql(
    parsed: &ApiArgs,
    method: Option<&str>,
    raw_args: &[String],
) -> GitHubCommandAssessment {
    if method.is_some() {
        return assessment(
            Cap::Unknown,
            "github.graphql.method-override",
            "A GraphQL method override prevents reliable operation classification.",
        );
    }
    let query_values: Vec<&str> = parsed
        .fields
        .iter()
        .filter(|(n, _)| n == "query")
        .map(|(_, v)| v.as_str())
        .collect();
    if query_values.len() != 1 {
        return assessment(
            Cap::Unknown,
            "github.graphql.query-count",
            "Exactly one static GraphQL query is required for classification.",
        );
    }
    if parsed
        .fields
        .iter()
        .any(|(n, v)| field_value_is_external(v, n == "query"))
    {
        return assessment(
            Cap::Unknown,
            "github.graphql.external-value",
            "GraphQL query or variable data loaded from an external source cannot be classified statically.",
        );
    }
    if parsed.headers.is_empty()
        && routine_review_thread_arguments_are_static(raw_args)
        && is_routine_review_thread_resolution(query_values[0], &parsed.fields)
    {
        return assessment(
            Cap::RoutineReviewThreadRemote,
            "github.graphql.routine-review-thread-resolution",
            "The command resolves one statically bounded pull-request review thread.",
        );
    }
    classify_graphql_document(query_values[0])
}

/// `_routine_review_thread_arguments_are_static` (:326).
fn routine_review_thread_arguments_are_static(args: &[String]) -> bool {
    if args.is_empty() || !args[0].eq_ignore_ascii_case("graphql") {
        return false;
    }
    let mut index = 1;
    let mut field_names: Vec<String> = Vec::new();
    let mut jq_count = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--jq" {
            jq_count += 1;
            if jq_count > 1 || index + 1 >= args.len() || args[index + 1] != ".data" {
                return false;
            }
            index += 2;
            continue;
        }
        if let Some(v) = token.strip_prefix("--jq=") {
            jq_count += 1;
            if jq_count > 1 || v != ".data" {
                return false;
            }
            index += 1;
            continue;
        }
        let (mut option_name, mut separator, mut attached_value) = match token.find('=') {
            Some(p) => (token[..p].to_string(), true, token[p + 1..].to_string()),
            None => (token.clone(), false, String::new()),
        };
        if !separator && token.len() > 2 && &token[..2] == "-f" {
            option_name = "-f".to_string();
            separator = true;
            attached_value = token[2..].to_string();
        }
        if !["-f", "--field", "--raw-field"].contains(&option_name.as_str()) {
            return false;
        }
        let value = if separator {
            index += 1;
            attached_value.clone()
        } else if index + 1 < args.len() {
            index += 2;
            args[index - 1].clone()
        } else {
            return false;
        };
        let (name, field_sep, _field_value) = match value.find('=') {
            Some(p) => (value[..p].to_string(), true, value[p + 1..].to_string()),
            None => (value.clone(), false, String::new()),
        };
        if !field_sep || (name != "query" && name != "threadId") {
            return false;
        }
        field_names.push(name);
    }
    field_names.iter().filter(|n| n.as_str() == "query").count() == 1
        && field_names
            .iter()
            .filter(|n| n.as_str() == "threadId")
            .count()
            <= 1
}

// ---------------------------------------------------------------------------
// github_graphql_capabilities.py
// ---------------------------------------------------------------------------

const MAINTENANCE_MUTATIONS: &[&str] = &[
    "minimizeComment",
    "resolveReviewThread",
    "unminimizeComment",
    "unresolveReviewThread",
];
const MERGE_MUTATIONS: &[&str] = &[
    "disablePullRequestAutoMerge",
    "enablePullRequestAutoMerge",
    "mergePullRequest",
    "updatePullRequestBranch",
];
const CONTENT_MUTATIONS: &[&str] = &[
    "addComment",
    "addProjectV2DraftIssue",
    "addProjectV2ItemById",
    "addPullRequestReview",
    "addPullRequestReviewComment",
    "addPullRequestReviewThread",
    "closeDiscussion",
    "closeIssue",
    "convertPullRequestToDraft",
    "createDiscussion",
    "createIssue",
    "createPullRequest",
    "markDiscussionCommentAsAnswer",
    "markPullRequestReadyForReview",
    "reopenDiscussion",
    "reopenIssue",
    "submitPullRequestReview",
    "unmarkDiscussionCommentAsAnswer",
    "updateDiscussion",
    "updateDiscussionComment",
    "updateIssue",
    "updateIssueComment",
    "updateProjectV2ItemFieldValue",
    "updatePullRequest",
    "updatePullRequestReview",
    "updatePullRequestReviewComment",
];

const REVIEW_THREAD_SELECTION: &str = "(?:id\\s+isResolved|isResolved\\s+id|id|isResolved)";

fn routine_review_thread_literal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r#"\A\s*mutation\s*\{{\s*resolveReviewThread\s*\(\s*input\s*:\s*\{{\s*threadId\s*:\s*"PRRT_[A-Za-z0-9_-]{{8,}}"\s*\}}\s*\)\s*\{{\s*thread\s*\{{\s*{REVIEW_THREAD_SELECTION}\s*\}}\s*\}}\s*\}}\s*\z"#
        ))
        .unwrap()
    })
}
fn routine_review_thread_variable_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r#"\A\s*mutation\s*\(\s*\$threadId\s*:\s*ID!\s*\)\s*\{{\s*resolveReviewThread\s*\(\s*input\s*:\s*\{{\s*threadId\s*:\s*\$threadId\s*\}}\s*\)\s*\{{\s*thread\s*\{{\s*{REVIEW_THREAD_SELECTION}\s*\}}\s*\}}\s*\}}\s*\z"#
        ))
        .unwrap()
    })
}
fn routine_review_thread_value_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\APRRT_[A-Za-z0-9_-]{8,}\z").unwrap())
}
fn graphql_alias_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?P<name>[_A-Za-z][_0-9A-Za-z]*)\s*:").unwrap())
}
fn word_re(word: &'static str) -> &'static Regex {
    static FRAGMENT: OnceLock<Regex> = OnceLock::new();
    static MUTATION: OnceLock<Regex> = OnceLock::new();
    let slot = if word == "fragment" {
        &FRAGMENT
    } else {
        &MUTATION
    };
    slot.get_or_init(|| Regex::new(&format!(r"\b{word}\b")).unwrap())
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Emulates Python `_GRAPHQL_NAME.match(document, index)` over `Vec<char>`:
/// leading `\b`, `[_A-Za-z][_0-9A-Za-z]*`, trailing boundary automatic.
fn name_match_at(chars: &[char], index: usize) -> Option<usize> {
    if index > 0 && is_word_char(chars[index - 1]) {
        return None;
    }
    let c = *chars.get(index)?;
    if !(c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    let mut end = index + 1;
    while end < chars.len() && is_word_char(chars[end]) {
        end += 1;
    }
    Some(end)
}

/// `classify_graphql_document` (:74).
pub fn classify_graphql_document(document: &str) -> GitHubCommandAssessment {
    let sanitized = strip_strings_and_comments(document);
    let suspicious_aliases: Vec<String> = graphql_alias_re()
        .captures_iter(&sanitized)
        .filter_map(|c| c.name("name").map(|m| m.as_str().to_string()))
        .filter(|n| {
            let l = n.to_lowercase();
            l.contains("mutation") || l.contains("subscription")
        })
        .collect();
    if !suspicious_aliases.is_empty() {
        return assessment(
            Cap::Unknown,
            "github.graphql.suspicious-alias",
            "A GraphQL alias resembles an operation type and is not classified automatically.",
        );
    }
    let has_fragment_definition = word_re("fragment").is_match(&sanitized);
    if has_fragment_definition && word_re("mutation").is_match(&sanitized) {
        return assessment(
            Cap::MutateRemote,
            "github.graphql.remote-mutation",
            "GraphQL mutations with fragment definitions require confirmation.",
        );
    }
    let operations = match top_level_operations(&sanitized) {
        Some(o) => o,
        None => {
            return assessment(
                Cap::Unknown,
                "github.graphql.invalid-document",
                "The GraphQL document is not balanced.",
            )
        }
    };
    if operations.is_empty() {
        return assessment(
            Cap::Unknown,
            "github.graphql.missing-operation",
            "No static GraphQL operation was found.",
        );
    }
    if operations.len() != 1 {
        return assessment(
            Cap::Unknown,
            "github.graphql.multiple-operations",
            "Multiple GraphQL operations or a batched document cannot be classified automatically.",
        );
    }
    let operation = operations[0].as_str();
    if operation == "mutation" {
        let root_fields = root_fields_of(&sanitized);
        let mut capabilities: Vec<Cap> = root_fields
            .unwrap_or_default()
            .iter()
            .flat_map(|f| graphql_mutation_capabilities(f))
            .collect();
        if has_fragment_definition || capabilities.is_empty() {
            capabilities = vec![Cap::MutateRemote];
        }
        let mut uniq = capabilities.clone();
        uniq.sort();
        uniq.dedup();
        let reason = if uniq.len() > 1 {
            "github.graphql.mixed-mutation".to_string()
        } else {
            graphql_reason(capabilities[0])
        };
        return github_assessment(
            &capabilities,
            &reason,
            "The GraphQL operation contains statically classified mutation root fields.",
        );
    }
    if operation == "subscription" {
        return assessment(
            Cap::MutateRemote,
            "github.graphql.remote-mutation",
            "The GraphQL operation can change or subscribe to GitHub-hosted state.",
        );
    }
    assessment(
        Cap::ReadRemote,
        "github.graphql.proven-query",
        "The GraphQL document is a single static query.",
    )
}

/// `_graphql_mutation_capabilities` (:137).
fn graphql_mutation_capabilities(field: &str) -> Vec<Cap> {
    if MAINTENANCE_MUTATIONS.contains(&field) {
        return vec![Cap::MaintainRemote];
    }
    if MERGE_MUTATIONS.contains(&field) {
        return vec![Cap::MergeRemote];
    }
    if CONTENT_MUTATIONS.contains(&field) {
        return vec![Cap::ContentRemote];
    }
    let lowered = field.to_lowercase();
    let mut capabilities = Vec::new();
    if lowered.starts_with("delete") || lowered.starts_with("remove") {
        capabilities.push(Cap::DeleteRemote);
    }
    if ["secret", "token"].iter().any(|m| lowered.contains(m)) {
        capabilities.push(Cap::SecretRemote);
    }
    if ["collaborator", "deploykey", "permission", "repository"]
        .iter()
        .any(|m| lowered.contains(m))
    {
        capabilities.push(Cap::AccessRemote);
    }
    if lowered.contains("workflow") {
        capabilities.push(Cap::WorkflowRemote);
    }
    if lowered.contains("release") {
        capabilities.push(Cap::PublishRemote);
    }
    if capabilities.is_empty() {
        capabilities.push(Cap::MutateRemote);
    }
    capabilities
}

/// `is_routine_review_thread_resolution` (:159).
pub fn is_routine_review_thread_resolution(document: &str, fields: &[(String, String)]) -> bool {
    let query_fields: Vec<&str> = fields
        .iter()
        .filter(|(n, _)| n == "query")
        .map(|(_, v)| v.as_str())
        .collect();
    if query_fields.len() != 1 || query_fields[0] != document {
        return false;
    }
    if routine_review_thread_literal_re().is_match(document) {
        return fields.len() == 1;
    }
    let thread_ids: Vec<&str> = fields
        .iter()
        .filter(|(n, _)| n == "threadId")
        .map(|(_, v)| v.as_str())
        .collect();
    routine_review_thread_variable_re().is_match(document)
        && fields.len() == 2
        && thread_ids.len() == 1
        && routine_review_thread_value_re().is_match(thread_ids[0])
}

/// `_graphql_reason` (:179).
fn graphql_reason(capability: Cap) -> String {
    format!(
        "github.graphql.{}",
        capability.as_str().replace("_remote", "").replace('_', "-")
    )
}

/// `_root_fields` (:183).
fn root_fields_of(document: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = document.chars().collect();
    let selection = selection_start(&chars)?;
    let mut fields: Vec<String> = Vec::new();
    let mut depth = 1i32;
    let mut parenthesis_depth = 0i32;
    let mut index = selection + 1;
    while index < chars.len() && depth > 0 {
        let character = chars[index];
        if character == '(' {
            parenthesis_depth += 1;
            index += 1;
            continue;
        }
        if character == ')' {
            if parenthesis_depth == 0 {
                return None;
            }
            parenthesis_depth -= 1;
            index += 1;
            continue;
        }
        if character == '{' {
            depth += 1;
            index += 1;
            continue;
        }
        if character == '}' {
            depth -= 1;
            index += 1;
            continue;
        }
        if depth != 1 || parenthesis_depth != 0 || character.is_whitespace() || character == ',' {
            index += 1;
            continue;
        }
        if chars[index..].starts_with(&['.', '.', '.']) {
            return None;
        }
        let name_end = name_match_at(&chars, index)?;
        let mut field_name: String = chars[index..name_end].iter().collect();
        index = name_end;
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index < chars.len() && chars[index] == ':' {
            index += 1;
            while index < chars.len() && chars[index].is_whitespace() {
                index += 1;
            }
            let field_end = name_match_at(&chars, index)?;
            field_name = chars[index..field_end].iter().collect();
            index = field_end;
        }
        fields.push(field_name);
    }
    if depth != 0 || parenthesis_depth != 0 {
        return None;
    }
    Some(fields)
}

/// `_selection_start` (:238).
fn selection_start(chars: &[char]) -> Option<usize> {
    let mut parenthesis_depth = 0i32;
    for (index, character) in chars.iter().enumerate() {
        if *character == '(' {
            parenthesis_depth += 1;
        } else if *character == ')' {
            if parenthesis_depth == 0 {
                return None;
            }
            parenthesis_depth -= 1;
        } else if *character == '{' && parenthesis_depth == 0 {
            return Some(index);
        }
    }
    None
}

/// `_top_level_operations` (:252).
fn top_level_operations(document: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = document.chars().collect();
    let mut operations: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut pending_definition = false;
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '{' {
            if depth == 0 {
                if !pending_definition {
                    operations.push("query".to_string());
                }
                pending_definition = false;
            }
            depth += 1;
            index += 1;
            continue;
        }
        if character == '}' {
            if depth == 0 {
                return None;
            }
            depth -= 1;
            index += 1;
            continue;
        }
        if depth == 0 {
            if let Some(end) = name_match_at(&chars, index) {
                let name: String = chars[index..end].iter().collect();
                let name = name.to_lowercase();
                if name == "query" || name == "mutation" || name == "subscription" {
                    operations.push(name);
                    pending_definition = true;
                } else if name == "fragment" {
                    pending_definition = true;
                }
                index = end;
                continue;
            }
        }
        index += 1;
    }
    if depth == 0 {
        Some(operations)
    } else {
        None
    }
}

/// `_strip_strings_and_comments` (:288) — char-exact port.
fn strip_strings_and_comments(document: &str) -> String {
    let chars: Vec<char> = document.chars().collect();
    let mut output: Vec<char> = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index..].starts_with(&['"', '"', '"']) {
            let mut end = index + 3;
            loop {
                if end + 3 > chars.len() {
                    return String::new();
                }
                if chars[end..].starts_with(&['"', '"', '"']) {
                    break;
                }
                end += 1;
            }
            output.resize(output.len() + (end + 3 - index), ' ');
            index = end + 3;
            continue;
        }
        let character = chars[index];
        if character == '"' {
            output.push(' ');
            index += 1;
            let mut escaped = false;
            while index < chars.len() {
                let current = chars[index];
                output.push(' ');
                index += 1;
                if escaped {
                    escaped = false;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '"' {
                    break;
                }
            }
            continue;
        }
        if character == '#' {
            while index < chars.len() && chars[index] != '\r' && chars[index] != '\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        output.push(character);
        index += 1;
    }
    output.into_iter().collect()
}

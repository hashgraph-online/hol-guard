//! What each native rule detector's reply looks like, and the checks of its
//! own finding fields: the rule id, the path and any extra field to store.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use super::{relative_path, rule_text, Row};

const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_CHARS: usize = 4096;

pub(super) struct Spec {
    pub(super) detector: &'static str,
    pub(super) result_schema: &'static str,
    /// The coverage key that holds the scan summary.
    pub(super) summary_key: &'static str,
    /// The coverage reason a reply that is not complete adds.
    pub(super) incomplete_reason: &'static str,
    pub(super) counters: &'static [&'static str],
    /// The counter that is zero when the worktree has nothing to check.
    pub(super) inputs_counter: &'static str,
    pub(super) skip_kinds: &'static [&'static str],
    /// Checks the detector's own fields, including the rule id and path, and
    /// returns the extra fields to store, or `None` for a malformed finding.
    pub(super) finding_fields: fn(&Row) -> Option<Row>,
    /// A strict reply must carry valid scan counts, its skipped counts and its
    /// truncation reasons; otherwise a missing count reads as zero.
    pub(super) strict_counts: bool,
}

const FILE_SKIPS: &[&str] = &["oversize", "not_text", "unread", "linked"];
const PARSED_FILE_SKIPS: &[&str] = &["oversize", "not_text", "unparsed", "unread", "linked"];

static SPECS: [Spec; 7] = [
    Spec {
        detector: "skill_content_v1",
        result_schema: "guard.workspace-skills.v1",
        summary_key: "skills",
        incomplete_reason: "skills_incomplete",
        counters: &["files_scanned", "bytes_scanned"],
        inputs_counter: "files_scanned",
        skip_kinds: FILE_SKIPS,
        finding_fields: skill_fields,
        strict_counts: false,
    },
    Spec {
        detector: "mcp_config_v1",
        result_schema: "guard.workspace-mcp-config.v1",
        summary_key: "mcp_config",
        incomplete_reason: "mcp_config_incomplete",
        counters: &["servers_scanned"],
        inputs_counter: "servers_scanned",
        skip_kinds: &["oversize"],
        finding_fields: mcp_fields,
        strict_counts: false,
    },
    Spec {
        detector: "hook_config_v1",
        result_schema: "guard.workspace-hooks.v1",
        summary_key: "hook_config",
        incomplete_reason: "hook_config_incomplete",
        counters: &["files_scanned", "commands_scanned"],
        inputs_counter: "files_scanned",
        skip_kinds: PARSED_FILE_SKIPS,
        finding_fields: hook_fields,
        strict_counts: false,
    },
    Spec {
        detector: "plugin_manifest_v1",
        result_schema: "guard.workspace-plugins.v1",
        summary_key: "plugin_manifest",
        incomplete_reason: "plugin_manifest_incomplete",
        counters: &[
            "plugins_scanned",
            "files_scanned",
            "commands_scanned",
            "servers_scanned",
        ],
        inputs_counter: "plugins_scanned",
        skip_kinds: &["oversize", "not_text", "unparsed", "unread"],
        finding_fields: plugin_fields,
        strict_counts: false,
    },
    Spec {
        detector: "ci_workflow_v1",
        result_schema: "guard.workspace-workflows.v1",
        summary_key: "ci_workflow",
        incomplete_reason: "ci_workflow_incomplete",
        counters: &["files_scanned"],
        inputs_counter: "files_scanned",
        skip_kinds: FILE_SKIPS,
        finding_fields: workflow_fields,
        strict_counts: true,
    },
    Spec {
        detector: "editor_task_v1",
        result_schema: "guard.workspace-editor-tasks.v1",
        summary_key: "editor_task",
        incomplete_reason: "editor_task_incomplete",
        counters: &["files_scanned"],
        inputs_counter: "files_scanned",
        skip_kinds: PARSED_FILE_SKIPS,
        finding_fields: editor_task_fields,
        strict_counts: true,
    },
    Spec {
        detector: "instruction_file_v1",
        result_schema: "guard.workspace-instructions.v1",
        summary_key: "instruction_file",
        incomplete_reason: "instruction_file_incomplete",
        counters: &["files_scanned"],
        inputs_counter: "files_scanned",
        skip_kinds: FILE_SKIPS,
        finding_fields: instruction_fields,
        strict_counts: true,
    },
];

pub(super) fn spec(detector: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.detector == detector)
}

/// `<prefix>[a-z0-9.-]{1,120}`, the rule ids a family of shared rules uses.
fn is_rule_id(value: Option<&Value>, prefix: &str) -> bool {
    value
        .and_then(Value::as_str)
        .and_then(|rule_id| rule_id.strip_prefix(prefix))
        .is_some_and(|rest| {
            (1..=120).contains(&rest.len())
                && rest.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'-')
                })
        })
}

/// `[A-Za-z0-9_.:-]{1,64}`: a hook event or server name.
fn event_name(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|name| {
        (1..=64).contains(&name.len())
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            })
    })
}

fn rule_id_in(item: &Row, rule_ids: &[&str]) -> bool {
    item.get("rule_id")
        .and_then(Value::as_str)
        .is_some_and(|rule_id| rule_ids.contains(&rule_id))
}

/// A string path within the native snapshot's byte bound.
fn bounded_path(item: &Row) -> Option<&str> {
    item.get("path")
        .and_then(Value::as_str)
        .filter(|path| path.len() <= MAX_PATH_BYTES)
}

/// No folder separator and no NUL: one file name in its folder.
fn is_file_name(text: &str) -> bool {
    !text.contains(['/', '\0'])
}

fn skill_fields(item: &Row) -> Option<Row> {
    // A normalized root-relative `.../SKILL.md` path.
    let path = relative_path(item.get("path"))?;
    let skill = path
        .rsplit_once('/')
        .is_some_and(|(_, name)| name == "SKILL.md");
    (is_rule_id(item.get("rule_id"), "skill.") && skill).then(Row::new)
}

fn mcp_fields(item: &Row) -> Option<Row> {
    if !is_rule_id(item.get("rule_id"), "mcp.config.") || relative_path(item.get("path")).is_none()
    {
        return None;
    }
    let server = rule_text(item.get("server"))?;
    Some([("server".to_owned(), json!(server))].into_iter().collect())
}

const HOOK_FILES: [&str; 9] = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".codex/config.toml",
    ".codex/hooks.json",
    ".cursor/hooks.json",
    ".devin/config.json",
    ".devin/config.local.json",
    ".devin/hooks.v1.json",
    ".gemini/settings.json",
];

fn hook_fields(item: &Row) -> Option<Row> {
    // One of the root-level hook configuration files the native check reads,
    // or `.github/hooks/[^/\\\0]{0,250}.json`.
    let is_hook_file = item
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(|path| {
            HOOK_FILES.contains(&path)
                || path
                    .strip_prefix(".github/hooks/")
                    .and_then(|rest| rest.strip_suffix(".json"))
                    .is_some_and(|stem| {
                        stem.chars().count() <= 250 && !stem.contains(['/', '\\', '\0'])
                    })
        });
    let event = event_name(item.get("event"))?;
    (is_rule_id(item.get("rule_id"), "hook.config.") && is_hook_file)
        .then(|| [("event".to_owned(), json!(event))].into_iter().collect())
}

fn plugin_fields(item: &Row) -> Option<Row> {
    let (component, prefix, name_field) = match item.get("kind").and_then(Value::as_str)? {
        "hook" => ("hook", "hook.config.", "event"),
        "mcp_server" => ("mcp_server", "mcp.config.", "server"),
        _ => return None,
    };
    let name = event_name(item.get("name"))?;
    (is_rule_id(item.get("rule_id"), prefix) && is_plugin_file(item.get("path"))).then(|| {
        [
            ("component".to_owned(), json!(component)),
            (name_field.to_owned(), json!(name)),
        ]
        .into_iter()
        .collect()
    })
}

/// A root-relative manifest or plugin hook or MCP file the native check keeps.
fn is_plugin_file(value: Option<&Value>) -> bool {
    let Some(path) = value.and_then(Value::as_str) else {
        return false;
    };
    if !(1..=MAX_PATH_CHARS).contains(&path.chars().count())
        || !path.chars().all(crate::hermes_printable::is_printable)
        || path.contains('\\')
    {
        return false;
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return false;
    }
    let Some(&name) = parts.last() else {
        return false;
    };
    let directory = parts.len().checked_sub(2).map(|index| parts[index]);
    name == "gemini-extension.json"
        || (name == "plugin.json" && matches!(directory, Some(".claude-plugin" | ".codex-plugin")))
        || (name == ".mcp.json" && directory.is_some())
        || (directory == Some("hooks") && name.ends_with(".json"))
}

fn workflow_fields(item: &Row) -> Option<Row> {
    const RULE_IDS: [&str; 3] = [
        "ci.workflow.untrusted-checkout",
        "ci.workflow.write-all-permissions",
        "ci.workflow.unpinned-action",
    ];
    // Any `.yml` or `.yaml` file directly in the root workflows directory.
    let workflow = bounded_path(item)
        .and_then(|path| path.strip_prefix(".github/workflows/"))
        .is_some_and(|file| {
            is_file_name(file) && (file.ends_with(".yml") || file.ends_with(".yaml"))
        });
    (rule_id_in(item, &RULE_IDS) && workflow).then(Row::new)
}

fn editor_task_fields(item: &Row) -> Option<Row> {
    // Each rule reads one kind of file.
    let path = bounded_path(item)?;
    let known = match item.get("rule_id").and_then(Value::as_str)? {
        "editor.task.folder-open" => {
            path == ".vscode/tasks.json"
                || (is_file_name(path) && path.ends_with(".code-workspace"))
        }
        "devcontainer.initialize-command" => {
            path == ".devcontainer.json"
                || path == ".devcontainer/devcontainer.json"
                || path
                    .strip_prefix(".devcontainer/")
                    .and_then(|rest| rest.strip_suffix("/devcontainer.json"))
                    .is_some_and(|folder| !folder.is_empty() && is_file_name(folder))
        }
        _ => false,
    };
    known.then(Row::new)
}

// The files the native scan reads, compared without regard to case. Each
// folder is one non-empty segment without a backslash.
static INSTRUCTION_PATH: LazyLock<Regex> = LazyLock::new(|| {
    let folders = r"(?:[^/\\\x00]+/)*";
    let file = r"[^/\\\x00]";
    Regex::new(&format!(
        r"(?i)^(?:{folders}(?:agents|agents\.override|claude|claude\.local|gemini)\.md|agent\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.github/copilot-instructions\.md|{folders}\.cursor/rules/{folders}{file}*\.mdc?|\.windsurf/rules/{folders}{file}+\.md|\.github/instructions/{folders}{file}+\.instructions\.md|\.kiro/steering/{folders}{file}+\.md|\.clinerules/{folders}{file}+\.md)$"
    ))
    .expect("instruction file path pattern compiles")
});

fn instruction_fields(item: &Row) -> Option<Row> {
    const RULE_IDS: [&str; 4] = [
        "instruction.approval-bypass",
        "instruction.guard-bypass",
        "instruction.hide-actions",
        "instruction.unicode-controls",
    ];
    let path = relative_path(item.get("path"))?;
    (rule_id_in(item, &RULE_IDS) && path.len() <= MAX_PATH_BYTES && INSTRUCTION_PATH.is_match(path))
        .then(Row::new)
}

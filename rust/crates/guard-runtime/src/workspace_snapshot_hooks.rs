//! Agent hook commands a project configures, checked over the bytes a
//! workspace snapshot hashed.
//!
//! Claude Code, Codex, Cursor, Gemini, Devin and Copilot each run shell
//! commands a project lists in its hook configuration, on their own and
//! without asking: at session start, around each tool call or when the agent
//! stops. Every command runs the shared `hook_config_risk` rules. A reported
//! finding carries the rule's fixed wording, the root-relative path of the
//! configuration file and the hook event, never the command.
//!
//! Only the configuration files agents read at the worktree root are checked.
//! A file the scan could not read in full leaves it incomplete: one larger
//! than the configuration bound, one that is not UTF-8 or does not parse, one
//! the snapshot left out, or a symlink or special file where a configuration
//! could be. PowerShell commands are not read.

use guard_command::hook_config_risk::detect_hook_config_risk;
use guard_command::jsonc::loads_jsonc;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-hooks.v1";
/// Moves whenever a rule is added, removed or changed, so a stored result
/// names the rule set that produced it.
pub(super) const DETECTOR_VERSION: &str = "hook-config-v1";
pub(super) const MAX_HOOK_FINDINGS: usize = 200;
/// Larger than any hand-written agent configuration.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// Hook commands checked in one worktree.
const MAX_COMMANDS: usize = 512;
pub(super) const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_EVENT_CHARS: usize = 64;
const FINDING_ID_HEX_CHARS: usize = 32;
/// Hook configuration files agents read from the worktree root.
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
/// Copilot reads every JSON file directly in this directory.
const COPILOT_HOOK_DIRECTORY: &str = ".github/hooks";
/// Directories whose link would hide a hook configuration.
const HOOK_DIRECTORIES: [&str; 7] = [
    ".claude",
    ".codex",
    ".cursor",
    ".devin",
    ".gemini",
    ".github",
    COPILOT_HOOK_DIRECTORY,
];

struct Finding {
    rule_id: &'static str,
    category: &'static str,
    severity: &'static str,
    confidence: &'static str,
    title: &'static str,
    reason: &'static str,
    false_positive_hint: Option<&'static str>,
    path: String,
    event: String,
}

/// One hook command: a shell command line, or a program with `args`.
pub(super) struct Command<'a> {
    pub(super) event: &'a str,
    pub(super) text: &'a str,
    pub(super) args: Option<Vec<String>>,
}

impl Command<'_> {
    /// The executable and arguments together, as held to the command bound.
    pub(super) fn bytes(&self) -> usize {
        self.text.len()
            + self
                .args
                .as_deref()
                .map_or(0, |args| args.iter().map(String::len).sum())
    }
}

#[derive(Default)]
pub(super) struct HookScan {
    worktree_key: String,
    /// Keyed by finding id, so a rule repeated in one event is one finding.
    findings: BTreeMap<String, Finding>,
    files_scanned: usize,
    commands_scanned: usize,
    skipped_oversize: usize,
    skipped_not_text: usize,
    skipped_unparsed: usize,
    unread: usize,
    linked: usize,
    command_oversize: bool,
    command_cap_hit: bool,
    finding_cap_hit: bool,
    path_too_long: bool,
}

impl HookScan {
    pub(super) fn new(worktree_key: &str) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            ..Self::default()
        }
    }

    /// Whether `relative` is a hook configuration this scan must read.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if !is_hook_file(relative) {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted configuration unread (oversize, byte
    /// budget, unreadable or unstable), so its hooks were never checked.
    pub(super) fn left_unread(&mut self) {
        self.unread += 1;
    }

    /// The snapshot did not follow the symlink or special file at `relative`.
    /// The scan cannot say it saw every hook when a configuration could sit
    /// there or below it.
    pub(super) fn left_unfollowed(&mut self, relative: &str) {
        if is_hook_file(relative) || HOOK_DIRECTORIES.contains(&relative) {
            self.linked += 1;
        }
    }

    /// Check every hook command in the exact bytes hashed for `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        if content.len() > MAX_CONFIG_BYTES {
            self.skipped_oversize += 1;
            return;
        }
        let Ok(text) = std::str::from_utf8(content) else {
            self.skipped_not_text += 1;
            return;
        };
        let document = if relative.ends_with(".toml") {
            toml::from_str::<toml::Value>(text)
                .ok()
                .and_then(|value| serde_json::to_value(value).ok())
        } else {
            loads_jsonc(text).ok()
        };
        let Some(document) = document else {
            self.skipped_unparsed += 1;
            return;
        };
        self.files_scanned += 1;
        for command in hook_commands(relative, &document) {
            if self.commands_scanned >= MAX_COMMANDS {
                self.command_cap_hit = true;
                return;
            }
            if command.bytes() > MAX_COMMAND_BYTES {
                self.command_oversize = true;
                continue;
            }
            self.commands_scanned += 1;
            let event = stored_event(command.event);
            for rule in detect_hook_config_risk(command.text, command.args.as_deref()) {
                let finding_id = self.finding_id(rule.id, relative, event);
                if self.findings.contains_key(&finding_id) {
                    continue;
                }
                if self.findings.len() >= MAX_HOOK_FINDINGS {
                    self.finding_cap_hit = true;
                    return;
                }
                self.findings.insert(
                    finding_id,
                    Finding {
                        rule_id: rule.id,
                        category: rule.category,
                        severity: rule.severity,
                        confidence: rule.confidence,
                        title: rule.title,
                        reason: rule.reason,
                        false_positive_hint: rule.false_positive_hint,
                        path: relative.to_owned(),
                        event: event.to_owned(),
                    },
                );
            }
        }
    }

    fn finding_id(&self, rule_id: &str, path: &str, event: &str) -> String {
        let mut hasher = Sha256::new();
        for part in [
            "guard.workspace-finding.v1",
            self.worktree_key.as_str(),
            "hook",
            rule_id,
            path,
            event,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\0");
        }
        let mut id = hex::encode(hasher.finalize());
        id.truncate(FINDING_ID_HEX_CHARS);
        id
    }

    /// `incomplete_reasons` names the snapshot limits that may have hidden a
    /// configuration from the walk; the scan is incomplete under any of them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        for (hit, reason) in [
            (self.finding_cap_hit, "max_findings"),
            (self.command_cap_hit, "max_commands"),
            (self.command_oversize, "command_oversize"),
            (self.path_too_long, "path_too_long"),
            (self.skipped_oversize > 0, "hook_config_oversize"),
            (self.skipped_not_text > 0, "hook_config_not_text"),
            (self.skipped_unparsed > 0, "hook_config_unparsed"),
            (self.unread > 0, "hook_config_unread"),
            (self.linked > 0, "hook_config_linked"),
        ] {
            if hit {
                truncation.push(reason);
            }
        }
        truncation.sort_unstable();
        truncation.dedup();
        let mut findings: Vec<(&String, &Finding)> = self.findings.iter().collect();
        findings.sort_by(|(_, a), (_, b)| {
            (&a.path, &a.event, a.rule_id).cmp(&(&b.path, &b.event, b.rule_id))
        });
        let findings: Vec<Value> = findings
            .into_iter()
            .map(|(finding_id, finding)| {
                json!({
                    "finding_id": finding_id,
                    "rule_id": finding.rule_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "title": finding.title,
                    "reason": finding.reason,
                    "false_positive_hint": finding.false_positive_hint,
                    "path": finding.path,
                    "event": finding.event,
                })
            })
            .collect();
        json!({
            "schema": RESULT_SCHEMA,
            "detector_version": DETECTOR_VERSION,
            "status": if truncation.is_empty() { "complete" } else { "incomplete" },
            "files_scanned": self.files_scanned,
            "commands_scanned": self.commands_scanned,
            "skipped": {
                "oversize": self.skipped_oversize,
                "not_text": self.skipped_not_text,
                "unparsed": self.skipped_unparsed,
                "unread": self.unread,
                "linked": self.linked,
            },
            "truncation_reasons": truncation,
            "findings": findings,
        })
    }
}

fn is_hook_file(relative: &str) -> bool {
    HOOK_FILES.contains(&relative)
        || relative
            .strip_prefix(COPILOT_HOOK_DIRECTORY)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|name| name.ends_with(".json") && !name.contains('/'))
}

/// Every hook command in a configuration document. Hooks sit under a `hooks`
/// object keyed by event. Only Devin's `hooks.v1.json` and Copilot's hook
/// files may instead be keyed by event at the top level; in a settings file
/// other top-level lists are not hooks. Each event lists entries that carry a
/// command themselves or a nested `hooks` list of them.
fn hook_commands<'a>(relative: &str, document: &'a Value) -> Vec<Command<'a>> {
    let flat = relative == ".devin/hooks.v1.json"
        || relative
            .strip_prefix(COPILOT_HOOK_DIRECTORY)
            .is_some_and(|rest| rest.starts_with('/'));
    let events = match (document.get("hooks"), document) {
        (Some(Value::Object(events)), _) => events,
        (None, Value::Object(events)) if flat => events,
        _ => return Vec::new(),
    };
    event_commands(events)
}

/// Every hook command in an object keyed by hook event.
pub(super) fn event_commands(events: &Map<String, Value>) -> Vec<Command<'_>> {
    let mut commands = Vec::new();
    for (event, entries) in events {
        let Value::Array(entries) = entries else {
            continue;
        };
        for entry in entries {
            push_entry(event, entry, true, &mut commands);
        }
    }
    commands
}

fn push_entry<'a>(event: &'a str, entry: &'a Value, nested: bool, out: &mut Vec<Command<'a>>) {
    match entry {
        Value::String(text) => out.push(Command {
            event,
            text,
            args: None,
        }),
        Value::Object(fields) => {
            if let Some(Value::String(text)) = fields.get("command") {
                let args = fields.get("args").and_then(Value::as_array).map(|args| {
                    args.iter()
                        .filter_map(|arg| arg.as_str().map(str::to_owned))
                        .collect()
                });
                out.push(Command { event, text, args });
            }
            if let Some(Value::String(text)) = fields.get("bash") {
                out.push(Command {
                    event,
                    text,
                    args: None,
                });
            }
            if let (true, Some(Value::Array(inner))) = (nested, fields.get("hooks")) {
                for entry in inner {
                    push_entry(event, entry, false, out);
                }
            }
        }
        _ => {}
    }
}

/// The event name as stored: a hook event identifier, or `other` for a key
/// that is not one, since the configuration file chooses it.
pub(super) fn stored_event(event: &str) -> &str {
    let identifier = !event.is_empty()
        && event.len() <= MAX_EVENT_CHARS
        && event
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
    if identifier {
        event
    } else {
        "other"
    }
}

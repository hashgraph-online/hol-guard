//! Checking a plugin's hooks and MCP servers once its files are parsed.

use std::collections::{BTreeMap, BTreeSet};

use guard_command::hook_config_risk::{detect_hook_config_risk, HookConfigRule};
use guard_command::jsonc::loads_jsonc;
use guard_command::mcp_config_risk::{detect_mcp_config_risk, McpConfigRule};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::super::hooks::{event_commands, stored_event, MAX_COMMAND_BYTES};
use super::{Kept, Kind, DETECTOR_VERSION, MAX_PLUGIN_FINDINGS, RESULT_SCHEMA};

const MAX_COMMANDS: usize = 512;
const MAX_SERVERS: usize = 512;
const MAX_ARGS: usize = 256;
const MAX_SERVER_TEXT: usize = 8 * 1024;
const FINDING_ID_HEX_CHARS: usize = 32;
/// Fields that name a remote MCP server's endpoint.
const URL_FIELDS: [&str; 3] = ["url", "httpUrl", "serverUrl"];

/// The fixed wording both rule sets share.
struct Rule {
    id: &'static str,
    category: &'static str,
    severity: &'static str,
    confidence: &'static str,
    title: &'static str,
    reason: &'static str,
    false_positive_hint: Option<&'static str>,
}

impl From<HookConfigRule> for Rule {
    fn from(rule: HookConfigRule) -> Self {
        let HookConfigRule {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        } = rule;
        Self {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        }
    }
}

impl From<McpConfigRule> for Rule {
    fn from(rule: McpConfigRule) -> Self {
        let McpConfigRule {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        } = rule;
        Self {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        }
    }
}

struct Finding {
    rule: Rule,
    path: String,
    kind: Kind,
    name: String,
}

#[derive(Default)]
pub(super) struct Run<'a> {
    worktree_key: &'a str,
    pub(super) truncation: BTreeSet<&'a str>,
    /// Keyed by finding id, so a rule repeated for one hook event or server is
    /// one finding.
    findings: BTreeMap<String, Finding>,
    pub(super) plugins_scanned: usize,
    files_scanned: usize,
    commands_scanned: usize,
    servers_scanned: usize,
    oversize: usize,
    not_text: usize,
    unparsed: usize,
    unread: usize,
}

impl<'a> Run<'a> {
    pub(super) fn new(worktree_key: &'a str, truncation: BTreeSet<&'a str>) -> Self {
        Self {
            worktree_key,
            truncation,
            ..Self::default()
        }
    }

    pub(super) fn document(&mut self, kept: &Kept) -> Option<Value> {
        let (count, reason) = match kept {
            Kept::Text(text) => match loads_jsonc(text) {
                Ok(document) => {
                    self.files_scanned += 1;
                    return Some(document);
                }
                Err(_) => (&mut self.unparsed, "plugin_file_unparsed"),
            },
            Kept::Oversize => (&mut self.oversize, "plugin_file_oversize"),
            Kept::NotText => (&mut self.not_text, "plugin_file_not_text"),
            Kept::Unread => (&mut self.unread, "plugin_file_unread"),
        };
        *count += 1;
        self.truncation.insert(reason);
        None
    }

    /// Check a hooks document or an MCP server map, inline in a manifest or
    /// as a file. Either may wrap its entries in `hooks` or `mcpServers`.
    pub(super) fn check(&mut self, path: &str, kind: Kind, document: &Value) {
        let wrapper = match kind {
            Kind::Hook => "hooks",
            Kind::McpServer => "mcpServers",
        };
        let entries = match (document.get(wrapper), document) {
            (Some(Value::Object(entries)), _) | (None, Value::Object(entries)) => entries,
            _ => return,
        };
        match kind {
            Kind::Hook => self.check_hooks(path, entries),
            Kind::McpServer => self.check_servers(path, entries),
        }
    }

    fn check_hooks(&mut self, path: &str, events: &Map<String, Value>) {
        for command in event_commands(events) {
            if self.commands_scanned >= MAX_COMMANDS {
                self.truncation.insert("max_commands");
                return;
            }
            if command.bytes() > MAX_COMMAND_BYTES {
                self.truncation.insert("command_oversize");
                continue;
            }
            self.commands_scanned += 1;
            let event = stored_event(command.event);
            for rule in detect_hook_config_risk(command.text, command.args.as_deref()) {
                self.add(rule.into(), path, Kind::Hook, event);
            }
        }
    }

    fn check_servers(&mut self, path: &str, servers: &Map<String, Value>) {
        for (name, server) in servers {
            let Value::Object(fields) = server else {
                continue;
            };
            if self.servers_scanned >= MAX_SERVERS {
                self.truncation.insert("max_servers");
                return;
            }
            let command = fields.get("command").and_then(Value::as_str);
            let args: Vec<String> = fields
                .get("args")
                .and_then(Value::as_array)
                .map(|args| {
                    args.iter()
                        .filter_map(|arg| arg.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let url = URL_FIELDS
                .iter()
                .find_map(|field| fields.get(*field).and_then(Value::as_str));
            let oversize = args.len() > MAX_ARGS
                || command
                    .into_iter()
                    .chain(url)
                    .chain(args.iter().map(String::as_str))
                    .any(|text| text.len() > MAX_SERVER_TEXT);
            if oversize {
                self.truncation.insert("server_oversize");
                continue;
            }
            self.servers_scanned += 1;
            let name = stored_event(name);
            for rule in detect_mcp_config_risk(command, &args, url) {
                self.add(rule.into(), path, Kind::McpServer, name);
            }
        }
    }

    fn add(&mut self, rule: Rule, path: &str, kind: Kind, name: &str) {
        let finding_id = self.finding_id(rule.id, path, kind, name);
        if self.findings.contains_key(&finding_id) {
            return;
        }
        if self.findings.len() >= MAX_PLUGIN_FINDINGS {
            self.truncation.insert("max_findings");
            return;
        }
        self.findings.insert(
            finding_id,
            Finding {
                rule,
                path: path.to_owned(),
                kind,
                name: name.to_owned(),
            },
        );
    }

    fn finding_id(&self, rule_id: &str, path: &str, kind: Kind, name: &str) -> String {
        let mut hasher = Sha256::new();
        for part in [
            "guard.workspace-finding.v1",
            self.worktree_key,
            "plugin",
            kind.as_str(),
            rule_id,
            path,
            name,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\0");
        }
        let mut id = hex::encode(hasher.finalize());
        id.truncate(FINDING_ID_HEX_CHARS);
        id
    }

    pub(super) fn into_value(self) -> Value {
        let mut findings: Vec<(&String, &Finding)> = self.findings.iter().collect();
        findings.sort_by(|(_, a), (_, b)| {
            (&a.path, a.kind, &a.name, a.rule.id).cmp(&(&b.path, b.kind, &b.name, b.rule.id))
        });
        let findings: Vec<Value> = findings
            .into_iter()
            .map(|(finding_id, finding)| {
                json!({
                    "finding_id": finding_id,
                    "rule_id": finding.rule.id,
                    "category": finding.rule.category,
                    "severity": finding.rule.severity,
                    "confidence": finding.rule.confidence,
                    "title": finding.rule.title,
                    "reason": finding.rule.reason,
                    "false_positive_hint": finding.rule.false_positive_hint,
                    "path": finding.path,
                    "kind": finding.kind.as_str(),
                    "name": finding.name,
                })
            })
            .collect();
        json!({
            "schema": RESULT_SCHEMA,
            "detector_version": DETECTOR_VERSION,
            "status": if self.truncation.is_empty() { "complete" } else { "incomplete" },
            "plugins_scanned": self.plugins_scanned,
            "files_scanned": self.files_scanned,
            "commands_scanned": self.commands_scanned,
            "servers_scanned": self.servers_scanned,
            "skipped": {
                "oversize": self.oversize,
                "not_text": self.not_text,
                "unparsed": self.unparsed,
                "unread": self.unread,
            },
            "truncation_reasons": self.truncation.into_iter().collect::<Vec<_>>(),
            "findings": findings,
        })
    }
}

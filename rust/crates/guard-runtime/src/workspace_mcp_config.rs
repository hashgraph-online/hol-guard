//! `mcp-config-assess --stdin`: check the MCP servers a worktree configures
//! for risky launch settings.
//!
//! The caller sends the worktree root, as named and with links followed, and
//! every MCP server its harness adapters found, with the absolute path of the
//! file that configures it. Only servers whose file sits inside a root are
//! checked, so a server from the user's home or a global configuration never
//! becomes a finding about the repository. The rules are the shared
//! [`guard_command::mcp_config_risk`] set. Each finding carries the rule's
//! fixed wording, the path and the server name, never the command or URL, so
//! nothing from the configuration is stored beyond where it lives.
//!
//! The command reads no files and starts no processes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use guard_command::mcp_config_risk::detect_mcp_config_risk;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::inventory_scan_targets_op::relative_to;

pub(crate) const COMMAND: &str = "mcp-config-assess";
pub(crate) const FEATURE: &str = "mcp-config-assess-v1";
const REQUEST_SCHEMA: &str = "guard.workspace-mcp-config-request.v1";
const RESULT_SCHEMA: &str = "guard.workspace-mcp-config.v1";
const FINDING_ID_DOMAIN: &str = "guard.workspace-mcp-config.v1";

const MAX_ROOTS: usize = 2;
const MAX_SERVERS: usize = 512;
const MAX_ARGS: usize = 256;
const MAX_TEXT: usize = 8_192;
/// A finding repeats the path and server name, so they are held to what the
/// Python side stores.
const MAX_PATH: usize = 4_096;
const MAX_NAME: usize = 1_024;
const MAX_FINDINGS: usize = 200;

#[cfg(test)]
#[path = "workspace_mcp_config_tests.rs"]
mod tests;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    roots: Vec<String>,
    servers: Vec<ServerInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerInput {
    config_path: String,
    server: String,
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    url: Option<String>,
}

impl ServerInput {
    fn within_bounds(&self) -> bool {
        self.args.len() <= MAX_ARGS
            && self.server.len() <= MAX_NAME
            && std::iter::once(&self.config_path)
                .chain(&self.command)
                .chain(&self.args)
                .chain(&self.url)
                .all(|text| text.len() <= MAX_TEXT)
    }
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| "mcp_config_request_invalid".to_owned())?;
    Ok(match assess(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

fn assess(request: &Request) -> Result<Value, String> {
    if request.schema != REQUEST_SCHEMA {
        return Err("mcp_config_request_schema".to_owned());
    }
    let roots: Vec<String> = request
        .roots
        .iter()
        .map(|root| lexical(Path::new(root)))
        .collect();
    if roots.is_empty()
        || roots.len() > MAX_ROOTS
        || request
            .roots
            .iter()
            .any(|root| root.len() > MAX_TEXT || !Path::new(root).is_absolute())
    {
        return Err("mcp_config_request_roots".to_owned());
    }
    let mut truncation = BTreeSet::new();
    let mut findings = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let (mut considered, mut scanned, mut oversize) = (0_usize, 0_usize, 0_usize);
    // Servers configured outside the worktree are dropped before any bound
    // applies, so a large home or global configuration never leaves a
    // repository's check incomplete.
    for server in &request.servers {
        let Some(path) = root_relative(&server.config_path, &roots) else {
            continue;
        };
        considered += 1;
        if considered > MAX_SERVERS {
            truncation.insert("max_servers");
            break;
        }
        if !server.within_bounds() || path.len() > MAX_PATH {
            oversize += 1;
            truncation.insert("server_oversize");
            continue;
        }
        if !seen.insert((path.clone(), server.server.as_str())) {
            continue;
        }
        scanned += 1;
        let rules = detect_mcp_config_risk(
            server.command.as_deref(),
            &server.args,
            server.url.as_deref(),
        );
        for rule in rules {
            let finding_id = finding_id(rule.id, &path, &server.server);
            if !findings.contains_key(&finding_id) && findings.len() >= MAX_FINDINGS {
                truncation.insert("max_findings");
                break;
            }
            findings.insert(
                finding_id.clone(),
                json!({
                    "finding_id": finding_id,
                    "rule_id": rule.id,
                    "category": rule.category,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "title": rule.title,
                    "reason": rule.reason,
                    "false_positive_hint": rule.false_positive_hint,
                    "path": path,
                    "server": server.server,
                }),
            );
        }
    }
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "status": if truncation.is_empty() { "complete" } else { "incomplete" },
        "servers_scanned": scanned,
        "skipped": {"oversize": oversize},
        "truncation_reasons": truncation.into_iter().collect::<Vec<_>>(),
        "findings": findings.into_values().collect::<Vec<_>>(),
    }))
}

/// The configuration file's path below one of `roots`, or `None` outside
/// them. Compared without following links, so a linked configuration is named
/// where the worktree keeps it.
fn root_relative(config_path: &str, roots: &[String]) -> Option<String> {
    let path = Path::new(config_path);
    if !path.is_absolute() {
        return None;
    }
    let path = lexical(path);
    roots
        .iter()
        .find_map(|root| relative_to(&path, root))
        .filter(|relative| relative != ".")
}

/// `os.path.normpath` for an absolute path: `.` dropped and `..` applied.
fn lexical(path: &Path) -> String {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    normal.to_string_lossy().into_owned()
}

fn finding_id(rule_id: &str, path: &str, server: &str) -> String {
    let mut digest = Sha256::new();
    for part in [FINDING_ID_DOMAIN, rule_id, path, server] {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())[..32].to_owned()
}

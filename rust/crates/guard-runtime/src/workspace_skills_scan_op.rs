//! `workspace-skills-scan --stdin`: the SKILL.md files an install leaves in a
//! workspace, described and risk-scanned, the retired Python
//! `scan_workspace_skills` body.
//!
//! The scan looks for `SKILL.md` at any depth under `.codex/skills`,
//! `.agents/skills` and `skills` in the workspace, each root in turn and each
//! root's files in path order. A skill is read as UTF-8 text with invalid
//! bytes replaced and line endings folded to `\n`, as a text-mode read gives
//! it. Two ops share the walk:
//!
//! - `list` answers `{skills: [path, ...]}`, so the caller can look up what
//!   it stored for each (the snapshot store stays Python's);
//! - `scan` takes `stored`, the identity hash the caller holds per skill path,
//!   and answers `{results, snapshots}`. A skill whose identity matches its
//!   stored hash is skipped. Every other skill's identity and firewall
//!   metadata become a snapshot for the caller to save, and a skill with risk
//!   signals becomes a `scanned` result. A skill the runtime could not
//!   describe or scan is an `unscanned` result with no snapshot, so the next
//!   install scans it again.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::mcp_skill_firewall::evaluate_firewall_evidence;
use guard_command::skill_content_risk::detect_skill_content_risk;
use guard_contracts::McpFirewallInputV1;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::runner_authority_detector::SKILL_CONTENT_MAX_BYTES;

const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const SKILL_FILE: &str = "SKILL.md";
const SKILL_ROOTS: [&[&str]; 3] = [&[".codex", "skills"], &[".agents", "skills"], &["skills"]];
const RESULT_INVALID: &str = "native_mcp_tool_evidence_result_invalid";
const TOO_LARGE: &str = "native_runner_authority_request_too_large";

pub(crate) fn is_command(command: &str) -> bool {
    command == "workspace-skills-scan"
}

#[derive(Deserialize)]
struct Request {
    op: String,
    workspace_dir: String,
    #[serde(default)]
    stored: BTreeMap<String, String>,
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name() == SKILL_FILE {
            found.push(path.clone());
        }
        // A link to a directory is not followed, as a recursive glob does not.
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            walk(&path, found);
        }
    }
}

/// Every skill document under the workspace's skill roots.
fn discover(workspace: &Path) -> Vec<PathBuf> {
    let mut all = Vec::new();
    for parts in SKILL_ROOTS {
        let root = parts
            .iter()
            .fold(workspace.to_path_buf(), |path, part| path.join(part));
        if !root.is_dir() {
            continue;
        }
        let mut found = Vec::new();
        walk(&root, &mut found);
        found.sort();
        all.extend(found);
    }
    all
}

/// A text-mode read: invalid UTF-8 replaced, `\r\n` and `\r` folded to `\n`.
fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

struct Described {
    identity_hash: String,
    identity: Value,
    firewall: Value,
}

/// A skill's identity and firewall metadata; `Ok(None)` when it has none.
fn describe(path: &Path, content: &str) -> Result<Option<Described>, String> {
    let name = path
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let input: McpFirewallInputV1 = serde_json::from_value(json!({
        "artifact_type": "skill",
        "name": name,
        "command": null,
        "config_path": text(path),
        "transport": null,
        "has_url": false,
        "args": [],
        "publisher": null,
        "server_name": null,
        "env": [],
        "mcp_server_identity": null,
        "mcp_tool_identity": null,
        "tool_schema": null,
        "tool_description": null,
        "tool_names": null,
        "tool_names_camel": null,
        "skill_content": content,
    }))
    .map_err(|_| RESULT_INVALID.to_owned())?;
    let answer = evaluate_firewall_evidence(&input).map_err(str::to_owned)?;
    let patch = match answer.get("metadata_patch") {
        None => return Err(RESULT_INVALID.to_owned()),
        Some(Value::Null) => return Ok(None),
        Some(Value::Object(patch)) => patch,
        Some(_) => return Err(RESULT_INVALID.to_owned()),
    };
    let (Some(identity), Some(firewall)) = (
        patch
            .get("mcp_skill_identity")
            .filter(|value| value.is_object()),
        patch
            .get("mcpSkillFirewall")
            .filter(|value| value.is_object()),
    ) else {
        return Err(RESULT_INVALID.to_owned());
    };
    let identity_hash = identity
        .get("identity_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| RESULT_INVALID.to_owned())?
        .to_owned();
    Ok(Some(Described {
        identity_hash,
        identity: identity.clone(),
        firewall: firewall.clone(),
    }))
}

fn unscanned(relative: &str, identity_hash: Option<&str>, error: &str) -> Value {
    json!({
        "skill_path": relative,
        "identity_hash": identity_hash,
        "status": "unscanned",
        "risk_count": null,
        "severities": [],
        "signal_ids": [],
        "scan_error": error,
    })
}

fn scan(workspace: &Path, stored: &BTreeMap<String, String>) -> Value {
    let mut results = Vec::new();
    let mut snapshots = Vec::new();
    for path in discover(workspace) {
        let Some(content) = read_text(&path) else {
            continue;
        };
        let relative = text(path.strip_prefix(workspace).unwrap_or(&path));
        let described = match describe(&path, &content) {
            Ok(Some(described)) => described,
            Ok(None) => continue,
            Err(error) => {
                results.push(unscanned(&relative, None, &error));
                continue;
            }
        };
        let path_text = text(&path);
        if stored.get(&path_text) == Some(&described.identity_hash) {
            continue;
        }
        if content.len() > SKILL_CONTENT_MAX_BYTES {
            results.push(unscanned(
                &relative,
                Some(&described.identity_hash),
                TOO_LARGE,
            ));
            continue;
        }
        let signals: Vec<Value> = detect_skill_content_risk(&content)
            .iter()
            .map(|signal| signal.to_value())
            .collect();
        snapshots.push(json!({
            "artifact_id": format!("skill-path:{path_text}"),
            "identity_hash": described.identity_hash,
            "payload": {
                "identity_hash": described.identity_hash,
                "skill_path": path_text,
                "mcp_skill_identity": described.identity,
                "mcpSkillFirewall": described.firewall,
            },
        }));
        if signals.is_empty() {
            continue;
        }
        let severities: BTreeSet<&str> = signals
            .iter()
            .filter_map(|signal| signal.get("severity").and_then(Value::as_str))
            .collect();
        let ids: Vec<&str> = signals
            .iter()
            .filter_map(|signal| signal.get("signal_id").and_then(Value::as_str))
            .collect();
        results.push(json!({
            "skill_path": relative,
            "identity_hash": described.identity_hash,
            "status": "scanned",
            "risk_count": signals.len(),
            "severities": severities,
            "signal_ids": ids,
        }));
    }
    json!({ "results": results, "snapshots": snapshots })
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "workspace_skills_scan_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("workspace_skills_scan_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "workspace_skills_scan_request_invalid".to_owned())?;
    let workspace = Path::new(&request.workspace_dir);
    if request.workspace_dir.is_empty()
        || request.workspace_dir.contains('\0')
        || !workspace.is_absolute()
    {
        return Err("workspace_skills_scan_request_invalid".to_owned());
    }
    let answer = match request.op.as_str() {
        "list" => {
            let skills: Vec<String> = discover(workspace).iter().map(|path| text(path)).collect();
            json!({ "skills": skills })
        }
        "scan" => scan(workspace, &request.stored),
        _ => return Err("workspace_skills_scan_request_invalid".to_owned()),
    };
    serde_json::to_vec(&answer)
        .map_err(|_| "workspace_skills_scan_response_encode_failed".to_owned())
}

#[cfg(test)]
#[path = "workspace_skills_scan_op_tests.rs"]
mod tests;

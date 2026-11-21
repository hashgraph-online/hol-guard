//! Read-only plans and post-removal verification for the ordered harness roster.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{
    absolute, invalid, split_candidates, sweep_results, Candidates, HarnessScope, MAX_CANDIDATES,
};
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_HARNESSES: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanRequest {
    home: String,
    workspace: Option<String>,
    harnesses: Vec<String>,
    active: Vec<String>,
}

pub(super) fn answer(request: &PlanRequest) -> Result<Value, String> {
    validate_roots(
        &request.home,
        request.workspace.as_deref(),
        request.harnesses.len(),
    )?;
    let active: HashSet<&str> = request.active.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut plans = Vec::new();
    for harness in &request.harnesses {
        if harness.is_empty() || !seen.insert(harness.as_str()) {
            return Err(invalid());
        }
        let (files, links) = discover(harness, &request.home, request.workspace.as_deref())?;
        let mut reasons = Vec::new();
        if active.contains(harness.as_str()) {
            reasons.push("managed_install");
        }
        let mut files_with_hooks = Vec::new();
        let mut hook_count = 0;
        for result in sweep_results(&files, &links, true).filter(|result| result.removed > 0) {
            files_with_hooks.push(result.path);
            hook_count += result.removed;
        }
        if hook_count > 0 {
            reasons.push("hooks_in_config");
        }
        if !reasons.is_empty() {
            plans.push(json!({
                "harness": harness,
                "reasons": reasons,
                "files_with_hooks": files_with_hooks,
                "hook_count": hook_count,
            }));
        }
    }
    Ok(json!({ "plans": plans }))
}

fn validate_roots(home: &str, workspace: Option<&str>, count: usize) -> Result<(), String> {
    absolute(home)?;
    workspace.map(absolute).transpose()?;
    if count > MAX_HARNESSES {
        return Err(invalid());
    }
    Ok(())
}

fn discover(
    harness: &str,
    home: &str,
    workspace: Option<&str>,
) -> Result<(Candidates, Candidates), String> {
    let scope = HarnessScope {
        harness: harness.to_owned(),
        home: home.to_owned(),
        workspace: workspace.map(str::to_owned),
    };
    let (candidates, roots) = scope.candidates()?;
    if candidates.len() > MAX_CANDIDATES {
        return Err(invalid());
    }
    Ok(split_candidates(candidates, &roots))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReportRequest {
    home: String,
    workspace: Option<String>,
    outcomes: Vec<HarnessOutcome>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessOutcome {
    harness: String,
    hook_count: u64,
    adapter_uninstall: UninstallStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum UninstallStatus {
    Ok,
    Error,
    Skipped,
}

pub(super) fn report(request: &ReportRequest) -> Result<Value, String> {
    validate_roots(
        &request.home,
        request.workspace.as_deref(),
        request.outcomes.len(),
    )?;
    let mut seen = HashSet::new();
    let mut remaining = Vec::new();
    let mut initial_count = 0_u64;
    let mut remaining_count = 0_u64;
    let mut affected_count = 0;
    for outcome in &request.outcomes {
        let harness = &outcome.harness;
        if harness.is_empty() || !seen.insert(harness) {
            return Err(invalid());
        }
        initial_count = initial_count
            .checked_add(outcome.hook_count)
            .ok_or_else(invalid)?;
        affected_count += usize::from(matches!(outcome.adapter_uninstall, UninstallStatus::Ok));
        let (files, links) = discover(harness, &request.home, request.workspace.as_deref())?;
        for item in sweep_results(&files, &links, true).filter(|item| item.removed > 0) {
            remaining_count += item.removed as u64;
            let path: PathBuf = Path::new(item.path).components().collect();
            remaining.push(json!({
                "harness": harness, "path": path, "hook_count": item.removed,
            }));
        }
    }
    let status = if remaining.is_empty() && affected_count == request.outcomes.len() {
        "removed"
    } else {
        "partial"
    };
    Ok(json!({
        "status": status,
        "remaining": remaining,
        "removed_hook_count": initial_count.saturating_sub(remaining_count),
        "affected_harness_count": affected_count,
    }))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::{run_command, SCHEMA};
    use super::*;

    fn claude_hook_fixture(settings: &Path) -> String {
        fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let original = json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{"type": "command", "command": "hol-guard hook --harness claude-code"}],
                }],
            },
        })
        .to_string();
        fs::write(settings, &original).unwrap();
        original
    }

    #[test]
    fn the_plan_keeps_roster_order_and_does_not_edit_hook_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let settings = root.join(".claude").join("settings.json");
        let original = claude_hook_fixture(&settings);
        let request = json!({
            "schema": SCHEMA,
            "op": "plan",
            "plan": {
                "home": root,
                "harnesses": ["grok", "claude-code", "muse"],
                "active": ["grok", "claude-code"],
            },
        })
        .to_string();
        let bytes = run_command(request.as_bytes()).unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result["plans"],
            json!([
                {"harness": "grok", "reasons": ["managed_install"], "files_with_hooks": [], "hook_count": 0},
                {"harness": "claude-code", "reasons": ["managed_install", "hooks_in_config"],
                    "files_with_hooks": [settings], "hook_count": 1},
            ]),
        );
        assert_eq!(fs::read_to_string(settings).unwrap(), original);
    }

    #[test]
    fn report_counts_remaining_hooks_and_adapter_errors_without_editing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let settings = root.join(".claude").join("settings.json");
        let original = claude_hook_fixture(&settings);
        let mut request = json!({
            "schema": SCHEMA,
            "op": "report",
            "report": {
                "home": root,
                "outcomes": [
                    {"harness": "grok", "hook_count": 1, "adapter_uninstall": "error"},
                    {"harness": "claude-code", "hook_count": 2, "adapter_uninstall": "ok"},
                ],
            },
        });
        let run = |request: &Value| -> Value {
            let bytes = run_command(request.to_string().as_bytes()).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        assert_eq!(
            run(&request),
            json!({
                "status": "partial",
                "removed_hook_count": 2,
                "affected_harness_count": 1,
                "remaining": [{"harness": "claude-code", "path": settings, "hook_count": 1}],
            }),
        );
        assert_eq!(fs::read_to_string(&settings).unwrap(), original);

        fs::write(settings, "{}").unwrap();
        let partial = run(&request);
        assert_eq!(partial["status"], "partial");
        assert_eq!(partial["remaining"], json!([]));
        request["report"]["outcomes"][0]["adapter_uninstall"] = json!("ok");
        assert_eq!(run(&request)["status"], "removed");
    }
}

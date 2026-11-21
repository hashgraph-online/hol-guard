//! Read-only hook removal plans for the ordered harness roster.

use std::collections::HashSet;

use super::{absolute, invalid, split_candidates, sweep_results, HarnessScope, MAX_CANDIDATES};
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
    absolute(&request.home)?;
    if let Some(workspace) = &request.workspace {
        absolute(workspace)?;
    }
    if request.harnesses.len() > MAX_HARNESSES {
        return Err(invalid());
    }
    let active: HashSet<&str> = request.active.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut plans = Vec::new();
    for harness in &request.harnesses {
        if harness.is_empty() || !seen.insert(harness.as_str()) {
            return Err(invalid());
        }
        let scope = HarnessScope {
            harness: harness.clone(),
            home: request.home.clone(),
            workspace: request.workspace.clone(),
        };
        let (candidates, roots) = scope.candidates()?;
        if candidates.len() > MAX_CANDIDATES {
            return Err(invalid());
        }
        let (files, links) = split_candidates(candidates, &roots);
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::{run_command, SCHEMA};
    use super::*;

    #[test]
    fn the_plan_keeps_roster_order_and_does_not_edit_hook_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let settings = root.join(".claude").join("settings.json");
        fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let original = json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{"type": "command", "command": "hol-guard hook --harness claude-code"}],
                }],
            },
        })
        .to_string();
        fs::write(&settings, &original).unwrap();
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
}

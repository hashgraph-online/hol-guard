use serde_json::{json, Value};

use super::*;

const FINDING_ID: &str = "0123456789abcdef0123456789abcdef";

fn empty_coverage() -> Value {
    json!({"status": "complete", "reasons": [], "detectors": {}})
}

fn finding_with(extra: Value) -> Value {
    let mut finding = json!({
        "finding_id": FINDING_ID,
        "rule_id": "skill.remote-fetch-exec",
        "category": "execution",
        "severity": "critical",
        "confidence": "strong",
        "title": "Skill downloads and runs remote code",
        "reason": "The skill tells the agent to pipe a download into a shell.",
        "false_positive_hint": null,
        "path": ".claude/skills/setup/SKILL.md",
    });
    for (key, value) in extra.as_object().expect("extra fields") {
        finding[key] = value.clone();
    }
    finding
}

fn skills(findings: Vec<Value>, extra: Value) -> Value {
    let mut result = json!({
        "schema": "guard.workspace-skills.v1",
        "status": "complete",
        "files_scanned": 1,
        "bytes_scanned": 90,
        "skipped": {},
        "truncation_reasons": [],
        "findings": findings,
    });
    for (key, value) in extra.as_object().expect("extra fields") {
        result[key] = value.clone();
    }
    result
}

fn run(coverage: Value, results: Value) -> (Vec<Value>, Value) {
    let answer = dispatch(&json!({"coverage": coverage, "results": results})).expect("answer");
    let findings = answer["findings"].as_array().expect("findings").clone();
    (findings, answer["coverage"].clone())
}

#[test]
fn a_well_formed_finding_is_a_stored_warning() {
    let (findings, coverage) = run(
        empty_coverage(),
        json!([[
            "skill_content_v1",
            skills(vec![finding_with(json!({}))], json!({}))
        ]]),
    );
    assert_eq!(
        findings,
        [json!({
            "finding_id": FINDING_ID,
            "source_kind": "workspace_source",
            "detector": "skill_content_v1",
            "severity": "critical",
            "decision": "warn",
            "ecosystem": null,
            "package_name": null,
            "package_version": null,
            "fix_version": null,
            "rule_ids": ["skill.remote-fetch-exec"],
            "advisory_ids": [],
            "path": ".claude/skills/setup/SKILL.md",
            "line": null,
            "category": "execution",
            "confidence": "strong",
            "title": "Skill downloads and runs remote code",
            "reason": "The skill tells the agent to pipe a download into a shell.",
            "false_positive_hint": null,
            "validation_state": "unvalidated",
            "lifecycle_state": "open",
        })]
    );
    assert_eq!(
        coverage,
        json!({
            "status": "complete",
            "reasons": [],
            "detectors": {"skill_content_v1": "complete"},
            "skills": {
                "files_scanned": 1,
                "bytes_scanned": 90,
                "skipped": {"oversize": 0, "not_text": 0, "unread": 0, "linked": 0},
                "truncation_reasons": [],
            },
        })
    );
}

#[test]
fn a_malformed_finding_is_dropped_and_leaves_the_detector_incomplete() {
    let bad = finding_with(json!({"finding_id": "not-an-id"}));
    let unprintable = finding_with(json!({"false_positive_hint": "line\nbreak"}));
    let result = skills(
        vec![finding_with(json!({})), bad, unprintable],
        json!({"truncation_reasons": ["zeta", "Bad!", "alpha", "zeta"]}),
    );
    let (findings, coverage) = run(empty_coverage(), json!([["skill_content_v1", result]]));
    assert_eq!(findings.len(), 1);
    assert_eq!(coverage["status"], json!("partial"));
    assert_eq!(coverage["reasons"], json!(["skills_incomplete"]));
    assert_eq!(
        coverage["detectors"]["skill_content_v1"],
        json!("incomplete")
    );
    assert_eq!(
        coverage["skills"]["truncation_reasons"],
        json!(["alpha", "invalid_finding", "zeta"])
    );
}

#[test]
fn findings_past_the_cap_are_dropped_and_a_capped_scan_names_the_finding_cap() {
    let many: Vec<Value> = (0..MAX_FINDINGS + 3)
        .map(|_| finding_with(json!({})))
        .collect();
    let result = skills(
        many,
        json!({"status": "incomplete", "truncation_reasons": ["max_findings"]}),
    );
    let coverage = json!({"status": "partial", "reasons": ["finding_cap"], "detectors": {"supply_chain": "complete"}});
    let (findings, coverage) = run(
        coverage,
        json!([
            ["skill_content_v1", result.clone()],
            ["skill_content_v1", result]
        ]),
    );
    assert_eq!(findings.len(), 2 * MAX_FINDINGS);
    assert_eq!(
        coverage["reasons"],
        json!(["finding_cap", "skills_incomplete", "skills_incomplete"])
    );
    assert_eq!(
        coverage["detectors"],
        json!({"supply_chain": "complete", "skill_content_v1": "incomplete"})
    );
    assert_eq!(
        coverage["skills"]["truncation_reasons"],
        json!(["invalid_finding", "max_findings"])
    );
}

#[test]
fn an_incomplete_reply_without_reasons_is_incomplete() {
    let result = skills(vec![], json!({"status": "incomplete"}));
    let (_, coverage) = run(empty_coverage(), json!([["skill_content_v1", result]]));
    assert_eq!(
        coverage["skills"]["truncation_reasons"],
        json!(["incomplete"])
    );
}

#[test]
fn a_strict_reply_needs_its_counts() {
    let workflows = |extra: Value| {
        let mut result = json!({
            "schema": "guard.workspace-workflows.v1",
            "status": "complete",
            "files_scanned": 2,
            "skipped": {},
            "truncation_reasons": [],
            "findings": [],
        });
        for (key, value) in extra.as_object().expect("extra fields") {
            result[key] = value.clone();
        }
        result
    };
    let (_, complete) = run(
        empty_coverage(),
        json!([["ci_workflow_v1", workflows(json!({}))]]),
    );
    assert_eq!(complete["detectors"]["ci_workflow_v1"], json!("complete"));
    let float: Value = serde_json::from_str("1.0").expect("float");
    for broken in [
        json!({"files_scanned": float}),
        json!({"files_scanned": true}),
        json!({"files_scanned": -1}),
        json!({"skipped": []}),
        json!({"truncation_reasons": null}),
    ] {
        let (_, coverage) = run(
            empty_coverage(),
            json!([["ci_workflow_v1", workflows(broken)]]),
        );
        assert_eq!(coverage["detectors"]["ci_workflow_v1"], json!("error"));
        assert_eq!(coverage["reasons"], json!(["ci_workflow_incomplete"]));
        assert!(coverage.get("ci_workflow").is_none());
    }
    // A lenient reply reads a missing or invalid count as zero.
    let (_, lenient) = run(
        empty_coverage(),
        json!([[
            "skill_content_v1",
            skills(vec![], json!({"files_scanned": 1.5, "skipped": []}))
        ]]),
    );
    assert_eq!(lenient["detectors"]["skill_content_v1"], json!("no_inputs"));
    assert_eq!(lenient["skills"]["files_scanned"], json!(0));
}

#[test]
fn an_unreadable_reply_is_an_error_but_keeps_its_findings() {
    let result = skills(
        vec![finding_with(json!({}))],
        json!({"schema": "guard.workspace-hooks.v1"}),
    );
    let (findings, coverage) = run(empty_coverage(), json!([["skill_content_v1", result]]));
    assert_eq!(findings.len(), 1);
    assert_eq!(coverage["detectors"]["skill_content_v1"], json!("error"));
    assert_eq!(coverage["reasons"], json!(["skills_incomplete"]));
}

#[test]
fn a_runtime_without_the_check_leaves_the_detector_not_run() {
    let (findings, coverage) = run(empty_coverage(), json!([["mcp_config_v1", null]]));
    assert!(findings.is_empty());
    assert_eq!(
        coverage,
        json!({"status": "partial", "reasons": ["detector_not_run:mcp_config_v1"], "detectors": {"mcp_config_v1": "not_run"}})
    );
}

#[test]
fn a_worktree_with_nothing_to_check_has_no_inputs() {
    let result = skills(vec![], json!({"files_scanned": 0, "bytes_scanned": 0}));
    let (_, coverage) = run(
        json!({"reasons": "ignored", "detectors": []}),
        json!([["skill_content_v1", result]]),
    );
    assert_eq!(coverage["status"], json!("complete"));
    assert_eq!(
        coverage["detectors"],
        json!({"skill_content_v1": "no_inputs"})
    );
}

#[test]
fn an_unknown_detector_or_malformed_request_is_invalid() {
    assert_eq!(
        dispatch(&json!({"coverage": {}, "results": [["secret_v1", null]]})),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"coverage": {}, "results": [["skill_content_v1"]]})),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"coverage": [], "results": []})),
        Err(ERR_INVALID)
    );
    assert_eq!(dispatch(&json!({"coverage": {}})), Err(ERR_INVALID));
}

#[test]
fn each_detector_checks_its_own_rule_id_path_and_fields() {
    let long_hook = format!(".github/hooks/{}.json", "a".repeat(251));
    let cases = json!([
        ["skill_content_v1", {}, true],
        ["skill_content_v1", {"path": "SKILL.md"}, false],
        ["skill_content_v1", {"path": "skills/README.md"}, false],
        ["skill_content_v1", {"path": "../x/SKILL.md"}, false],
        ["skill_content_v1", {"path": "a//SKILL.md"}, false],
        ["skill_content_v1", {"path": "c:/SKILL.md"}, false],
        ["skill_content_v1", {"path": "a\\b/SKILL.md"}, false],
        ["skill_content_v1", {"rule_id": "mcp.config.x"}, false],
        ["mcp_config_v1", {"rule_id": "mcp.config.x", "path": ".mcp.json", "server": "files"}, true],
        ["mcp_config_v1", {"rule_id": "mcp.config.x", "path": ".mcp.json", "server": ""}, false],
        ["mcp_config_v1", {"rule_id": "mcp.config.x", "path": "/etc/.mcp.json", "server": "files"}, false],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": ".claude/settings.json", "event": "PreToolUse"}, true],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": ".github/hooks/guard.json", "event": "a:b"}, true],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": ".github/hooks/.json", "event": "x"}, true],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": ".github/hooks/a/b.json", "event": "x"}, false],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": long_hook, "event": "x"}, false],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": "settings.json", "event": "x"}, false],
        ["hook_config_v1", {"rule_id": "hook.config.x", "path": ".claude/settings.json", "event": "two words"}, false],
        ["plugin_manifest_v1", {"kind": "hook", "rule_id": "hook.config.x", "path": "p/.claude-plugin/plugin.json", "name": "n"}, true],
        ["plugin_manifest_v1", {"kind": "hook", "rule_id": "hook.config.x", "path": "gemini-extension.json", "name": "n"}, true],
        ["plugin_manifest_v1", {"kind": "hook", "rule_id": "hook.config.x", "path": "p/hooks/hooks.json", "name": "n"}, true],
        ["plugin_manifest_v1", {"kind": "hook", "rule_id": "mcp.config.x", "path": "p/hooks/hooks.json", "name": "n"}, false],
        ["plugin_manifest_v1", {"kind": "mcp_server", "rule_id": "mcp.config.x", "path": ".mcp.json", "name": "n"}, false],
        ["plugin_manifest_v1", {"kind": "hook", "rule_id": "hook.config.x", "path": "p/plugin.json", "name": "n"}, false],
        ["plugin_manifest_v1", {"kind": "skill", "rule_id": "hook.config.x", "path": "p/hooks/hooks.json", "name": "n"}, false],
        ["ci_workflow_v1", {"rule_id": "ci.workflow.unpinned-action", "path": ".github/workflows/ci.yml"}, true],
        ["ci_workflow_v1", {"rule_id": "ci.workflow.write-all-permissions", "path": ".github/workflows/r.yaml"}, true],
        ["ci_workflow_v1", {"rule_id": "ci.workflow.unpinned-action", "path": ".github/workflows/a/ci.yml"}, false],
        ["ci_workflow_v1", {"rule_id": "ci.workflow.unpinned-action", "path": ".github/workflows/ci.json"}, false],
        ["ci_workflow_v1", {"rule_id": "ci.workflow.other", "path": ".github/workflows/ci.yml"}, false],
        ["editor_task_v1", {"rule_id": "editor.task.folder-open", "path": ".vscode/tasks.json"}, true],
        ["editor_task_v1", {"rule_id": "editor.task.folder-open", "path": "app.code-workspace"}, true],
        ["editor_task_v1", {"rule_id": "editor.task.folder-open", "path": "a/app.code-workspace"}, false],
        ["editor_task_v1", {"rule_id": "devcontainer.initialize-command", "path": ".devcontainer.json"}, true],
        ["editor_task_v1", {"rule_id": "devcontainer.initialize-command", "path": ".devcontainer/devcontainer.json"}, true],
        ["editor_task_v1", {"rule_id": "devcontainer.initialize-command", "path": ".devcontainer/py/devcontainer.json"}, true],
        ["editor_task_v1", {"rule_id": "devcontainer.initialize-command", "path": ".devcontainer/a/b/devcontainer.json"}, false],
        ["editor_task_v1", {"rule_id": "devcontainer.initialize-command", "path": ".vscode/tasks.json"}, false],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": "AGENTS.md"}, true],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": "pkg/Claude.local.md"}, true],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": ".cursor/rules/a/b.mdc"}, true],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": ".Kiro/Steering/x.md"}, true],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": ".github/copilot-instructions.md"}, true],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": "README.md"}, false],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": "../AGENTS.md"}, false],
        ["instruction_file_v1", {"rule_id": "instruction.guard-bypass", "path": "a\\AGENTS.md"}, false],
        ["instruction_file_v1", {"rule_id": "instruction.other", "path": "AGENTS.md"}, false],
    ]);
    for case in cases.as_array().expect("cases") {
        let (detector, overrides) = (case[0].as_str().expect("detector"), case[1].clone());
        let schema = specs::spec(detector).expect("detector").result_schema;
        let result =
            json!({"schema": schema, "status": "complete", "findings": [finding_with(overrides)]});
        let (findings, _) = run(empty_coverage(), json!([[detector, result]]));
        assert_eq!(Value::Bool(findings.len() == 1), case[2], "{case}");
    }
}

#[test]
fn rule_findings_store_their_extra_fields() {
    let mcp =
        finding_with(json!({"rule_id": "mcp.config.x", "path": ".mcp.json", "server": "files"}));
    let hook = finding_with(
        json!({"rule_id": "hook.config.x", "path": ".codex/hooks.json", "event": "Stop"}),
    );
    let plugin = finding_with(
        json!({"kind": "mcp_server", "rule_id": "mcp.config.x", "path": "p/.mcp.json", "name": "db"}),
    );
    let results = json!([
        ["mcp_config_v1", {"schema": "guard.workspace-mcp-config.v1", "status": "complete", "findings": [mcp]}],
        ["hook_config_v1", {"schema": "guard.workspace-hooks.v1", "status": "complete", "findings": [hook]}],
        ["plugin_manifest_v1", {"schema": "guard.workspace-plugins.v1", "status": "complete", "findings": [plugin]}],
    ]);
    let (findings, _) = run(empty_coverage(), results);
    let extras: Vec<Value> = findings
        .iter()
        .map(|finding| {
            json!([
                finding["server"],
                finding["event"],
                finding["component"],
                finding["detector"]
            ])
        })
        .collect();
    assert_eq!(
        extras,
        [
            json!(["files", null, null, "mcp_config_v1"]),
            json!([null, "Stop", null, "hook_config_v1"]),
            json!(["db", null, "mcp_server", "plugin_manifest_v1"]),
        ]
    );
}

#[test]
fn every_detector_in_a_request_is_added_in_order() {
    let hooks = json!({"schema": "guard.workspace-hooks.v1", "status": "complete", "files_scanned": 0, "findings": []});
    let (_, coverage) = run(
        empty_coverage(),
        json!([["hook_config_v1", hooks], ["instruction_file_v1", null], ["editor_task_v1", {"schema": "unreadable"}]]),
    );
    assert_eq!(
        coverage["reasons"],
        json!([
            "detector_not_run:instruction_file_v1",
            "editor_task_incomplete"
        ])
    );
    assert_eq!(
        coverage["detectors"],
        json!({"hook_config_v1": "no_inputs", "instruction_file_v1": "not_run", "editor_task_v1": "error"})
    );
    assert_eq!(coverage["hook_config"]["commands_scanned"], json!(0));
}

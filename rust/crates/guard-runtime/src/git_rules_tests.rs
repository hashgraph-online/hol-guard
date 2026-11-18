use super::*;
use crate::git_rules_inline::{process_calls, Call};
use crate::git_rules_match::{breaks, Breaks};
use guard_contracts::{PreToolActionV1, PreToolOperationV1, PRE_TOOL_ACTION_V1_SCHEMA};

const HOOK_BYPASSES: &[&str] = &[
    "HUSKY=0 git commit -m 'release metadata'",
    "env HUSKY=0 git commit -m \"feat: sync\"",
    "env SKIP=eslint,pytest git commit -m \"quick fix\"",
    "flutter pub get && python3 -c \"import os; os.system('SKIP=pre-commit-hooks git commit -m \\\"skip tests\\\"')\"",
    "git status --short && git commit --amend --no-verify --no-edit",
    "git log -n 3 --oneline && git commit --amend -nm \"tidy message\"",
    "npm run build && git commit --no-verify -m \"ship it\"",
    "HUSKY=0 git commit -m 'fix bindings' && lua -e 'print(1)'",
    "git commit -nm 'hotfix after sync'",
    "git -c core.hooksPath=/dev/null commit -m \"relax metrics\"",
    "git -c core.hookspath= commit -m wip",
    "sh -c 'git commit -n -m \"bypass\"'",
    "bash -lc 'git push --no-verify origin main'",
    "git add src/ui && git commit -nm \"wip: demo UI\"",
    "mix compile && echo \"Committing changes\" && git commit -m \"update\" -n",
    "export HUSKY=0; git commit -m wip",
    "git config core.hooksPath /dev/null && git commit -m wip",
    "LEFTHOOK=0 git push",
    "caffeinate -i git commit --no-verify -m wip",
    "timeout 60 git merge --no-verify feature",
    "(cd app && HUSKY=0 git commit -m wip)",
    "eval \"git commit --no-verify -m wip\"",
    "node -e \"require('child_process').execSync('git commit -n -m wip')\"",
];

const WHOLE_TREE_STAGES: &[&str] = &[
    "python3 -c 'import subprocess; root=subprocess.check_output([\"git\",\"-C\",\"/work/repo\",\"rev-parse\",\"--show-toplevel\"],text=True).strip(); subprocess.run([\"git\",\"-C\",root,\"add\",\"--all\",\".\"],check=True)'",
    "snakemake --cores 4 && git add -A",
    "git status --porcelain && git rm -r --cached . && git add src/ client/",
    "node -e \"const{execSync}=require('child_process');execSync('npx prettier --write src',{stdio:'inherit'});execSync('git add --all',{stdio:'inherit'})\"",
    "caffeinate -i git add -u && caffeinate -i git commit -m \"stage every tracked tweak\"",
    "git status --short && git add . ':!docs/generated'",
    "python3 -c 'import subprocess; subprocess.run([\"git\", \"add\", \"-A\"])' && cd app && git commit -m prep",
    "git commit -m \"sync drivetrain constants\" .",
    "pnpm exec prettier --write \"static/**\" ; git add --all ; git commit -m 'rebuild'",
    "git status && git add -A && git commit -m 'squash WIP'",
    "git diff --stat && git add -- ':(top)' && git diff --cached --stat",
    "set -euo pipefail\nprintf 'Refreshing\\n'\npython3 -c 'import subprocess; subprocess.run([\"git\", \"add\", \"-u\", \".\"], check=True)'\ngit diff --cached --check",
    "git add .",
    "git add :/",
    "git add ':!vendor'",
    "git commit -am 'everything'",
    "git commit --all -m wip",
    "git add \"$(git rev-parse --show-toplevel)\"",
    "cd \"$(git rev-parse --show-toplevel)\" && git add .",
    "git -C . add -A",
];

const QUIET: &[&str] = &[
    "cd src/ui && git add .",
    "(cd src/ui && npm run lint && git add .)",
    "git add -A packages/icons",
    "timeout 30 git add -A packages/vapor/",
    "git add -p",
    "git add -n .",
    "git add src ':!src/gen'",
    "git restore --staged . && git add src/main.rs",
    "env HUSKY=1 git commit -m wip",
    "git -c core.hooksPath=.githooks commit -m wip",
    "git config core.hooksPath .githooks",
    "git commit -m 'docs: explain --no-verify and git add -A' -- docs/hooks.md",
    "git commit --amend -m \"never use --no-verify\"",
    "git commit -v --amend",
    "caffeinate git commit -m wip",
    "git commit --only src/a.rs -m wip",
    "git commit src/a.rs -m wip",
    "git push -n origin main",
    "git push --dry-run",
    "node -e \"console.log('git add . && git commit --no-verify')\"",
    "python3 -c \"print('git add -A')\"",
    "echo 'git add -A && git commit -n'",
    "printf '%s\\n' 'HUSKY=0 git commit'",
    "grep -rn 'no-verify' docs/",
    "cat <<'EOF'\ngit add .\nEOF",
    "git -C packages/api add .",
    "git status --short",
    "git log --oneline -n 5",
    "git commit -m wip",
];

#[test]
fn hook_bypasses_are_found() {
    for command in HOOK_BYPASSES {
        assert!(breaks(command).hook_bypass, "missed hook bypass: {command}");
    }
}

#[test]
fn whole_tree_stages_are_found() {
    for command in WHOLE_TREE_STAGES {
        assert!(
            breaks(command).stage_all,
            "missed whole-tree stage: {command}"
        );
    }
}

#[test]
fn ordinary_git_work_breaks_no_rule() {
    for command in QUIET {
        assert_eq!(breaks(command), Breaks::default(), "flagged: {command}");
    }
}

#[test]
fn inline_code_reads_only_process_calls() {
    assert_eq!(
        process_calls("import os; os.system('git add .')"),
        vec![Call::Shell("git add .".into())]
    );
    assert_eq!(
        process_calls("subprocess.run(['git', cmd, '.'])"),
        vec![Call::Argv(vec!["git".into(), "$VAR".into(), ".".into()])]
    );
    assert_eq!(
        process_calls("spawnSync('git', ['add', '-A'])"),
        vec![Call::Argv(vec!["git".into(), "add".into(), "-A".into()])]
    );
    assert!(process_calls("print('os.system(\"git add .\")')").is_empty());
    assert!(process_calls("runner = 1; rerun('x')").is_empty());
}

fn result(minimum_action: &str) -> PreToolResultV1 {
    PreToolResultV1 {
        schema: "guard-pre-tool-result.v1".into(),
        version: 1,
        authority: "rust".into(),
        action: PreToolActionV1 {
            schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
            version: 1,
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            action_type: PreToolActionTypeV1::Command,
            operation: PreToolOperationV1::Execute,
            bounded: true,
            sensitive_target: false,
        },
        decision: if matches!(minimum_action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: minimum_action == "allow",
        command_extensions: None,
        prompt_risk_classes: Vec::new(),
    }
}

fn rule(action: &str) -> Rule {
    Rule {
        action: action.into(),
        code: STAGE_ALL,
        observed: STAGE_ALL_OBSERVED,
        reason: "whole tree",
    }
}

#[test]
fn a_set_rule_raises_an_allowed_command_to_its_action() {
    for action in ["review", "require-reapproval", "block"] {
        let raised = raise(result("allow"), &rule(action), false);
        assert_eq!(raised.minimum_action, action);
        assert_eq!(raised.policy_action, action);
        assert_eq!(raised.decision, "deny");
        assert_eq!(raised.reason_code, STAGE_ALL);
        assert!(!raised.explicitly_benign);
    }
    assert!(is_review_finding(STAGE_ALL) && is_review_finding(HOOK_BYPASS));
}

#[test]
fn a_sandbox_route_does_not_stand_in_for_a_set_rule() {
    let raised = raise(result("sandbox-required"), &rule("review"), false);
    assert_eq!(raised.minimum_action, "review");
    assert_eq!(raised.decision, "deny");
    assert_eq!(raised.reason_code, STAGE_ALL);
}

#[test]
fn a_posture_sandbox_route_does_not_stand_in_for_a_set_rule() {
    for (floor, kept) in [
        ("allow", "review"),
        ("review", "review"),
        ("require-reapproval", "require-reapproval"),
    ] {
        let mut contained = result(floor);
        contained.policy_action = "sandbox-required".into();
        contained.decision = "deny".into();
        let raised = raise(contained, &rule("review"), false);
        assert_eq!(raised.minimum_action, kept);
        assert_eq!(raised.policy_action, kept);
        assert_eq!(raised.decision, "deny");
        assert_eq!(raised.reason_code, STAGE_ALL);
    }
}

#[test]
fn a_stronger_verdict_is_kept() {
    for kept in ["review", "require-reapproval"] {
        let raised = raise(result(kept), &rule("review"), false);
        assert_eq!(raised.minimum_action, kept);
        assert_eq!(raised.reason_code, "native_test");
    }
    let blocked = raise(result("sandbox-required"), &rule("block"), false);
    assert_eq!(blocked.minimum_action, "block");
}

#[test]
fn watch_mode_and_warn_only_record_a_warning() {
    let watched = raise(result("allow"), &rule("review"), true);
    assert_eq!(watched.minimum_action, "warn");
    assert_eq!(watched.decision, "allow");
    assert_eq!(watched.reason_code, STAGE_ALL_OBSERVED);
    assert!(watched.reason.contains("would have required review"));
    let warned = raise(result("allow"), &rule("warn"), false);
    assert_eq!(warned.minimum_action, "warn");
    assert_eq!(warned.decision, "allow");
    let reviewed = raise(result("review"), &rule("review"), true);
    assert_eq!(reviewed.minimum_action, "review");
    assert_eq!(reviewed.reason_code, "native_test");
}

#[test]
fn a_git_step_beside_a_package_script_or_service_is_still_a_shell_command() {
    for covered in [
        PreToolActionTypeV1::Command,
        PreToolActionTypeV1::Package,
        PreToolActionTypeV1::ProcessService,
        PreToolActionTypeV1::Network,
    ] {
        assert!(shell_action(&covered));
    }
    for skipped in [
        PreToolActionTypeV1::FileWrite,
        PreToolActionTypeV1::McpTool,
        PreToolActionTypeV1::Unknown,
    ] {
        assert!(!shell_action(&skipped));
    }
}

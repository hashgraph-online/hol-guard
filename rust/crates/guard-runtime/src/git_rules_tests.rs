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
    "git status && env HUSKY=0 git commit -m wip",
    "git status && env -u PAGER SKIP=lint git commit -m wip",
    "nohup env HUSKY=0 git commit -m wip",
    "HUSKY=0 python3 -c 'import subprocess; subprocess.run([\"git\",\"commit\",\"-m\",\"wip\"])'",
    "HUSKY=0 python3 -c 'import os; os.system(\"git commit -m wip\")'",
    "HUSKY=0 sh -c 'git commit -m wip'",
    "HUSKY=0 eval git commit -m wip",
    "git config --file .git/config core.hooksPath /dev/null",
    "git config set core.hooksPath /dev/null",
    "git config --local core.hooksPath ''",
    "export SKIP=lint; export HUSKY=1; git commit -m wip",
    "env -S 'git commit --no-verify -m wip'",
    "env --split-string='git commit -n -m wip'",
    "git commit -am '--dry-run' --no-verify",
    "git -c core.hooksPath=/nonexistent/hooks commit -m wip",
    "perl -e 'my $n = $#ARGV; system(\"git commit --no-verify -m x\")'",
    "perl -e '`git commit -n -m wip`'",
    "python3 -c \"import os as o; system = o.system; system('git commit -n -m x')\"",
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
    "cd . && git add .",
    "cd sub && cd .. && git add .",
    "cd app/src && cd ../.. && git add -- .",
    "cd app && cd - && git add .",
    "pushd app && popd && git add .",
    "cd app && git -C .. add .",
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
    "echo $(git add .); cd src",
    "python3 -c \"import subprocess\ndef run(c):\n    subprocess.call(c, shell=True)\nrun('git add -A')\"",
    "python3 -c 'import subprocess; subprocess.run([\"git\", \"add\", \".\"])'",
    "node -e 'const x = `${require(\"child_process\").execSync(\"git add -A\")}`'",
    "env -S 'git add -A'",
    "ruby -e '`git add -A`'",
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
    "export HUSKY=0; export HUSKY=1; git commit -m wip",
    "export HUSKY=0; unset HUSKY; git commit -m wip",
    "env -i git commit -m wip",
    "git commit --dry-run -a",
    "git commit --dry-run .",
    "HUSKY=0 git commit --dry-run -m wip",
    "python3 -c \"# os.system('git add -A')\nprint(1)\"",
    "node -e \"// execSync('git add -A')\nconsole.log(1)\"",
    "node -e \"/* execSync('git add -A') */ console.log(1)\"",
    "git config --unset core.hooksPath",
    "git config --get core.hooksPath",
    "git config --file .git/config core.hooksPath .githooks",
    "cd app/src && cd .. && git add .",
    "pushd app && git add .",
    "cd src; echo $(git add .)",
    "git rm -n -r --cached .",
    "git rm --dry-run -r --cached .",
    "python3 -c \"def run(text):\n    print(text)\nrun('git add .')\"",
    "node -e \"function exec(t) { console.log(t) }\nexec('git add -A')\"",
    "python3 -c 'import subprocess; subprocess.run([\"git\", \"add\", \".\" + \"/docs\"])'",
    "env -C app git add .",
    "node -e 'console.log(`git add -A`)'",
    "perl -e 'my $n = $#ARGV; print(\"git add -A\")'",
    "python3 -c \"run = lambda t: print(t)\nrun('git add .')\"",
    "node -e \"const exec = (t) => console.log(t); exec('git add -A')\"",
    "node -e \"const exec = t => console.log(t); exec('git add -A')\"",
    "git commit -m '--no-verify' --dry-run",
];

#[test]
fn hook_bypasses_are_found() {
    for command in HOOK_BYPASSES {
        assert!(
            breaks(command, None).hook_bypass,
            "missed hook bypass: {command}"
        );
    }
}

#[test]
fn whole_tree_stages_are_found() {
    for command in WHOLE_TREE_STAGES {
        assert!(
            breaks(command, None).stage_all,
            "missed whole-tree stage: {command}"
        );
    }
}

#[test]
fn ordinary_git_work_breaks_no_rule() {
    for command in QUIET {
        assert_eq!(
            breaks(command, None),
            Breaks::default(),
            "flagged: {command}"
        );
    }
}

#[test]
fn inline_code_reads_only_process_calls() {
    assert_eq!(
        process_calls("import os; os.system('git add .')", true),
        vec![Call::Shell("git add .".into())]
    );
    assert_eq!(
        process_calls("subprocess.run(['git', cmd, '.'])", true),
        vec![Call::Argv(vec!["git".into(), "$VAR".into(), ".".into()])]
    );
    assert_eq!(
        process_calls("spawnSync('git', ['add', '-A'])", true),
        vec![Call::Argv(vec!["git".into(), "add".into(), "-A".into()])]
    );
    assert!(process_calls("print('os.system(\"git add .\")')", true).is_empty());
    assert!(process_calls("runner = 1; rerun('x')", true).is_empty());
    // A first argument that opens with a curly quote is not a literal, and
    // reading it must not split a multi-byte character.
    assert!(process_calls("os.system(\u{201c}git add .\u{201d})", true).is_empty());
    assert!(process_calls("run(\u{e9}x, 'git add .')", false).is_empty());
    // `#` starts a comment in Python, not in JavaScript; `//` the reverse.
    assert!(process_calls("# os.system('git add .')", true).is_empty());
    assert_eq!(process_calls("# x\nos.system('git add .')", true).len(), 1);
    assert!(process_calls("// execSync('git add .')", false).is_empty());
    assert_eq!(
        process_calls("a = 4 // 2; os.system('git add .')", true).len(),
        1
    );
    // A template's `${...}` runs; its text does not.
    assert_eq!(
        process_calls("x = `${execSync('git add .')} and exec('no')`", false),
        vec![Call::Shell("git add .".into())]
    );
    assert_eq!(
        process_calls(
            "`${`${`${`${`${`${`${`${`${`${exec('x')}`}`}`}`}`}`}`}`}`}`",
            false
        )
        .len(),
        0
    );
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
    // The sandbox still lets the commit land with its hooks off.
    for configured in ["review", "require-reapproval"] {
        let raised = raise(result("sandbox-required"), &rule(configured), false);
        assert_eq!(raised.minimum_action, configured);
        assert_eq!(raised.decision, "deny");
        assert_eq!(raised.reason_code, STAGE_ALL);
    }
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
    let mut warned = result("warn");
    warned.decision = "allow".into();
    warned.reason = "An earlier warning.".into();
    let watched = raise(warned, &rule("review"), true);
    assert_eq!(watched.minimum_action, "warn");
    assert_eq!(watched.decision, "allow");
    assert_eq!(watched.reason_code, "native_test");
    assert!(watched.reason.starts_with("An earlier warning."));
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

#[test]
fn a_hooks_folder_counts_only_when_it_runs_no_hook() {
    let root = tempfile::tempdir().expect("temp dir");
    let repo = root.path().join("repo");
    let hooks = repo.join(".githooks");
    let empty = root.path().join("empty-hooks");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    std::fs::create_dir_all(&hooks).expect("hooks dir");
    std::fs::create_dir_all(repo.join(".empty")).expect("empty repo dir");
    std::fs::create_dir_all(&empty).expect("empty dir");
    std::fs::write(hooks.join("pre-commit"), "#!/bin/sh\n").expect("hook");
    let cwd = Some(repo.as_path());
    let empty = empty.display();
    let hooks = hooks.display();
    for command in [
        format!("git -c core.hooksPath={empty} commit -m wip"),
        "git -c core.hooksPath=.empty commit -m wip".to_owned(),
        "git -c core.hooksPath=missing commit -m wip".to_owned(),
        format!("git config core.hooksPath {empty}"),
    ] {
        assert!(breaks(&command, cwd).hook_bypass, "missed: {command}");
    }
    for command in [
        format!("git -c core.hooksPath={hooks} commit -m wip"),
        "git -c core.hooksPath=.githooks commit -m wip".to_owned(),
        format!("git config core.hooksPath {hooks}"),
        // A hooks folder saved inside the tree is how hook managers set
        // themselves up, before or after they write their hooks.
        "git config core.hooksPath .empty".to_owned(),
        "git config core.hooksPath missing".to_owned(),
    ] {
        assert_eq!(
            breaks(&command, cwd),
            Breaks::default(),
            "flagged: {command}"
        );
    }
}

#[test]
fn the_agent_folder_below_the_top_is_not_the_whole_tree() {
    let root = tempfile::tempdir().expect("temp dir");
    let repo = root.path().join("repo");
    let ui = repo.join("src").join("ui");
    std::fs::create_dir_all(repo.join(".git")).expect("git dir");
    std::fs::create_dir_all(&ui).expect("ui dir");
    assert_eq!(breaks("git add .", Some(&ui)), Breaks::default());
    assert_eq!(
        breaks("cd ../.. && cd src && git add .", Some(&ui)),
        Breaks::default()
    );
    assert!(breaks("git add -A", Some(&ui)).stage_all);
    assert!(breaks("cd ../.. && git add .", Some(&ui)).stage_all);
    assert!(breaks("git add .", Some(&repo)).stage_all);
}

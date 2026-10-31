use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tempfile::TempDir;

use super::{
    node_command, typescript_command, NodeCommandOutcome, ParseIntent, RunExecution, VITEST_REFUSAL,
};
use crate::contained_runner::{flows, RunnerLaunch};
use crate::package_intent_common::{LocalPackageExecutionEvidence, PackageIntent};

fn execution(package: &str) -> LocalPackageExecutionEvidence {
    LocalPackageExecutionEvidence {
        manager_name: "npx".to_owned(),
        path_source: "path".to_owned(),
        effective_cwd: "/workspace".to_owned(),
        cwd_source: "workspace".to_owned(),
        manager_is_guard_shim: true,
        local_only_requested: true,
        context_hash: "c".repeat(64),
        package_name: Some(package.to_owned()),
        executable_name: Some(package.to_owned()),
        declared_version: Some("1.2.3".to_owned()),
        manager: None,
        local_executable: None,
        manifests: Vec::new(),
        lockfiles: Vec::new(),
        typescript_launch: None,
    }
}

fn intent(executions: Vec<LocalPackageExecutionEvidence>) -> PackageIntent {
    PackageIntent {
        package_manager: "npx".to_owned(),
        intent_kind: "execute",
        command_tokens: Vec::new(),
        redacted_command: String::new(),
        targets: Vec::new(),
        manifest_paths: Vec::new(),
        lockfile_paths: Vec::new(),
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: executions,
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
        routine_local_runner: false,
    }
}

/// A canonical workspace and a shim directory laid out like Guard's
/// installed package shims (`<home>/package-shims/bin`) or not.
struct Fixture {
    root: TempDir,
    workspace: PathBuf,
    shim_directory: PathBuf,
    environment: BTreeMap<String, String>,
    argv: Vec<String>,
}

fn fixture(installed_shim: bool) -> Fixture {
    let root = TempDir::new().unwrap();
    let base = fs::canonicalize(root.path()).unwrap();
    let workspace = base.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let shim_directory = if installed_shim {
        base.join("guard-home").join("package-shims").join("bin")
    } else {
        base.join("bin")
    };
    fs::create_dir_all(&shim_directory).unwrap();
    let environment = BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin".to_owned()),
        ("GITHUB_TOKEN".to_owned(), "never-parsed".to_owned()),
    ]);
    let argv = ["--no-install", "vitest", "run", "src/a b.test.ts"]
        .map(str::to_owned)
        .to_vec();
    Fixture {
        root,
        workspace,
        shim_directory,
        environment,
        argv,
    }
}

fn launch<'a>(fixture: &'a Fixture, manager: &'a str) -> RunnerLaunch<'a> {
    RunnerLaunch {
        workspace: &fixture.workspace,
        manager,
        argv: &fixture.argv,
        shim_directory: &fixture.shim_directory,
        environment: &fixture.environment,
        timeout_seconds: None,
    }
}

fn never_parsed(_: &str, _: &Path, _: Option<&BTreeMap<String, String>>) -> Option<PackageIntent> {
    panic!("the launch must return to review before parsing");
}

fn never_run(_: &flows::Launch<'_>, _: &Value) -> Result<Value, String> {
    panic!("the launch must return to review before running");
}

fn run_fails(_: &flows::Launch<'_>, _: &Value) -> Result<Value, String> {
    Err("sandbox unavailable".to_owned())
}

#[test]
fn a_single_local_execution_runs_with_its_own_evidence() {
    let fixture = fixture(true);
    let parsed = RefCell::new(None);
    let parse: ParseIntent<'_> = &|command, workspace, environment| {
        *parsed.borrow_mut() = Some((
            command.to_owned(),
            workspace.to_path_buf(),
            environment.cloned(),
        ));
        Some(intent(vec![execution("vitest")]))
    };
    let ran = RefCell::new(None);
    let run: RunExecution<'_> = &|launch, execution| {
        *ran.borrow_mut() = Some((launch.manager.to_owned(), execution.clone()));
        Ok(json!({"operation_id": "test"}))
    };

    let outcome = node_command(&launch(&fixture, " NPX "), parse, run);

    assert_eq!(
        outcome,
        NodeCommandOutcome {
            result: Some(json!({"operation_id": "test"})),
            refusal: None,
        }
    );
    let (command, workspace, environment) = parsed.take().unwrap();
    assert_eq!(command, "npx --no-install vitest run 'src/a b.test.ts'");
    assert_eq!(workspace, fixture.workspace);
    // Only the caller's PATH reaches the parser, never the rest of its environment.
    assert_eq!(
        environment,
        Some(BTreeMap::from([("PATH".to_owned(), "/usr/bin".to_owned())]))
    );
    let (manager, evidence) = ran.take().unwrap();
    assert_eq!(manager, " NPX ");
    assert_eq!(evidence, execution("vitest").to_dict());
}

#[test]
fn bunx_is_a_node_runner_and_typescript_runs_through_npx() {
    let fixture = fixture(false);
    let parse: ParseIntent<'_> = &|_, _, _| Some(intent(vec![execution("tsc")]));
    let run: RunExecution<'_> = &|_, _| Ok(json!({"operation_id": "typecheck"}));

    let node = node_command(&launch(&fixture, "bunx"), parse, run);
    assert_eq!(node.result, Some(json!({"operation_id": "typecheck"})));
    let typescript = typescript_command(&launch(&fixture, "npx"), parse, run);
    assert_eq!(typescript, Some(json!({"operation_id": "typecheck"})));
}

#[test]
fn zero_or_several_local_executions_return_to_review_without_running() {
    let fixture = fixture(true);
    for executions in [Vec::new(), vec![execution("vitest"), execution("vitest")]] {
        let calls = Cell::new(0);
        let parse: ParseIntent<'_> = &|_, _, _| {
            calls.set(calls.get() + 1);
            Some(intent(executions.clone()))
        };
        // No execution was selected, so even a Vitest launch from the
        // installed shims returns to review rather than stopping.
        assert_eq!(
            node_command(&launch(&fixture, "npx"), parse, &never_run),
            NodeCommandOutcome::default()
        );
        assert_eq!(
            typescript_command(&launch(&fixture, "npx"), parse, &never_run),
            None
        );
        assert_eq!(calls.get(), 2);
    }
    let no_intent: ParseIntent<'_> = &|_, _, _| None;
    assert_eq!(
        node_command(&launch(&fixture, "npx"), no_intent, &never_run),
        NodeCommandOutcome::default()
    );
}

#[test]
fn unsupported_managers_return_to_review_before_parsing() {
    let fixture = fixture(true);
    for manager in ["pnpm", "yarn", "bun", "npm", ""] {
        assert_eq!(
            node_command(&launch(&fixture, manager), &never_parsed, &never_run),
            NodeCommandOutcome::default()
        );
    }
    for manager in ["pnpm", "yarn", "bun", "bunx"] {
        assert_eq!(
            typescript_command(&launch(&fixture, manager), &never_parsed, &never_run),
            None
        );
    }
}

#[test]
fn a_system_root_or_aliased_workspace_returns_to_review_before_parsing() {
    let mut fixture = fixture(true);
    // The OS backends expose system runtime roots read-only, so a project
    // beneath one would bypass omission through an absolute path.
    fixture.workspace = PathBuf::from("/usr");
    assert_eq!(
        node_command(&launch(&fixture, "npx"), &never_parsed, &never_run),
        NodeCommandOutcome::default()
    );
    assert_eq!(
        typescript_command(&launch(&fixture, "npx"), &never_parsed, &never_run),
        None
    );
    // A missing workspace, or one reached through a symlink, is not canonical.
    let base = fixture.root.path().canonicalize().unwrap();
    let alias = base.join("alias");
    std::os::unix::fs::symlink(base.join("workspace"), &alias).unwrap();
    for workspace in [base.join("missing"), alias] {
        fixture.workspace = workspace;
        assert_eq!(
            node_command(&launch(&fixture, "npx"), &never_parsed, &never_run),
            NodeCommandOutcome::default()
        );
    }
}

#[test]
fn an_uncontained_vitest_handoff_from_the_installed_shims_is_refused() {
    let fixture = fixture(true);
    let parse: ParseIntent<'_> = &|_, _, _| Some(intent(vec![execution("vitest")]));

    let outcome = node_command(&launch(&fixture, "bunx"), parse, &run_fails);

    assert_eq!(outcome.result, None);
    assert_eq!(outcome.refusal.as_deref(), Some(VITEST_REFUSAL));
    assert_eq!(
        VITEST_REFUSAL,
        "HOL Guard refused uncontained Vitest execution: sandbox startup or enforcement proof failed"
    );
}

#[test]
fn other_failed_handoffs_return_to_review() {
    // A Vitest launch outside Guard's installed shim directory.
    let outside = fixture(false);
    let vitest: ParseIntent<'_> = &|_, _, _| Some(intent(vec![execution("vitest")]));
    assert_eq!(
        node_command(&launch(&outside, "npx"), vitest, &run_fails),
        NodeCommandOutcome::default()
    );
    // Another runner from the installed shims.
    let installed = fixture(true);
    let eslint: ParseIntent<'_> = &|_, _, _| Some(intent(vec![execution("eslint")]));
    assert_eq!(
        node_command(&launch(&installed, "npx"), eslint, &run_fails),
        NodeCommandOutcome::default()
    );
    // A TypeScript check never stops the shim.
    assert_eq!(
        typescript_command(&launch(&installed, "npx"), vitest, &run_fails),
        None
    );
}

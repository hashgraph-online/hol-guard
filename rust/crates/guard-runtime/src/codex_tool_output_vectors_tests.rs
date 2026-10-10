//! Parity vectors recorded from the retired Python implementation.
//!
//! Environment-dependent git verdicts (trusted binary, clean routing
//! environment, execution-free status config) are pinned to pass, so each vector
//! isolates argument shape, path resolution and shell-context semantics. The
//! `full` expectation is Python-only (it includes the Python-owned sensitive
//! source check).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use guard_command::{review_codex_tool_output, Ctx, GitCheck, GitRun, InspectionHost};
use guard_contracts::{
    CodexCommandCwdV1, CodexCommandScopeV1, CodexCommandTextV1, CodexCommandsScopeV1,
    CodexSecretNameScopeV1, CodexToolOutputActionV1, GitExecutionSafetyCheckV1,
    GitExecutionSafetyRequestV1, GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};
use serde_json::Value;

use crate::codex_tool_output_git::run_pathspec_git;

const VECTORS: &str = include_str!("../tests/fixtures/codex_tool_output_vectors.json");

struct PinnedHost {
    git: Option<String>,
}

impl InspectionHost for PinnedHost {
    fn env(&self, _name: &str) -> Option<String> {
        None
    }

    fn git_executable(&self) -> Option<String> {
        self.git.clone()
    }

    fn git_safety(&self, check: GitCheck, _cwd: Option<&str>, arguments: &[String]) -> bool {
        if check != GitCheck::StatusArguments {
            return true;
        }
        let request = GitExecutionSafetyRequestV1 {
            schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            check: GitExecutionSafetyCheckV1::StatusArguments,
            cwd: "/".to_owned(),
            home: "/".to_owned(),
            account_home: None,
            groups: Vec::new(),
            environment: BTreeMap::new(),
            git_binary: None,
            git_path: None,
            arguments: arguments.to_vec(),
            branch: None,
            reference: None,
        };
        crate::git_execution_safety_checks::decide(&request).allowed
    }

    fn run_git(&self, git: &str, args: &[String], cwd: &str) -> GitRun {
        run_pathspec_git(git, args, cwd, &BTreeMap::new())
    }
}

fn find_git() -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

fn git(root: &Path, repo: &str, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root.join(repo))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("proc"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git runs")
        .status;
    assert!(status.success(), "git {args:?} failed in {repo}");
}

fn build_tree(vectors: &Value) -> PathBuf {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("cto-vectors-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for dir in vectors["dirs"].as_array().unwrap() {
        fs::create_dir_all(root.join(dir.as_str().unwrap())).unwrap();
    }
    for (file, text) in vectors["files"].as_object().unwrap() {
        let path = root.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text.as_str().unwrap()).unwrap();
    }
    for (link, target) in vectors["symlinks"].as_object().unwrap() {
        std::os::unix::fs::symlink(target.as_str().unwrap(), root.join(link)).unwrap();
    }
    for repo in vectors["git_repos"].as_array().unwrap() {
        let path = repo["path"].as_str().unwrap();
        git(&root, path, &["init", "-q"]);
        for entry in repo["config"].as_array().unwrap() {
            git(
                &root,
                path,
                &[
                    "config",
                    entry[0].as_str().unwrap(),
                    entry[1].as_str().unwrap(),
                ],
            );
        }
        git(&root, path, &["add", "-A"]);
    }
    root
}

fn absolute(root: &Path, value: &Value) -> Option<String> {
    value
        .as_str()
        .map(|relative| root.join(relative).to_string_lossy().into_owned())
}

fn actions(case: &Value, root: &Path) -> Vec<(&'static str, CodexToolOutputActionV1)> {
    let root_text = root.to_string_lossy().into_owned();
    let command = case["command"]
        .as_str()
        .unwrap()
        .replace("${ROOT}", &root_text);
    let (cwd, home_dir) = (
        absolute(root, &case["cwd"]),
        absolute(root, &case["home_dir"]),
    );
    let scope = |command: &str| CodexCommandScopeV1 {
        command: command.to_owned(),
        cwd: cwd.clone(),
        home_dir: home_dir.clone(),
    };
    let secret = |exec_context: bool| CodexSecretNameScopeV1 {
        command: command.clone(),
        cwd: cwd.clone(),
        home_dir: home_dir.clone(),
        exec_context,
    };
    let cwd_only = CodexCommandCwdV1 {
        command: command.clone(),
        cwd: cwd.clone(),
    };
    let texts: Vec<String> = if command.trim().is_empty() {
        Vec::new()
    } else {
        vec![py_trim(&command)]
    };
    vec![
        (
            "ro",
            CodexToolOutputActionV1::ReadOnlyInspection(scope(&command)),
        ),
        (
            "sn",
            CodexToolOutputActionV1::SecretLikeSourceName(secret(false)),
        ),
        (
            "sx",
            CodexToolOutputActionV1::SecretLikeSourceName(secret(true)),
        ),
        (
            "post",
            CodexToolOutputActionV1::PostToolReadOnly(CodexCommandsScopeV1 {
                commands: texts,
                cwd: cwd.clone(),
                home_dir: home_dir.clone(),
            }),
        ),
        (
            "meta",
            CodexToolOutputActionV1::GitMetadata(cwd_only.clone()),
        ),
        (
            "id",
            CodexToolOutputActionV1::GitPathspecIdentity(cwd_only.clone()),
        ),
        ("tail", CodexToolOutputActionV1::LocalContentTail(cwd_only)),
        (
            "envp",
            CodexToolOutputActionV1::ReadsEnvironmentPipeline(CodexCommandTextV1 {
                command: command.clone(),
            }),
        ),
        (
            "pytest",
            CodexToolOutputActionV1::FocusedPytest(CodexCommandTextV1 { command }),
        ),
    ]
}

fn py_trim(text: &str) -> String {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .to_owned()
}

fn verdict(action: &CodexToolOutputActionV1, key: &str, root: &Path) -> bool {
    let host = PinnedHost { git: find_git() };
    let root_text = root.to_string_lossy().into_owned();
    let ctx = Ctx::new(
        &host,
        &format!("{root_text}/proc"),
        &format!("{root_text}/home"),
    );
    let outcome = review_codex_tool_output(&ctx, action);
    if key == "id" {
        outcome.value.is_some()
    } else {
        outcome.allowed
    }
}

#[cfg(unix)]
#[test]
fn codex_tool_output_matches_the_retired_python_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let root = build_tree(&vectors);
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 2000, "vector corpus shrank: {}", cases.len());
    let mut checked = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let expected = case["expected"].as_object().unwrap();
        for (key, action) in actions(case, &root) {
            let Some(want) = expected.get(key).and_then(Value::as_bool) else {
                continue;
            };
            checked += 1;
            let got = verdict(&action, key, &root);
            if got != want {
                mismatches.push(format!(
                    "#{index} {key} {:?} cwd={} home={}: expected {want} got {got}",
                    case["command"], case["cwd"], case["home_dir"]
                ));
            }
        }
    }
    for pair in vectors["post_pairs"].as_array().unwrap() {
        let commands: Vec<String> = pair["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        let action = CodexToolOutputActionV1::PostToolReadOnly(CodexCommandsScopeV1 {
            commands,
            cwd: absolute(&root, &pair["cwd"]),
            home_dir: absolute(&root, &pair["home_dir"]),
        });
        checked += 1;
        if verdict(&action, "post", &root) != pair["expected"].as_bool().unwrap() {
            mismatches.push(format!("pair {pair}"));
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(checked > 20_000, "too few expectations checked: {checked}");
    assert!(
        mismatches.is_empty(),
        "{} vector mismatches, first: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(40)]
    );
}

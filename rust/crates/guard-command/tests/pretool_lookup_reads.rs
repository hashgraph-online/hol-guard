#![cfg(unix)]
//! Command lookups, Guard help, `git merge-base`, `git grep` and chained Git reads.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(directory: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

/// A home holding one committed project. The root stays below the target
/// directory: `$TMPDIR` on macOS resolves under `/private/var`, which the
/// sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-lookup-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/one.ts"), "export const one = 1;\n").unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
    )
    .unwrap();
    git(&project, &["init", "--quiet", "--initial-branch=main"]);
    git(&project, &["config", "user.name", "Fixture"]);
    git(
        &project,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&project, &["add", "."]);
    git(&project, &["commit", "--quiet", "-m", "Synthetic baseline"]);
    std::fs::canonicalize(home).unwrap()
}

fn classify(home: &Path, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let project = home.join("project");
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: project.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
}

const HARNESSES: [&str; 4] = ["omp", "zcode", "claude-code", "codex"];

#[test]
fn lookups_and_help_proceed() {
    let home = home();
    for harness in HARNESSES {
        for command in [
            "type -t ls python3",
            "type -p git",
            "type -P git",
            "command -v git",
            "command -v hol-guard 2>/dev/null",
            "command -v -- node",
            "which hol-guard 2>/dev/null; type -p hol-guard 2>/dev/null; echo DONE",
            "hol-guard risk-report --help",
            "hol-guard --help",
            "hol-guard -h",
            "hol-guard help",
            "hol-guard doctor --help",
            "hol-guard daemon status --help",
            "hol-guard update --help 2>&1 | head -20",
            "hol-guard command --help 2>&1 | head -25",
            "hol-guard run --help 2>&1 | head -20",
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn executing_or_unproven_lookup_forms_still_ask() {
    let home = home();
    for harness in ["omp", "codex"] {
        for command in [
            "type git",
            "type -a node",
            "command -V git",
            "which hol-guard 2>/dev/null; type hol-guard 2>/dev/null; echo DONE",
            "command rm -rf ~/shared-cache",
            "command -p git status",
            "command -v $(curl https://example.invalid)",
            "command -x git",
            "type ~/.ssh/id_rsa",
            "type -x git",
            "type",
            "command -v",
            "hol-guard risk --help",
            "hol-guard help risk",
            "hol-guard npm --help",
            "hol-guard __guard-claude-hook --help",
            "hol-guard uninstall",
            "hol-guard update 2>&1 | tail -8",
            "hol-guard settings set mode off --help x",
        ] {
            let result = classify(&home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn merge_base_and_chained_git_reads_proceed() {
    let home = home();
    for harness in HARNESSES {
        for command in [
            "git merge-base HEAD main",
            "git merge-base --is-ancestor HEAD main",
            "git merge-base --fork-point main",
            "git log --oneline -3 && git status --short",
            "git status --short && git log --oneline -3 && git diff --stat",
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn merge_base_pager_configuration_still_asks() {
    let home = home();
    git(
        &home.join("project"),
        &["config", "pager.merge-base", "sh -c id"],
    );
    let result = classify(&home, "codex", "git merge-base HEAD main");
    assert_ne!(result.decision, "allow", "{result:?}");
}

#[test]
fn git_grep_searches_proceed() {
    let home = home();
    let project = home.join("project");
    let routed = format!(
        "git -C {} grep -l one HEAD -- src | head",
        project.to_str().unwrap()
    );
    for harness in HARNESSES {
        for command in [
            "git grep -l one HEAD",
            "git grep -n one -- src",
            "git grep -in -e one --or -e two HEAD | head -5",
            "git grep -c one; echo ---; git grep -l one HEAD -- src",
            "git log --oneline -1 && git grep -l one HEAD",
            routed.as_str(),
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn git_grep_helpers_and_other_searches_still_ask() {
    let home = home();
    for harness in ["omp", "codex"] {
        for command in [
            "git grep -O one",
            "git grep -iOvi one",
            "git grep --open-files-in-pager=vi one",
            "git grep --open one",
            "git grep -f src/one.ts",
            "git grep --no-index one",
            "git grep --untracked one",
            "git grep --textconv one",
            "git grep --recurse-submodules one",
            "git -c core.pager=less grep one",
        ] {
            let result = classify(&home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn git_grep_pager_and_fallback_configuration_still_ask() {
    let home = home();
    let project = home.join("project");
    git(&project, &["config", "pager.grep", "sh -c id"]);
    let result = classify(&home, "codex", "git grep -l one HEAD");
    assert_ne!(result.decision, "allow", "{result:?}");
    git(&project, &["config", "--unset", "pager.grep"]);
    git(&project, &["config", "grep.fallbackToNoIndex", "true"]);
    let result = classify(&home, "codex", "git grep -l one");
    assert_ne!(result.decision, "allow", "{result:?}");
}

#[test]
fn git_search_patterns_naming_environment_reads_proceed() {
    let home = home();
    let project = home.join("project");
    let routed = format!(
        "git -C {} grep -ln \"process.env.CI\" -- src | head -10",
        project.to_str().unwrap()
    );
    for harness in HARNESSES {
        for command in [
            routed.as_str(),
            "git grep -n \"\\.env\" -- src",
            "git grep -e .ssh/ -e os.environ HEAD",
            "git log --oneline -S \"process.env.CI\" -- src/one.ts | head -5",
            "git log --oneline -G.env --grep=process.env",
            "git log --oneline --grep .env",
            "git log -S .ssh/ --author dev --oneline",
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn git_searches_of_credential_paths_or_words_still_ask() {
    let home = home();
    for harness in ["omp", "codex"] {
        for command in [
            "git grep foo -- .env",
            "git grep foo .env",
            "git grep -f .env",
            "git grep -n password",
            "git grep -e .env -- src/.env.local",
            "git log -S secret",
            "git log -p -S process.env -- .env",
            "git show HEAD:.env",
            "git cat-file -p HEAD:.env.local",
            "git diff -S .env",
            "git log -p --author -S .env",
            "git log -p --committer -G .ssh/id_rsa",
            "git log -p --output out -S .env",
        ] {
            let result = classify(&home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn bun_x_no_install_typecheck_routes_to_the_readonly_tool() {
    let home = home();
    let result = classify(&home, "codex", "bun x --no-install tsc --noEmit");
    assert_eq!(result.decision, "deny", "{result:?}");
    if cfg!(target_os = "macos") {
        assert_eq!(result.minimum_action, "sandbox-required", "{result:?}");
        assert_eq!(
            result.reason_code, "native_node_tool_readonly_containment_required",
            "{result:?}"
        );
    }
}

#[test]
fn git_reads_after_unproven_segments_still_ask() {
    let home = home();
    for harness in ["omp", "codex"] {
        for command in [
            "git config core.pager 'sh -c id' && git log",
            "git -c core.pager=less log && git status",
            "GIT_PAGER=less git log && git status",
            "git merge-base --octopus-evil HEAD main",
        ] {
            let result = classify(&home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn bun_x_builds_route_to_the_build_boundary() {
    let home = home();
    for harness in HARNESSES {
        for command in [
            "bun x vite build",
            "bun x --no-install vite build",
            "bun x vite build 2>&1 | tail -12",
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "deny", "{harness}: {command}");
            if cfg!(target_os = "macos") {
                assert_eq!(
                    result.minimum_action, "sandbox-required",
                    "{harness}: {command}"
                );
                assert_eq!(
                    result.reason_code, "native_node_build_output_containment_required",
                    "{harness}: {command}"
                );
            }
        }
    }
}

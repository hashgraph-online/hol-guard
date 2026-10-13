#![cfg(unix)]
//! Env-access idioms such as `process.env` inside a `git grep` pattern or a
//! `git log` pickaxe are search text; real environment and secret reads stay
//! reviewed.
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
        .join("../../target/pretool-git-search-literals")
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
    std::fs::write(
        project.join("src/one.ts"),
        "export const flag = process.env.SAMPLE_FLAG;\n",
    )
    .unwrap();
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
fn env_idioms_in_git_search_text_proceed() {
    let home = home();
    let project = home.join("project");
    let routed = format!(
        "git -C {} grep -ln \"process.env\" -- src",
        project.to_str().unwrap()
    );
    for harness in HARNESSES {
        for command in [
            "git grep -ln \"process.env.SAMPLE_FLAG\" -- src",
            "git grep -n -e process.env.SAMPLE_FLAG -- src | head -5",
            "git grep -l \"os.environ\" HEAD -- src",
            "git log --oneline -S \"process.env.SAMPLE_FLAG\" -- src/one.ts | head",
            "git log --oneline -G process.env -- src",
            routed.as_str(),
        ] {
            let result = classify(&home, harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}: {result:?}");
        }
    }
}

#[test]
fn environment_and_secret_reads_around_git_search_text_still_ask() {
    let home = home();
    for harness in ["omp", "codex"] {
        for command in [
            "git grep -ln process.env -- .env",
            "git grep -n -e process.env HEAD -- .env.local",
            "git grep -f .env -- src",
            "git grep -O process.env -- src",
            "git grep --open-files-in-pager=vi process.env",
            "git grep -ln \"$(printenv)\" -- src",
            "git grep -ln \"$SAMPLE_API_KEY\" -- src",
            "git -c core.pager=env log -S process.env",
            "git log -S process.env -- .env",
            "git log -p -S process.env -- id_rsa",
        ] {
            let result = classify(&home, harness, command);
            assert_ne!(result.decision, "allow", "{harness}: {command}");
        }
    }
}

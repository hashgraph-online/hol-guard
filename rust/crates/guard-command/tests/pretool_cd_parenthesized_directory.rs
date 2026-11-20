#![cfg(unix)]
//! A directory whose own name holds parentheses is an ordinary directory.
//!
//! Next.js route groups (`app/(group)`), Xcode build products and plenty
//! of hand-made folders are spelled that way. The shell only reads `(` as
//! syntax when it is unquoted, and an unquoted one opens a subshell the
//! parser refuses long before a `cd` operand is read. So a parenthesis in a
//! quoted or escaped operand is part of the directory's name, and the reads
//! after the `cd` keep the proof they have anywhere else.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a project with both a plain and a parenthesized directory.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-cd-parenthesized-directory")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
    let home = root.join("home");
    for directory in ["project/app/(group)/overview", "project/app/plain"] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    std::fs::write(
        home.join("project/app/(group)/overview/page.tsx"),
        "export default function Page() {}\n",
    )
    .unwrap();
    std::fs::canonicalize(home).unwrap()
}

/// The action each shell harness settles on for `command`, as
/// `[omp, zcode]`. Both are returned so an assertion can hold each harness
/// to the expected action and report the pair when one of them differs.
fn shell(home: &str, cwd: &str, command: &str) -> [String; 2] {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".to_owned()],
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        ..Default::default()
    };
    ["omp", "zcode"].map(|harness| {
        evaluate_pre_tool_envelope_with_execution_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
            None,
            None,
            PathContext {
                home_dir: Some(home),
                cwd: Some(cwd),
                ..PathContext::default()
            },
            Some(&environment),
        )
        .minimum_action
    })
}

/// Both harnesses allowing `command`, for an `assert_eq!` that prints the
/// pair when either one does not.
fn allowed() -> [String; 2] {
    ["allow".to_owned(), "allow".to_owned()]
}

#[test]
fn a_read_below_a_parenthesized_directory_keeps_its_proof() {
    let home = home();
    let home_text = home.to_str().unwrap();
    let project = home.join("project");
    let cwd = project.to_str().unwrap().to_owned();
    let group = project.join("app/(group)/overview");
    let group_text = group.to_str().unwrap();
    for command in [
        format!("cd \"{group_text}\" && pwd"),
        format!("cd \"{group_text}\" && ls"),
        format!("cd \"{group_text}\" && head -40 page.tsx"),
        "cd \"app/(group)/overview\" && pwd".to_owned(),
        "cd app/\\(group\\)/overview && pwd".to_owned(),
    ] {
        assert_eq!(shell(home_text, &cwd, &command), allowed(), "{command}");
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// The plain spelling is the control: it was always allowed, so the case
/// above is about the parentheses and nothing else.
#[test]
fn the_plain_directory_beside_it_is_allowed_the_same_way() {
    let home = home();
    let home_text = home.to_str().unwrap();
    let project = home.join("project");
    let cwd = project.to_str().unwrap().to_owned();
    let plain = project.join("app/plain");
    assert_eq!(
        shell(
            home_text,
            &cwd,
            &format!("cd \"{}\" && pwd", plain.to_str().unwrap())
        ),
        allowed()
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// An unquoted parenthesis is shell syntax, not a directory name, and the
/// command stays unproven.
#[test]
fn an_unquoted_parenthesis_is_still_unproven() {
    let home = home();
    let home_text = home.to_str().unwrap();
    let project = home.join("project");
    let cwd = project.to_str().unwrap().to_owned();
    for command in ["cd app/(group)/overview && pwd", "cd $(echo app) && pwd"] {
        let actions = shell(home_text, &cwd, command);
        assert!(
            actions.iter().all(|action| action != "allow"),
            "{command}: {actions:?}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

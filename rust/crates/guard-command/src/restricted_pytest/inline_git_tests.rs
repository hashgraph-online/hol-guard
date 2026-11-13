//! An inline program the hook contains because it only reads the work tree
//! through Git has to be able to start that Git inside its sandbox.
use super::contained_tests::fixture;
use super::*;
use serde_json::{json, Value};
use std::process::Command;

const SEARCH_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const READ: &str =
    "import subprocess; subprocess.run([\"git\", \"status\", \"--short\"], check=True)";

fn plan(workspace: &Path, program: &str) -> Value {
    authority::evaluate(
        "prepare_inline",
        &json!({
            "command": ["python3", "-c", program],
            "workspace": workspace,
            "cwd": workspace,
            "platform": "darwin",
            "backend_executable": "/usr/bin/sandbox-exec",
            "search_path": SEARCH_PATH,
        }),
    )
}

fn names_git(plan: &Value) -> bool {
    plan["value"]["allowed_executables"]
        .as_array()
        .unwrap_or_else(|| panic!("{plan}"))
        .iter()
        .any(|path| path.as_str().unwrap().ends_with("/git"))
}

fn host_git() -> bool {
    Command::new("/usr/bin/git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn only_a_program_that_names_git_is_given_git() {
    if !cfg!(target_os = "macos") || !host_git() {
        return;
    }
    let fixture = fixture("guard-inline-git-plan");
    fs::create_dir(fixture.0.join(".git")).unwrap();
    let plan_for = |program: &str| plan(&fixture.0, program);
    assert!(names_git(&plan_for(READ)), "{}", plan_for(READ));
    for program in [
        "print(1)",
        "print(open('.github/x').read())",
        "import os; print(os.listdir('.git'))",
        "print('legit')",
    ] {
        assert!(!names_git(&plan_for(program)), "{program}");
    }
}

#[test]
fn a_workspace_git_is_never_given_to_the_program() {
    let fixture = fixture("guard-inline-git-workspace");
    let tools = fixture.0.join("tools");
    fs::create_dir(&tools).unwrap();
    let git = tools.join("git");
    fs::write(&git, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&git, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let search = format!("{}:{SEARCH_PATH}", tools.display());
    let words = vec!["-c".to_owned(), READ.to_owned()];
    assert_eq!(
        inline_git::trusted_git(&words, &fixture.0, &fixture.0, &search),
        None
    );
}

#[test]
fn the_contained_program_runs_the_git_it_reads_with() {
    if !cfg!(target_os = "macos") || !host_git() {
        return;
    }
    let fixture = fixture("guard-inline-git-run");
    let workspace = fixture.0.join("project");
    fs::create_dir(&workspace).unwrap();
    let init = Command::new("/usr/bin/git")
        .args(["init", "-q"])
        .current_dir(&workspace)
        .status()
        .unwrap();
    assert!(init.success());
    fs::write(workspace.join("notes.txt"), "draft\n").unwrap();
    let reply = plan(&workspace, READ);
    let plan = &reply["value"];
    assert_eq!(
        plan["profile_version"], "python-eval-readonly-v1",
        "{reply}"
    );
    let private = fixture.0.join("private");
    for directory in ["home", "tmp"] {
        fs::create_dir_all(private.join(directory)).unwrap();
    }
    let mut profile_input = plan.clone();
    profile_input["private_root"] = json!(private);
    for key in ["backend", "denied_capabilities", "executable"] {
        profile_input.as_object_mut().unwrap().remove(key);
    }
    let profile = profiles::evaluate("macos_profile", &profile_input).unwrap();
    let profile = profile["value"]
        .as_str()
        .unwrap_or_else(|| panic!("{profile}"));
    let environment = authority::evaluate(
        "environment",
        &json!({
            "source": {},
            "workspace": workspace,
            "cwd": workspace,
            "private_home": private.join("home"),
            "private_tmp": private.join("tmp"),
            "allowed_executables": plan["allowed_executables"],
        }),
    );
    let environment = environment["value"].as_object().unwrap();
    let command: Vec<&str> = plan["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect();
    let output = Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .args(&command)
        .current_dir(&workspace)
        .env_clear()
        .envs(
            environment
                .iter()
                .map(|(key, value)| (key, value.as_str().unwrap())),
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("?? notes.txt"), "{stdout}\n{stderr}");
}

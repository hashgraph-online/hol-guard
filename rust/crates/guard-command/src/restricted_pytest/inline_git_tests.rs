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

/// The Git binary itself: the tool `/usr/bin/git` forwards to, when it is a
/// developer shim.
fn real_git() -> PathBuf {
    developer_shim::forwarded_tool(Path::new("/usr/bin/git"))
        .unwrap_or_else(|| PathBuf::from("/usr/bin/git"))
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
    let absolute = READ.replace(
        "\"git\"",
        &format!("{:?}", real_git().display().to_string()),
    );
    assert!(names_git(&plan_for(&absolute)), "{}", plan_for(&absolute));
    // The shim itself cannot run contained, so naming it adds nothing.
    let shim = READ.replace("\"git\"", "\"/usr/bin/git\"");
    if developer_shim::forwarded_tool(Path::new("/usr/bin/git")).is_some() {
        assert!(!names_git(&plan_for(&shim)), "{}", plan_for(&shim));
    }
    for program in [
        "import subprocess; subprocess.run(['./git', 'status'])",
        "import subprocess; subprocess.run(['tools/git', 'status'])",
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
    assert!(inline_git::trusted_gits(&words, &fixture.0, &fixture.0, &search).is_empty());
    let named = vec![
        "-c".to_owned(),
        format!(
            "import subprocess; subprocess.run(['{}', 'status'])",
            git.display()
        ),
    ];
    assert!(inline_git::trusted_gits(&named, &fixture.0, &fixture.0, SEARCH_PATH).is_empty());
}

/// Run `program` the way the contained sink does: the plan's profile, its
/// filtered environment and nothing else.
fn run_contained(fixture: &Path, workspace: &Path, program: &str) -> String {
    let reply = plan(workspace, program);
    let plan = &reply["value"];
    assert_eq!(
        plan["profile_version"], "python-eval-readonly-v1",
        "{reply}"
    );
    let private = fixture.join("private");
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
        .current_dir(workspace)
        .env_clear()
        .envs(
            environment
                .iter()
                .map(|(key, value)| (key, value.as_str().unwrap())),
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    stdout
}

fn git(directory: &Path, args: &[&str]) {
    let status = Command::new("/usr/bin/git")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .current_dir(directory)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

#[test]
fn the_contained_program_runs_the_git_it_reads_with() {
    if !cfg!(target_os = "macos") || !host_git() {
        return;
    }
    let fixture = fixture("guard-inline-git-run");
    let workspace = fixture.0.join("project");
    fs::create_dir(&workspace).unwrap();
    git(&workspace, &["init", "-q"]);
    fs::write(workspace.join("notes.txt"), "draft\n").unwrap();
    let absolute = READ.replace(
        "\"git\"",
        &format!("{:?}", real_git().display().to_string()),
    );
    for program in [READ, absolute.as_str()] {
        let stdout = run_contained(&fixture.0, &workspace, program);
        assert!(stdout.contains("?? notes.txt"), "{program}: {stdout}");
    }
}

#[test]
fn a_linked_worktree_reads_its_shared_repository() {
    if !cfg!(target_os = "macos") || !host_git() {
        return;
    }
    let fixture = fixture("guard-inline-git-linked");
    let main = fixture.0.join("main");
    fs::create_dir(&main).unwrap();
    git(&main, &["init", "-q"]);
    fs::write(main.join("README"), "main\n").unwrap();
    git(&main, &["add", "README"]);
    git(&main, &["commit", "-qm", "init"]);
    let linked = fixture.0.join("linked");
    git(&main, &["worktree", "add", "-q", linked.to_str().unwrap()]);
    fs::write(linked.join("notes.txt"), "draft\n").unwrap();
    let reply = plan(&linked, READ);
    let roots = reply["value"]["read_only_roots"]
        .as_array()
        .unwrap_or_else(|| panic!("{reply}"));
    assert!(!roots.is_empty(), "{reply}");
    let stdout = run_contained(&fixture.0, &linked, READ);
    assert!(stdout.contains("?? notes.txt"), "{stdout}");
}

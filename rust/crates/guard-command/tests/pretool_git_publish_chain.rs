#![cfg(unix)]
//! A `&&` chain that commits work, pushes it and opens a pull request runs
//! without review only when every step keeps the proof it has on its own.
//! This binary registers a push verdict, so it runs in its own process.
#[path = "../../../test_support/unique_nanos.rs"]
mod unique_nanos;

#[path = "support/git_helper_fixture.rs"]
#[allow(dead_code)]
mod git_helper_fixture;

use git_helper_fixture::{evaluate_with_node, FixtureCleanup};
use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_command::pretool::{install_git_push_verdict, GitPushRequest};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const PUBLISH: &str = "native_exact_safe_git_publish_chain";

/// Every repository and branch the verdict was asked about, and whether the
/// chain creates the branch.
static ASKED: Mutex<Vec<(PathBuf, String, bool)>> = Mutex::new(Vec::new());

/// Stands in for the runtime's repository checks: it refuses one branch name.
fn verdict(push: &GitPushRequest<'_>) -> bool {
    ASKED.lock().unwrap().push((
        push.repository.to_path_buf(),
        push.branch.to_owned(),
        push.creates_branch,
    ));
    push.git.is_absolute()
        && push.git.file_name().and_then(|name| name.to_str()) == Some("git")
        && push.branch != "refused"
}

fn controls(propose: &str) -> CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":[{"target_kind":"permission",
                "target_id":"command.github.permission.propose-remote", "state":propose}]
        }]
    });
    if propose == "default" {
        value["layers"][0]["controls"] = json!([]);
    }
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn git(home: &Path, directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

struct Repository {
    home: PathBuf,
    primary: PathBuf,
    worktree: PathBuf,
    _cleanup: FixtureCleanup,
}

/// `home/org/app` on `main` with a GitHub HTTPS origin, and a linked worktree
/// `home/app-fix` on `fix/lane`.
fn repository(label: &str) -> Repository {
    let base = if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
    };
    let home = std::fs::canonicalize(base).unwrap().join(format!(
        "guard-git-publish-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    let cleanup = FixtureCleanup(home.clone());
    let primary = home.join("org/app");
    let worktree = home.join("app-fix");
    std::fs::create_dir_all(&primary).unwrap();
    git(&home, &primary, &["init", "--quiet", "-b", "main"]);
    git(&home, &primary, &["config", "user.name", "Guard Fixture"]);
    git(
        &home,
        &primary,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    std::fs::write(primary.join("tracked.txt"), "fixture\n").unwrap();
    git(&home, &primary, &["add", "tracked.txt"]);
    git(&home, &primary, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &primary,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/app.git",
        ],
    );
    let linked = worktree.to_str().unwrap();
    git(
        &home,
        &primary,
        &["worktree", "add", "--quiet", "-b", "fix/lane", linked],
    );
    std::fs::write(primary.join("CONTRIBUTING.md"), "guide\n").unwrap();
    std::fs::write(worktree.join("notes.md"), "notes\n").unwrap();
    Repository {
        home,
        primary,
        worktree,
        _cleanup: cleanup,
    }
}

impl Repository {
    fn evaluate_with(
        &self,
        command: &str,
        cwd: &Path,
        controls: &CompiledNativeCommandControls,
    ) -> guard_contracts::PreToolResultV1 {
        evaluate_with_node(
            "codex",
            "PreToolUse",
            &json!({"tool_name":"bash", "tool_input":{"command":command}}),
            Some(controls),
            &self.home,
            cwd.to_str(),
        )
    }

    fn decision(&self, command: &str) -> (String, String) {
        let result = self.evaluate_with(command, &self.primary, &controls("default"));
        (result.minimum_action, result.reason_code)
    }
}

impl Repository {
    /// Takes what the verdict was asked about checkouts under this home. The
    /// standalone push path may ask first and then give way to the chain.
    fn asked(&self) -> Vec<(String, bool)> {
        let mut asked = ASKED.lock().unwrap();
        let (mine, others) = std::mem::take(&mut *asked)
            .into_iter()
            .partition::<Vec<_>, _>(|(repository, _, _)| repository.starts_with(&self.home));
        *asked = others;
        let mut mine: Vec<_> = mine
            .into_iter()
            .map(|(_, branch, created)| (branch, created))
            .collect();
        mine.dedup();
        mine
    }
}

#[test]
fn a_chain_of_proven_steps_publishes_without_review() {
    install_git_push_verdict(verdict);
    let repository = repository("allow");
    let allow = |command: &str| {
        assert_eq!(
            repository.decision(command),
            ("allow".to_owned(), PUBLISH.to_owned()),
            "{command}"
        );
    };
    // A static proposal alone is allowed by its GitHub permission.
    assert_eq!(
        repository.decision("gh pr create --title 'Add guide' --body 'Adds a guide.'"),
        (
            "allow".to_owned(),
            "native_command_explicit_permission_allow".to_owned()
        )
    );
    repository.asked();
    allow(concat!(
        "git checkout -b add-contributing && git add CONTRIBUTING.md && ",
        "git commit -m \"Add CONTRIBUTING.md\" && git push -u origin add-contributing && ",
        "gh pr create --title \"Add CONTRIBUTING.md\" --body \"Adds a contributor guide.\"",
    ));
    assert_eq!(repository.asked(), [("add-contributing".to_owned(), true)]);
    allow("git switch -c feat/guide && git add . && git commit -am 'docs: guide' && git push origin HEAD");
    assert_eq!(repository.asked(), [("feat/guide".to_owned(), true)]);
    allow("git add -A && git commit -m 'docs: guide' && git push -u origin main");
    assert_eq!(repository.asked(), [("main".to_owned(), false)]);
    allow("git push -u origin main && gh pr create --title Guide --body Guide");
    assert_eq!(repository.asked(), [("main".to_owned(), false)]);
    // A proposal after local writes needs no push in the same chain.
    allow("git add . && git commit -m guide && gh pr create --title Guide --body Guide");
    assert!(repository.asked().is_empty());
    // A leading `cd` into a linked worktree of the checkout keeps its proof.
    let worktree = repository.worktree.display();
    let command = format!(
        "cd {worktree} && git add notes.md && git commit -m notes && git push origin fix/lane"
    );
    let result = repository.evaluate_with(&command, &repository.home, &controls("default"));
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", PUBLISH),
        "{command}"
    );
}

#[test]
fn any_unproven_step_or_connector_keeps_the_review() {
    install_git_push_verdict(verdict);
    let repository = repository("review");
    let allowed: Vec<_> = [
        // Connectors other than `&&` run later steps after a failed one.
        "git checkout -b b1 && git add . && git commit -m x; git push origin b1",
        "git checkout -b b1 && git commit -m x || git push origin b1",
        "git add . && git commit -m x && git push origin main | tail -1",
        "git add . && git commit -m x && git push origin main & gh pr create --title T --body B",
        // The push must send the branch the chain checks out, once.
        "git checkout -b b1 && git push origin other",
        "git checkout -b b1 && git checkout -b b2 && git push origin HEAD",
        "git push origin main && git checkout -b b2",
        "git add . && git commit -m x && git push origin main && git push origin main",
        "git add . && git commit -m x && git -C . push origin main",
        "git add . && git commit -m x && git push -f origin main",
        "git add . && git commit -m x && git push origin HEAD:refs/heads/release",
        "git add . && git commit -m x && git push upstream main",
        "git checkout -b refused && git push origin refused",
        // Only Git itself is resolved and run by the push proof.
        "perl push origin main",
        "git add . && git commit -m x && perl push origin main",
        "git checkout -b feat && git add . && git commit -m x && perl push origin feat",
        "git add . && git commit -m x && env -C ../other git push origin main",
        "git add . && git commit -m x && env -i git push origin main",
        "git add . && git commit -m x && env -u HOME git push origin main",
        "git add . && git commit -m x && env -S 'git push' origin main",
        // A proposal follows the push of the work it proposes.
        "git add . && git commit -m x && gh pr create --title T --body B && git push origin main",
        "git checkout -b b1 origin/main && git push origin b1",
        // A rename or a switch would change what a push of `HEAD` sends.
        "git branch -m b1 && git push origin HEAD",
        "git checkout -b b1 && git branch -m b2 && git push origin HEAD",
        "git switch fix/lane && git push origin HEAD",
        "git add . && git commit -m x && GIT_SSH_COMMAND=id git push origin main",
        // Every other step still needs its own proof.
        "git add -f . && git commit -m x && git push origin main",
        "git add . && npm publish && git push origin main",
        "git add . && git commit -m x && git push origin main && gh pr create --title \"$(id)\" --body B",
        "git add . && git commit -m x && git push origin main && gh pr merge 1 --squash",
        "git add . && git commit -m x && git push origin main && gh repo create app --public --source . --push",
        "git add . && git commit -m x && git push origin main && gh pr create --title T --body B > out.txt",
    ]
    .into_iter()
    .filter(|command| repository.decision(command).0 == "allow")
    .collect();
    assert!(allowed.is_empty(), "allowed without review: {allowed:#?}");
    // A proposal the user's controls disable never rides along.
    let disabled = repository.evaluate_with(
        "git add . && git commit -m x && git push origin main && gh pr create --title T --body B",
        &repository.primary,
        &controls("disabled"),
    );
    assert_ne!(disabled.minimum_action, "allow");
    // A commit hook keeps the whole chain under review.
    let hook = repository.primary.join(".git/hooks/pre-commit");
    std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (action, _) = repository.decision("git add . && git commit -m x && git push origin main");
    assert_ne!(action, "allow");
}

#[test]
fn checks_before_a_proven_publish_run_contained_then_publish() {
    install_git_push_verdict(verdict);
    let repository = repository("checks");
    let command = concat!(
        "node --input-type=module -e \"console.log('guide')\" && ",
        "git checkout -b add-guide && git add CONTRIBUTING.md && ",
        "git commit -m \"Add guide\" && git push -u origin add-guide",
    );
    let result = repository.evaluate_with(command, &repository.primary, &controls("default"));
    assert_eq!(
        result.reason_code, "native_workspace_containment_required",
        "{command}"
    );
    assert!(
        result.reason.contains("then runs the Git steps"),
        "{}",
        result.reason
    );
    // The Git steps must pass on their own, joined by `&&` alone.
    for command in [
        "node -e \"console.log(1)\" && git checkout -b refused && git push origin refused",
        "node -e \"console.log(1)\" && git add -f . && git commit -m x && git push origin main",
        "node -e \"console.log(1)\" && git add . ; git push origin main",
        "node -e \"console.log(1)\" && git push upstream main",
    ] {
        let result = repository.evaluate_with(command, &repository.primary, &controls("default"));
        assert_ne!(result.minimum_action, "allow", "{command}");
        assert!(
            !result.reason.contains("then runs the Git steps"),
            "{command}"
        );
    }
}

/// Evaluates `command` in the primary checkout for an Oh My Pi session whose
/// environment also carries `names`.
fn in_session(
    repository: &Repository,
    command: &str,
    names: &[&str],
) -> guard_contracts::PreToolResultV1 {
    let home = repository.home.to_str().unwrap();
    let mut environment_names: Vec<String> = ["PATH", "HOME", "GIT_CONFIG_NOSYSTEM"]
        .into_iter()
        .chain(names.iter().copied())
        .map(str::to_owned)
        .collect();
    environment_names.sort();
    let context = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names,
        environment_digest: "0".repeat(64),
        home: Some(home.to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls("default")),
        None,
        guard_command::pretool::PathContext {
            home_dir: Some(home),
            cwd: repository.primary.to_str(),
            cdpath_unset: false,
            rustup_override_absent: false,
            npm_config_inert: false,
            pip_config_inert: false,
            shell_home_matches: false,
            ripgrep_config_absent: false,
            psql_environment: Default::default(),
        },
        Some(&context),
    )
}

/// A session behind a TLS-inspecting proxy names the proxy's certificate
/// authority for Git and every other client. That chooses who may sign for
/// GitHub and runs nothing, so the chain keeps its proof; settings that
/// present a client identity, loosen verification or run a program do not.
#[test]
fn a_session_certificate_anchor_keeps_the_publish_chain_proof() {
    install_git_push_verdict(verdict);
    let repository = repository("anchor");
    let anchors = [
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    ];
    let publish = concat!(
        "git checkout -b add-contributing && git add CONTRIBUTING.md && ",
        "git commit -m \"Add CONTRIBUTING.md with setup and contribution guidelines\" && ",
        "git push -u origin add-contributing",
    );
    let result = in_session(&repository, publish, &anchors);
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("allow", PUBLISH),
        "{result:?}"
    );
    for command in [
        "git checkout -b b1 && git add . && git commit -m x && git push -u origin other",
        "git checkout -b b1 && git add . && git commit -m x && git push -u upstream b1",
        "git checkout -b refused && git add . && git commit -m x && git push origin refused",
        "git checkout -b b1 && git add -f . && git commit -m x && git push origin b1",
        "git checkout -b b1 && git add . && git -c core.fsmonitor=./mon commit -m x && git push origin b1",
        "git checkout -b b1 && GIT_SSL_CAINFO=/tmp/ca.pem git push origin b1",
    ] {
        let result = in_session(&repository, command, &anchors);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
    for name in [
        "GIT_SSL_NO_VERIFY",
        "GIT_SSL_CERT",
        "GIT_SSL_KEY",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_EXEC_PATH",
        "GIT_DIR",
    ] {
        let result = in_session(&repository, publish, &["GIT_SSL_CAINFO", name]);
        assert_ne!(result.minimum_action, "allow", "{name}");
    }
}
